// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "gox"

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "../libbpf/include/uapi/linux/bpf.h"
#include "../libbpf/src/bpf_helpers.h"
#include "../libbpf/src/bpf_endian.h"

#include "common.h"

#define IPV4_UDP_GTPU_SIZE 36

struct bpf_map_def SEC("maps") src_gtpu_addr = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct in_addr),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") far_entries = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct far_t),
    .max_entries = 16,
};

struct bpf_map_def SEC("maps") gtpu_pdr_entries = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct pdr_t),
    .max_entries = 16,
};

struct bpf_map_def SEC("maps") raw_pdr_entries = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct in_addr),
    .value_size = sizeof(struct pdr_t),
    .max_entries = 16,
};

#define bpf_printk(fmt, ...)			\
({                                             \
    char ____fmt[] = fmt;                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), \
            ##__VA_ARGS__);             \
})


static inline
int parse_ipv4(void *data, u64 *nh_off, void *data_end)
{
    struct iphdr *iph = data + *nh_off;

    if (iph + 1 > data_end)
        return -1;

    *nh_off += iph->ihl << 2;

    return iph->protocol;
}

static inline
int parse_udp(void *data, u64 th_off, void *data_end)
{
    struct udphdr *uh = data + th_off;

    if (uh + 1 > data_end)
        return -1;

    if (uh->check)
        return -1;

    if (bpf_htons(uh->dest) != GTP_UDP_PORT)
        return -1;

    return bpf_ntohs(uh->len);
}

static inline
int parse_gtpu(void *data, u64 offset, void *data_end)
{
    struct gtpuhdr *gh = data + offset;

    if (gh + 1 > data_end)
        return -1;

    if (gh->type != GTPU_G_PDU) {
        bpf_printk("parse_gtpu: type 0x%x is not GPDU(0x%x)\n",
                            gh->type, GTPU_G_PDU);
        return -1;
    }

    bpf_printk("parse_gtpu: input teid %d\n", bpf_ntohl(gh->teid));

    return bpf_ntohl(gh->teid);
}

static inline
void parse_inner_ipv4(struct xdp_md *ctx, struct iphdr *inner_iph)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = (void *)(long)ctx->data + \
                            sizeof(struct ethhdr) + IPV4_UDP_GTPU_SIZE;

    if (iph + 1 > data_end) return;

    inner_iph->daddr = iph->daddr;
    inner_iph->saddr = iph->saddr;
}

static
int decap_gtpu(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int decap_size = IPV4_UDP_GTPU_SIZE;

    void *new_eth = (void *)(long)ctx->data + decap_size;

    if (data + decap_size + sizeof(struct ethhdr) > data_end)
        return -1;

    __builtin_memcpy(new_eth, data, sizeof(struct ethhdr));

    return bpf_xdp_adjust_head(ctx, decap_size);
}

static
int encap_gtpu(struct xdp_md *ctx, int payload_size,
               struct far_t *far, struct in_addr *gtpu_addr)
{
    int encap_size = IPV4_UDP_GTPU_SIZE;
    if (bpf_xdp_adjust_head(ctx, 0 - encap_size) != 0)
        return -1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + encap_size + sizeof(struct ethhdr) > data_end) {
        bpf_printk("encap_gtpu: inner payload size %d\n", payload_size);
        return -1;
    }

    struct ethhdr *new_eth = data;
    struct ethhdr *old_eth = data + encap_size;

    __builtin_memcpy(new_eth, old_eth, sizeof(struct ethhdr));

    struct iphdr *iph = data + sizeof(*new_eth);
    if (iph + 1 > data_end) return -1;

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->frag_off = 0;
    iph->protocol = IPPROTO_UDP;
    iph->tos = 0;
    iph->tot_len = bpf_htons(payload_size + encap_size);
    iph->daddr = far->peer_addr_ipv4.s_addr;
    iph->saddr = gtpu_addr->s_addr;
    iph->ttl = 64;
    iph->check = 0;

    struct udphdr *uh = (void *)iph + sizeof(struct iphdr);
    if (uh + 1 > data_end) return -1;

    uh->source = bpf_htons(GTP_UDP_PORT);
    uh->dest = bpf_htons(GTP_UDP_PORT);
    uh->len = bpf_htons(payload_size + encap_size - sizeof(struct iphdr));
    uh->check = 0;

    struct gtpuhdr *gh = (void *)uh + sizeof(struct udphdr);
    if (gh + 1 > data_end) return -1;

    gh->flags = 0x30; // GTP-non-prime
    gh->type = GTPU_G_PDU;
    gh->length = bpf_htons(payload_size);
    gh->teid = bpf_htonl(far->teid);

    return 0;
}

static
int confirm_redirect_ipv4(struct xdp_md *ctx,
                          struct bpf_fib_lookup *fib_params,
                          u32 src, u32 dst)
{
    fib_params->family = AF_INET;
    fib_params->ipv4_src = src;
    fib_params->ipv4_dst = dst;

    int rc = bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params), 0);

    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
        bpf_printk("confirm_redirect_ipv4: not found neighbor rc %d\n", rc);
        return -1;
    }

    return 0;
}

static
int redirect_ipv4(struct xdp_md *ctx, struct bpf_fib_lookup *fib_params)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eh = data;

    if (data + sizeof(*eh) > data_end)
        return -1;

    __builtin_memcpy(eh->h_dest, fib_params->dmac, ETH_ALEN);
    __builtin_memcpy(eh->h_source, fib_params->smac, ETH_ALEN);

    bpf_printk("redirect_ipv4: ingress ifindex %d egress ifindex %d\n",
                ctx->ingress_ifindex, fib_params->ifindex);

    return bpf_redirect(fib_params->ifindex, 0);
}

SEC("input_gtpu_prog")
int xdp_input_gtpu(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr inner_iph = {};
    struct pdr_t *pdr;
    struct pdi_t pdi = {};
    struct far_t *far;
    struct in_addr *gtpu_addr;
    u64 offset;

    offset = sizeof(*eth);
    if (data + offset > data_end)
        goto drop;

    if (ETH_P_IP != bpf_htons(eth->h_proto))
        return XDP_PASS;

    int ipproto = parse_ipv4(data, &offset, data_end);
    if (ipproto != IPPROTO_UDP) {
        bpf_printk("xdp_input_gtpu: ipproto(%d)\n", ipproto);
        return XDP_PASS;
    }

    int len = parse_udp(data, offset, data_end);
    if (len < sizeof(struct gtpuhdr))
        goto drop;
    if (len > data_end - data - offset)
        goto drop;

    offset += sizeof(struct udphdr);
    u32 teid = parse_gtpu(data, offset, data_end);
    pdr = bpf_map_lookup_elem(&gtpu_pdr_entries, &teid);
    if (!pdr) {
        bpf_printk("xdp_input_gtpu: pdr not found pdr key(%d)\n", teid);
        goto drop;
    }

    pdi = pdr->pdi;
    if (pdi.teid != teid)
        goto drop;

    far = bpf_map_lookup_elem(&far_entries, &pdr->far_id);
    if (!far) {
        bpf_printk("xdp_input_gtpu: far not found far key(%d)\n", pdr->far_id);
        goto drop;
    }

    u32 src, dst;
    if (far->encapsulation) {
        int key = 0;
        gtpu_addr = bpf_map_lookup_elem(&src_gtpu_addr, &key);
        if (!gtpu_addr) goto drop;
        src = gtpu_addr->s_addr;
        dst = far->peer_addr_ipv4.s_addr;
    } else {
        parse_inner_ipv4(ctx, &inner_iph);
        src = inner_iph.saddr;
        dst = inner_iph.daddr;
    }

    struct bpf_fib_lookup fib_params = { .ifindex = ctx->ingress_ifindex };
    if (confirm_redirect_ipv4(ctx, &fib_params, src, dst) < 0)
        return XDP_PASS;

    if (decap_gtpu(ctx) < 0)
        goto drop;

    if (far->encapsulation) {
        if (encap_gtpu(ctx, data_end - (data + sizeof(*eth)),
                        far, gtpu_addr) < 0)
            goto drop;
    }

    return redirect_ipv4(ctx, &fib_params);

drop:
    return XDP_DROP;
}

SEC("input_raw_prog")
int xdp_input_raw(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct pdi_t pdi;
    struct pdr_t *pdr;
    struct far_t *far;
    struct in_addr *gtpu_addr;
    u64 offset;

    offset = sizeof(*eth);
    if (data + offset > data_end)
        goto drop;

    if (ETH_P_IP != bpf_htons(eth->h_proto))
        return XDP_PASS;

    iph = data + offset;
    if (iph + 1 > data_end) goto drop;

    bpf_printk("xdp_input_raw: ip src 0x%x dst 0x%x\n",
                iph->saddr, iph->daddr);

    pdr = bpf_map_lookup_elem(&raw_pdr_entries, &iph->daddr);
    if (!pdr) {
        bpf_printk("xdp_input_raw: not found pdr key(0x%x)\n", iph->daddr);
        goto drop;
    }

    pdi = pdr->pdi;
    if (pdi.ue_addr_ipv4.s_addr != iph->daddr)
        goto drop;

    far = bpf_map_lookup_elem(&far_entries, &pdr->far_id);
    if (!far) {
        bpf_printk("xdp_input_raw: not found far key(%d)\n", pdr->far_id);
        goto drop;
    }

    if (!far->encapsulation) goto drop;

    int key = 0;
    gtpu_addr = bpf_map_lookup_elem(&src_gtpu_addr, &key);
    if (!gtpu_addr) goto drop;

    struct bpf_fib_lookup fib_params = { .ifindex = ctx->ingress_ifindex };
    if (confirm_redirect_ipv4(ctx, &fib_params, gtpu_addr->s_addr,
                              far->peer_addr_ipv4.s_addr) < 0)
        return XDP_PASS;

    if (encap_gtpu(ctx, data_end - (data + offset), far, gtpu_addr) < 0)
        goto drop;

    return redirect_ipv4(ctx, &fib_params);

drop:
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
