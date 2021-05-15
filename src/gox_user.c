#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>

#include "common.h"

static bool interrupted;

int gtpu_map_fd, raw_map_fd, far_map_fd;

enum {
	RAW = 0,
	GTPU
};

static void sigint_handler(int signum)
{
	printf("interrupted\n");
	interrupted = true;
}


static
int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map)  {
        printf("Error finding eBPF map: %s\n", mapname);
        goto out;
    }

    fd = bpf_map__fd(map);

out:
	return fd;
}

static 
int set_program_by_title(struct bpf_object *bpf_obj, int prog_fd,
                         const char *title, const char *ifname)
{
	struct bpf_program *prog;
	int ifindex = if_nametoindex(ifname);
	
	prog = bpf_object__find_program_by_title(bpf_obj, title);
	prog_fd = bpf_program__fd(prog);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
		printf("can't attach program to interface %d\n", ifindex);
		return -1;
	}

	return ifindex;
}

static
int update_forwarding_rule_element(u16 pdr_id, u32 far_id, u32 self_teid,
                                   u32 ue_addr, u32 gtpu_addr, bool forward,
								   u32 peer_teid, u32 peer_addr, int direction)
{
	struct pdi_t pdi = {
		.teid = self_teid,
		.gtpu_addr_ipv4.s_addr = gtpu_addr,
		.ue_addr_ipv4.s_addr = ue_addr
	};

	struct pdr_t pdr = {
		.id = pdr_id,
		.far_id = far_id,
		.pdi = pdi
	};

	struct far_t far = {
		.id = far_id,
		.forward = false
	};

	if (forward) {
		far.forward = true;
		far.teid = peer_teid;
		far.peer_addr_ipv4.s_addr = peer_addr;
	}

	if (direction == RAW) {
		if (bpf_map_update_elem(raw_map_fd, &pdi.ue_addr_ipv4, &pdr, BPF_ANY)) {
			printf("can't add raw map entry\n");
			return -1;
		}
	} else {
		if (bpf_map_update_elem(gtpu_map_fd, &self_teid, &pdr, BPF_ANY)) {
			printf("can't add gtpu map entry\n");
			return -1;
		}
	}

	if (bpf_map_update_elem(far_map_fd, &far.id, &far, BPF_ANY)) {
		printf("can't add far entry\n");
		return -1;
	}	

	return 0;
}


int main(int argc, char **argv)
{
	int prog_fd, gtpu_ifindex, raw_ifindex;
	struct bpf_object *obj;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "src/gox_kern.o",
	};

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("can't load file %s\n", prog_load_attr.file);
		return -1;
	}

	if ((gtpu_map_fd = find_map_fd(obj, "gtpu_pdr_entries")) < 0) return -1;
	if ((raw_map_fd = find_map_fd(obj, "raw_pdr_entries")) < 0) return -1;
	if ((far_map_fd = find_map_fd(obj, "far_entries")) < 0) return -1;

	if (strcmp(argv[1], "upf") == 0) {
		if ((gtpu_ifindex = set_program_by_title(obj, prog_fd, "input_gtpu_prog", "upf-veth1")) < 0) return -1;
		if ((raw_ifindex = set_program_by_title(obj, prog_fd, "input_raw_prog", "upf-veth2")) < 0) return -1;

		//upf pdr_id, far_id, self_teid, ue_addr, gtpu_addr, forward, peer_teid, peer_addr, direction(raw/gtpu)
		update_forwarding_rule_element(1, 21, 202, 0x100000A, 0x200A8C0, false, 0, 0, 1);
		update_forwarding_rule_element(2, 22, 202, 0x100000A, 0x200A8C0, true, 101, 0x100A8C0, 0);
	} else if (strcmp(argv[1], "ran") == 0) {
		// ran
		gtpu_ifindex = set_program_by_title(obj, prog_fd, "input_gtpu_prog", "ran-veth2");
		raw_ifindex = set_program_by_title(obj, prog_fd, "input_raw_prog", "ran-veth1");

		update_forwarding_rule_element(1, 21, 101, 0x10010AC, 0x100A8C0, false, 0, 0, 1);
		update_forwarding_rule_element(2, 22, 101, 0x10010AC, 0x100A8C0, true, 202, 0x200A8C0, 0);
	}

	struct pdr_t confirm = { 0 };
	u32 key = 202;
	bpf_map_lookup_elem(gtpu_map_fd, &key, &confirm);
	//u32 key = 0x100000A;
	//bpf_map_lookup_elem(raw_map_fd, &key, &confirm);
	printf("pdr.id %d\n", confirm.id);
	printf("pdr.far_id %d\n", confirm.far_id);

	struct pdi_t confirm_pdi = confirm.pdi;
	printf("pdi.teid %d\n", confirm_pdi.teid);
	printf("pdi.ue_addr_ipv4 %x\n", confirm_pdi.ue_addr_ipv4.s_addr);
	printf("pdi.gtpu_addr_ipv4 %x\n", confirm_pdi.gtpu_addr_ipv4.s_addr);

	struct far_t confirm_far = { 0 };
	bpf_map_lookup_elem(far_map_fd, &confirm.far_id, &confirm_far);
	printf("far.id %d\n", confirm_far.id);
	printf("far.forward %d\n", confirm_far.forward);
	printf("far.teid %d\n", confirm_far.teid);
	printf("far.peer_addr_ipv4 %x\n", confirm_far.peer_addr_ipv4.s_addr);

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	while (!interrupted) {
		sleep(1);
	}

	// detach program
	bpf_set_link_xdp_fd(gtpu_ifindex, -1, 0);
	bpf_set_link_xdp_fd(raw_ifindex, -1, 0);

	return 0;
}
