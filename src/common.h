/* This common.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>

typedef __u64 u64;
typedef __s64 s64;

typedef __u32 u32;
typedef __s32 s32;

typedef __u16 u16;
typedef __s16 s16;

typedef __u8  u8;
typedef __s8  s8;

#define GTPU_G_PDU       255
#define GTP_UDP_PORT     2152

#define GOX_UNIX_DOMAIN  "/var/run/gox"
#define COMMAND_MSG_BUFSIZE         256
#define COMMAND_ITEM_BUFSIZE        64

struct gtpuhdr {
    u8 flags;
    u8 type;
    u16 length;
    u32 teid;
}__attribute__((packed));

struct pdi_t {
    struct in_addr ue_addr_ipv4; // raw key or dn address
    u32 teid; // input_teid & gtpu key
};

struct pdr_t {
    struct pdi_t pdi;
    u32 far_id;
};

struct far_t {
    u32 id;
    bool encapsulation;
    u32 teid; // output_teid for header creation
    struct in_addr peer_addr_ipv4; // ran ip or a-upf ip for header creation
};


#endif /* __COMMON_H */

