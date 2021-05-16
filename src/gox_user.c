#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

static bool interrupted;

int gtpu_map_fd, raw_map_fd, far_map_fd;

enum {
	RAW = 0,
	GTPU
};

enum {
	UPF = 0,
	RAN
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
                                   u32 ue_addr, u32 gtpu_addr, bool encapsulation,
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
		.encapsulation = false
	};

	if (encapsulation) {
		far.encapsulation = true;
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

void usage(void) {
	printf("Usage:\n");
	printf("-u|-a: use UPF Mode (-u, default) or RAN Mode (-a)\n");
	printf("-r <raw iface name>: Name of interface to use (mandatory)\n");
	printf("-g <gtpu iface name>: Name of interface to use (mandatory)\n");
}


int main(int argc, char **argv)
{
	int prog_fd, gtpu_ifindex, raw_ifindex;
	int option;
	int mode = UPF;
	char raw_ifname[IFNAMSIZ] = "";
	char gtpu_ifname[IFNAMSIZ] = "";
	struct bpf_object *obj;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "src/gox_kern.o",
	};

	while((option = getopt(argc, argv, "r:g:hua")) > 0) {
		switch(option) {
			case 'h':
				usage();
				return -1;
				break;
			case 'u':
				mode = UPF;
				break;
			case 'a':
				mode = RAN;
				break;
			case 'r':
				strncpy(raw_ifname, optarg, IFNAMSIZ - 1);
				break;
			case 'g':
				strncpy(gtpu_ifname, optarg, IFNAMSIZ - 1);
				break;
			default:
				printf("Unknown option %c\n", option);
				printf("\n");
				usage();
				return -1;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		printf("Too many options!\n");
		printf("\n");
		usage();
		return -1;
	}

	if(*raw_ifname == '\0' || *gtpu_ifname == '\0') {
		printf("Must specify raw interface name and gtpu interface name\n");
		printf("\n");
		usage();
		return -1;
	}

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("can't load file %s\n", prog_load_attr.file);
		return -1;
	}

	if ((gtpu_map_fd = find_map_fd(obj, "gtpu_pdr_entries")) < 0)
		return -1;
	if ((raw_map_fd = find_map_fd(obj, "raw_pdr_entries")) < 0)
		return -1;
	if ((far_map_fd = find_map_fd(obj, "far_entries")) < 0)
		return -1;

	if ((gtpu_ifindex = set_program_by_title(obj, prog_fd, "input_gtpu_prog", gtpu_ifname)) < 0)
		return -1;
	if ((raw_ifindex = set_program_by_title(obj, prog_fd, "input_raw_prog", raw_ifname)) < 0)
		return -1;

	if (mode == UPF) {
		//upf pdr_id, far_id, self_teid, ue_addr, gtpu_addr, encapsulation, peer_teid, peer_addr, direction(raw/gtpu)
		update_forwarding_rule_element(1, 21, 202, 0x100000A, 0x200A8C0, false, 0, 0, 1);
		update_forwarding_rule_element(2, 22, 202, 0x100000A, 0x200A8C0, true, 101, 0x100A8C0, 0);
	} else {
		// ran
		update_forwarding_rule_element(1, 21, 101, 0x10010AC, 0x100A8C0, false, 0, 0, 1);
		update_forwarding_rule_element(2, 22, 101, 0x10010AC, 0x100A8C0, true, 202, 0x200A8C0, 0);
	}

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
