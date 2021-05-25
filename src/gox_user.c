#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "gox_user.h"
#include "command.h"


static
void sigint_handler(int signum)
{
	printf("interrupted\n");
	interrupted = true;
}

static
void cleanup(struct gox_ctx_t *gt)
{
	// detach xdp program
	bpf_set_link_xdp_fd(gt->gtpu_ifindex, -1, 0);
	bpf_set_link_xdp_fd(gt->raw_ifindex, -1, 0);
}

static
int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, mapname);

	if (!map)  {
		printf("can't find eBPF map: %s\n", mapname);
		goto out;
	}

	fd = bpf_map__fd(map);

out:
	return fd;
}

static 
int set_xdp_program(struct bpf_object *bpf_obj, int prog_fd,
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
int set_source_gtpu_addr(int fd, char *addr)
{
	struct in_addr gtpu_addr;
	int key = 0;

	if (inet_pton(AF_INET, addr, &gtpu_addr) < 1) {
		printf("invalid gtpu addr\n");
		return -1;
	}

	if (bpf_map_update_elem(fd, &key, &gtpu_addr, BPF_NOEXIST)) {
		printf("can't add gtpu addr map entry\n");
		return -1;
	}

	return 0;
}

static
void usage(void) {
	printf("Usage:\n");
	printf("\t-r <raw iface name>: Name of interface to receive raw packet (mandatory)\n");
	printf("\t-g <gtpu iface name>: Name of interface to receive GTPU packet (mandatory)\n");
	printf("\t-s <gtpu source address>: Address when sending GTPU packet (mandatory)\n");
	printf("\t-p <unix domain socket path>: Path of unix socket to listen (default: /var/run/gox)\n");
}

int main(int argc, char **argv)
{
	struct gox_ctx_t gt;
	int prog_fd, src_map_fd, option;
	char raw_ifname[IFNAMSIZ] = "";
	char gtpu_ifname[IFNAMSIZ] = "";
	char gtpu_addr[16] = "";
	char unix_path[UNIX_PATH_SIZE] = "";
	struct bpf_object *obj;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "src/gox_kern.o",
	};

	while((option = getopt(argc, argv, "r:g:s:p:h")) > 0) {
		switch(option) {
			case 'h':
				usage();
				return 0;
				break;
			case 's':
				strncpy(gtpu_addr, optarg, 16);
				break;
			case 'r':
				strncpy(raw_ifname, optarg, IFNAMSIZ - 1);
				break;
			case 'g':
				strncpy(gtpu_ifname, optarg, IFNAMSIZ - 1);
				break;
			case 'p':
				strncpy(unix_path, optarg, UNIX_PATH_SIZE - 1);
				break;
			default:
				printf("Unknown option %c\n\n", option);
				usage();
				return -1;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		printf("Too many options!\n\n");
		usage();
		return -1;
	}

	if(*raw_ifname == '\0' || *gtpu_ifname == '\0' || *gtpu_addr == '\0') {
		usage();
		return -1;
	}

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("can't load file %s\n", prog_load_attr.file);
		return -1;
	}

	memset(&gt, 0, sizeof(struct gox_ctx_t));

	if ((gt.gtpu_map_fd = find_map_fd(obj, "gtpu_pdr_entries")) < 0)
		return -1;
	if ((gt.raw_map_fd = find_map_fd(obj, "raw_pdr_entries")) < 0)
		return -1;
	if ((gt.far_map_fd = find_map_fd(obj, "far_entries")) < 0)
		return -1;
	if ((src_map_fd = find_map_fd(obj, "src_gtpu_addr")) < 0)
		return -1;

	if ((gt.gtpu_ifindex = set_xdp_program(obj, prog_fd, "input_gtpu_prog", gtpu_ifname)) < 0)
		return -1;
	if ((gt.raw_ifindex = set_xdp_program(obj, prog_fd, "input_raw_prog", raw_ifname)) < 0)
		return -1;

	if (set_source_gtpu_addr(src_map_fd, gtpu_addr) < 0) {
		cleanup(&gt);
		return -1;
	}

	*unix_path != '\0' ? strncpy(gt.unix_path, unix_path, UNIX_PATH_SIZE - 1) : \
	                     strncpy(gt.unix_path, GOX_UNIX_DOMAIN, UNIX_PATH_SIZE - 1);

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	// main process
	process_gox_control(&gt);

	cleanup(&gt);

	return 0;
}
