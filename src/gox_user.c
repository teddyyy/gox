#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/un.h>

#include "common.h"

static bool interrupted;

struct gox_t {
	int gtpu_map_fd;
	int raw_map_fd;
	int far_map_fd;
	int raw_ifindex;
	int gtpu_ifindex;
};

enum {
	RAW = 0,
	GTPU
};

static void sigint_handler(int signum)
{
	printf("interrupted\n");
	interrupted = true;
}

static void cleanup(struct gox_t *gt)
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
		printf("Error finding eBPF map: %s\n", mapname);
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
int create_unix_domain_socket(char *domain)
{
	int sock;
	struct sockaddr_un saddru = {
		.sun_family = AF_UNIX,
	};

	strncpy(saddru.sun_path, domain, UNIX_PATH_MAX);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&saddru, sizeof (saddru)) != 0) {
		perror("bind");
		close(sock);
		return -1;
	}

	int val = 1;
	if (ioctl(sock, FIONBIO, &val) < 0) {
		perror("ioctl");
		close(sock);
		return -1;
	}

	return sock;
}

static
int resolve_direction_by_ifname(struct gox_t *gt, char *ifname)
{
	int ifindex = if_nametoindex(ifname);
	if (gt->raw_ifindex == ifindex)
		return RAW;
	else if (gt->gtpu_ifindex == ifindex)
		return GTPU;

	return -1;
}

static
void exec_pdr_add_command(struct gox_t *gt, char *cmd, int sock)
{
	int direction, map_fd;
	char ifname[256], key[256], far_id[256];
	struct pdi_t pdi;
	struct pdr_t pdr;

	printf("pdr add: %s\n", cmd);

	if (sscanf(cmd, "%s %s %s", ifname, key, far_id) < 3) {
		write(sock, "invalid pdr add command", 24);
		return;
	}

	if ((direction = resolve_direction_by_ifname(gt, ifname)) < 0) {
		write(sock, "invalid interface name", 24);
		return;
	}

	pdr.far_id = atoi(far_id);
	pdr.pdi = pdi;

	if (direction == RAW) {
		struct in_addr inaddr;
		if (inet_pton(AF_INET, key, &inaddr) < 1) {
			write(sock, "invalid ue address", 19);
			return;
		}
		pdr.pdi.ue_addr_ipv4 = inaddr;

		if (bpf_map_update_elem(gt->raw_map_fd, &pdr.pdi.ue_addr_ipv4, &pdr, BPF_NOEXIST)) {
			write(sock, "can't add raw map entry", 24);
			return;
		}

	} else {
		pdr.pdi.teid = atoi(key);
		if (bpf_map_update_elem(gt->gtpu_map_fd, &pdr.pdi.teid, &pdr, BPF_NOEXIST)) {
			write(sock, "can't add gtpu map entry", 25);
			return;
		}
	}

	write(sock, "add pdr entry", 14);
	return;
}

static
void exec_pdr_del_command(struct gox_t *gt, char *cmd, int sock)
{
	int direction, map_fd;
	char ifname[256], key[256];

	printf("pdr del: %s\n", cmd);

	if (sscanf(cmd, "%s %s", ifname, key) < 2) {
		write(sock, "invalid pdr del command", 24);
		return;
	}

	if ((direction = resolve_direction_by_ifname(gt, ifname)) < 0) {
		write(sock, "invalid interface name", 24);
		return;
	}

	if (direction == RAW) {
		struct in_addr inaddr;
		if (inet_pton(AF_INET, key, &inaddr) < 1) {
			write(sock, "invalid ue address", 19);
			return;
		}

		if (bpf_map_delete_elem(gt->raw_map_fd, &inaddr)) {
			write(sock, "can't delete raw map entry", 27);
			return;
		}
	} else {
		int teid = atoi(key);
		if (bpf_map_delete_elem(gt->gtpu_map_fd, &teid)) {
			write(sock, "can't delete gtpu map entry", 28);
			return;
		}
	}

	write(sock, "delete pdr entry", 17);
	return;
}

static
void exec_far_del_command(struct gox_t *gt, char *cmd, int sock)
{
	char id[256];

	printf("far del: %s\n", cmd);

	if (sscanf(cmd, "%s", id) != 1) {
		write(sock, "invalid far delete command", 27);
		return;
	}

	int key = atoi(id);
	if (bpf_map_delete_elem(gt->far_map_fd, &key)) {
		write(sock, "can't delete far entry", 23);
		return;
	}	

	write(sock, "delete far entry", 17);
	return;
}

static
void exec_far_add_command(struct gox_t *gt, char *cmd, int sock)
{

	char id[256], teid[256], peer_addr[256];
	struct far_t far = { .encapsulation = false };

	printf("far add: %s\n", cmd);

	if (sscanf(cmd, "%s %s %s", id, teid, peer_addr) == 3) {
		far.id = atoi(id);
		far.teid = atoi(teid);
		struct in_addr inaddr;

		if (inet_pton(AF_INET, peer_addr, &inaddr) < 1) {
			write(sock, "invalid peer address", 21);
			return;
		}

		far.peer_addr_ipv4 = inaddr;
		far.encapsulation = true;
	} else if (sscanf(cmd, "%s", id) == 1) {
		far.id = atoi(id);
	} else {
		write(sock, "invalid far add command", 24);
		return;
	}

	if (bpf_map_update_elem(gt->far_map_fd, &far.id, &far, BPF_NOEXIST)) {
		write(sock, "can't add far entry", 20);
		return;
	}

	write(sock, "add far entry", 14);
	return;
}

static
void exec_command(struct gox_t *gt, char *cmd, int sock)
{
	if (strncmp(cmd, "pdr add", 7) == 0) {
		cmd += 8;
		return exec_pdr_add_command(gt, cmd, sock);
	} else if (strncmp(cmd, "pdr del", 7) == 0) {
		cmd += 8;
		return exec_pdr_del_command(gt, cmd, sock);
	} else if (strncmp(cmd, "far add", 7) == 0) {
		cmd += 8;
		return exec_far_add_command(gt, cmd, sock);
	} else if (strncmp(cmd, "far del", 7) == 0) {
		cmd += 8;
		return exec_far_del_command(gt, cmd, sock);
	}

	write(sock, "invalid command", 16);
}

static
void process_gox_control(struct gox_t *gt)
{
	char buf[256];
	char *c;
	int accept_sock, sock;

	if ((sock = create_unix_domain_socket(GOX_UNIX_DOMAIN)) < 0)
		return;

	listen(sock, 1);

	while (!interrupted) {
		memset(buf, 0, sizeof(buf));

		accept_sock = accept(sock, NULL, 0);

		if (read(accept_sock, buf, sizeof(buf)) < 0) {
			continue;
		}

		for (c = buf; *c == ' '; c++);
		exec_command(gt, c, accept_sock);

		close(accept_sock);
	}

	unlink(GOX_UNIX_DOMAIN);
	close(sock);
}

void usage(void) {
	printf("Usage:\n");
	printf("-r <raw iface name>: Name of interface to receive raw packet  (mandatory)\n");
	printf("-g <gtpu iface name>: Name of interface to receive GTPU packet (mandatory)\n");
	printf("-s <gtpu source address>: Address when sending GTPU packet (mandatory)\n");
}


int main(int argc, char **argv)
{
	struct gox_t gt;
	int prog_fd, gtpu_ifindex, raw_ifindex, src_map_fd;
	int option;
	char raw_ifname[IFNAMSIZ] = "";
	char gtpu_ifname[IFNAMSIZ] = "";
	char gtpu_addr[16] = "";
	struct bpf_object *obj;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "src/gox_kern.o",
	};

	while((option = getopt(argc, argv, "r:g:s:h")) > 0) {
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

	memset(&gt, 0, sizeof(struct gox_t));

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

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	// main process
	process_gox_control(&gt);

	cleanup(&gt);

	return 0;
}
