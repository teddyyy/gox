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
#include <limits.h>

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
int create_unix_domain_socket(char *domain)
{
	int sock;
	struct sockaddr_un saddru = { .sun_family = AF_UNIX };

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
void response_command_message(int sock, char *msg) {
	if (write(sock, msg, strlen(msg)) < 0)
		printf("response message can't be returned\n");
}

static
u32 str_to_id(char *str) {
	u32 id = strtoul(str, NULL, 0);
	if (id == UINT_MAX || id == 0) return 0;
	return id;
}

static
int count_params_number(char *params) {
	int count = 1;

	while(*params != '\0'){
		if (strncmp(params, " ", 1) == 0) count++;
		params++;
	}

	return count;
}

static
void exec_pdr_add_command(struct gox_t *gt, char *params, int sock)
{
	int direction, n;
	char ifname[COMMAND_ITEM_BUFSIZE];
	char key[COMMAND_ITEM_BUFSIZE];
	char far_id[COMMAND_ITEM_BUFSIZE];
	struct pdi_t pdi = {};
	struct pdr_t pdr = {};

	n = count_params_number(params);
	if (n != 3) {
		response_command_message(sock, "invalid pdr add command");
		return;
	}

	printf("pdr add: %s\n", params);
	sscanf(params, "%s %s %s", ifname, key, far_id);

	if ((direction = resolve_direction_by_ifname(gt, ifname)) < 0) {
		response_command_message(sock, "invalid interface name");
		return;
	}

	u32 ret = str_to_id(far_id);
	if (ret < 1) {
		response_command_message(sock, "invalid far id");
		return;
	}
	pdr.far_id = ret;
	pdr.pdi = pdi;

	if (direction == RAW) {
		struct in_addr inaddr;
		if (inet_pton(AF_INET, key, &inaddr) < 1) {
			response_command_message(sock, "invalid ue address");
			return;
		}
		pdr.pdi.ue_addr_ipv4 = inaddr;
		if (bpf_map_update_elem(gt->raw_map_fd, &pdr.pdi.ue_addr_ipv4,
                                        &pdr, BPF_NOEXIST)) {
			response_command_message(sock, "can't add raw map entry");
			return;
		}
	} else {
		ret = str_to_id(key);
		if (ret < 1) {
			response_command_message(sock, "invalid teid");
			return;
		}
		pdr.pdi.teid = ret;
		if (bpf_map_update_elem(gt->gtpu_map_fd, &pdr.pdi.teid,
                                        &pdr, BPF_NOEXIST)) {
			response_command_message(sock, "can't add gtpu map entry");
			return;
		}
	}

	response_command_message(sock, "add pdr entry");
	return;
}

static
void exec_pdr_del_command(struct gox_t *gt, char *params, int sock)
{
	int direction, n;
	char ifname[COMMAND_ITEM_BUFSIZE], key[COMMAND_ITEM_BUFSIZE];

	n = count_params_number(params);
	if (n != 2) {
		response_command_message(sock, "invalid pdr del command");
		return;
	}

	printf("pdr del: %s\n", params);
	sscanf(params, "%s %s", ifname, key);

	if ((direction = resolve_direction_by_ifname(gt, ifname)) < 0) {
		response_command_message(sock, "invalid interface name");
		return;
	}

	if (direction == RAW) {
		struct in_addr inaddr;
		if (inet_pton(AF_INET, key, &inaddr) < 1) {
			response_command_message(sock, "invalid ue address");
			return;
		}

		if (bpf_map_delete_elem(gt->raw_map_fd, &inaddr)) {
			response_command_message(sock, "can't delete raw map entry");
			return;
		}
	} else {
		u32 ret = str_to_id(key);
		if (ret < 1) {
			response_command_message(sock, "invalid teid");
			return;
		}
		if (bpf_map_delete_elem(gt->gtpu_map_fd, &ret)) {
			response_command_message(sock, "can't delete gtpu map entry");
			return;
		}
	}

	response_command_message(sock, "delete pdr entry");
	return;
}

static
void exec_far_del_command(struct gox_t *gt, char *params, int sock)
{
	int n;
	char id[COMMAND_ITEM_BUFSIZE];

	n = count_params_number(params);
	if (n != 1) {
		response_command_message(sock, "invalid far del command");
		return;
	}

	printf("far del: %s\n", params);
	sscanf(params, "%s", id);

	u32 ret = str_to_id(id);
	if (ret < 1) {
		response_command_message(sock, "invalid far id");
		return;
	}

	if (bpf_map_delete_elem(gt->far_map_fd, &ret)) {
		response_command_message(sock, "can't delete far entry");
		return;
	}	

	response_command_message(sock, "delete far entry");
	return;
}

static
void exec_far_add_command(struct gox_t *gt, char *params, int sock)
{
	int n;
	char id[COMMAND_ITEM_BUFSIZE];
	char teid[COMMAND_ITEM_BUFSIZE];
	char peer_addr[COMMAND_ITEM_BUFSIZE];
	struct far_t far = { .encapsulation = false };

	n = count_params_number(params);
	if (n != 1 && n != 3) {
		response_command_message(sock, "invalid far add command");
		return;
	}

	printf("far add: %s\n", params);

	if (n == 3) {
		sscanf(params, "%s %s %s", id, teid, peer_addr);
		far.encapsulation = true;

		u32 ret = str_to_id(teid);
		if (ret < 1) {
			response_command_message(sock, "invalid teid");
			return;
		}
		far.teid = ret;

		struct in_addr inaddr;
		if (inet_pton(AF_INET, peer_addr, &inaddr) < 1) {
			response_command_message(sock, "invalid peer address");
			return;
		}
		far.peer_addr_ipv4 = inaddr;
	} else if (n == 1) {
		sscanf(params, "%s", id);
	}

	u32 ret = str_to_id(id);
	if (ret < 1) {
		response_command_message(sock, "invalid far id");
		return;
	}
	far.id = ret;

	if (bpf_map_update_elem(gt->far_map_fd, &far.id, &far, BPF_NOEXIST)) {
		response_command_message(sock, "can't add far entry");
		return;
	}

	response_command_message(sock, "add far entry");
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

	response_command_message(sock, "invalid command");
}

static
void process_gox_control(struct gox_t *gt)
{
	char buf[COMMAND_MSG_BUFSIZE];
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
	printf("-r <raw iface name>: Name of interface to receive raw packet (mandatory)\n");
	printf("-g <gtpu iface name>: Name of interface to receive GTPU packet (mandatory)\n");
	printf("-s <gtpu source address>: Address when sending GTPU packet (mandatory)\n");
}


int main(int argc, char **argv)
{
	struct gox_t gt;
	int prog_fd, src_map_fd, option;
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
