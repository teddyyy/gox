#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/un.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "gox_user.h"
#include "command.h"

enum {
	RAW = 0,
	GTPU
};

static
int create_unix_domain_socket(char *domain)
{
	int sock, val = 1;
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

	if (ioctl(sock, FIONBIO, &val) < 0) {
		perror("ioctl");
		close(sock);
		return -1;
	}

	return sock;
}

static
int resolve_direction_by_ifname(struct gox_ctx_t *gt, char *ifname)
{
	int ifindex = if_nametoindex(ifname);
	if (gt->raw_ifindex == ifindex)
		return RAW;
	else if (gt->gtpu_ifindex == ifindex)
		return GTPU;

	return -1;
}

static
void response_command_message(int sock, char *msg)
{
	if (write(sock, msg, strlen(msg)) < 0)
		printf("response message can't be returned\n");
}

static
int count_params_number(char *params)
{
	int count = 1;

	while(*params != '\0'){
		if (strncmp(params, " ", 1) == 0) count++;
		params++;
	}

	return count;
}

static
int set_u32_value(char *str, u32 *id)
{
	u32 val = strtoul(str, NULL, 0);
	if (val == UINT_MAX || val == 0) return -1;

	memcpy(id, &val, sizeof(u32));

	return 0;
}

static
int set_ipv4_addr(char *addrstr, struct in_addr *inaddr)
{
	struct in_addr tmp;
	if (inet_pton(AF_INET, addrstr, &tmp) < 1) return -1;
	memcpy(inaddr, &tmp, sizeof(struct in_addr));

	return 0;
}

static
void exec_pdr_add_command(struct gox_ctx_t *gt, char *params, int sock)
{
	int direction, n;
	char ifname[IFNAMSIZ];
	char key[COMMAND_ITEM_BUFSIZE];
	char far_id[COMMAND_ITEM_BUFSIZE];
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

	if (set_u32_value(far_id, &pdr.far_id) < 0) {
		response_command_message(sock, "invalid far id");
		return;
	}

	if (direction == RAW) {
		if (set_ipv4_addr(key, &pdr.pdi.ue_addr_ipv4) < 0) {
			response_command_message(sock, "invalid ue address");
			return;
		}
		if (bpf_map_update_elem(gt->raw_map_fd, &pdr.pdi.ue_addr_ipv4,
                                        &pdr, BPF_NOEXIST)) {
			response_command_message(sock, "can't add raw map entry");
			return;
		}
	} else {
		if (set_u32_value(key, &pdr.pdi.teid) < 0) {
			response_command_message(sock, "invalid teid");
			return;
		}
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
void exec_pdr_del_command(struct gox_ctx_t *gt, char *params, int sock)
{
	u32 ret;
	int direction, n;
	struct in_addr inaddr;
	char ifname[IFNAMSIZ], key[COMMAND_ITEM_BUFSIZE];

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
		if (set_ipv4_addr(key, &inaddr) < 0) {
			response_command_message(sock, "invalid ue address");
			return;
		}
		if (bpf_map_delete_elem(gt->raw_map_fd, &inaddr)) {
			response_command_message(sock, "can't delete raw map entry");
			return;
		}
	} else {
		if (set_u32_value(key, &ret) < 0) {
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
void exec_far_del_command(struct gox_ctx_t *gt, char *params, int sock)
{
	u32 ret;
	char id[COMMAND_ITEM_BUFSIZE];

	int n = count_params_number(params);
	if (n != 1) {
		response_command_message(sock, "invalid far del command");
		return;
	}

	printf("far del: %s\n", params);
	sscanf(params, "%s", id);

	if (set_u32_value(id, &ret) < 0) {
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
void exec_far_add_command(struct gox_ctx_t *gt, char *params, int sock)
{
	char id[COMMAND_ITEM_BUFSIZE];
	char teid[COMMAND_ITEM_BUFSIZE];
	char peer_addr[COMMAND_ITEM_BUFSIZE];
	struct far_t far = { .encapsulation = false };

	int n = count_params_number(params);
	if (n != 1 && n != 3) {
		response_command_message(sock, "invalid far add command");
		return;
	}

	printf("far add: %s\n", params);

	if (n == 3) {
		sscanf(params, "%s %s %s", id, teid, peer_addr);
		far.encapsulation = true;

		if (set_u32_value(teid, &far.teid) < 0) {
			response_command_message(sock, "invalid teid");
			return;
		}

		if (set_ipv4_addr(peer_addr, &far.peer_addr_ipv4) < 0) {
			response_command_message(sock, "invalid peer address");
			return;
		}
	} else if (n == 1) {
		sscanf(params, "%s", id);
	}

	if (set_u32_value(id, &far.id) < 0) {
		response_command_message(sock, "invalid far id");
		return;
	}

	if (bpf_map_update_elem(gt->far_map_fd, &far.id, &far, BPF_NOEXIST)) {
		response_command_message(sock, "can't add far entry");
		return;
	}

	response_command_message(sock, "add far entry");
	return;
}

static
void exec_command(struct gox_ctx_t *gt, char *cmd, int sock)
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

void process_gox_control(struct gox_ctx_t *gt)
{
	char buf[COMMAND_MSG_BUFSIZE];
	char *c;
	int accept_sock, sock;

	if ((sock = create_unix_domain_socket(gt->unix_path)) < 0)
		return;

	listen(sock, 1);

	while (!interrupted) {
		memset(buf, 0, sizeof(buf));

		accept_sock = accept(sock, NULL, 0);

		if (read(accept_sock, buf, sizeof(buf)) < 0) continue;

		for (c = buf; *c == ' '; c++);
		exec_command(gt, c, accept_sock);

		close(accept_sock);
	}

	unlink(gt->unix_path);
	close(sock);
}

