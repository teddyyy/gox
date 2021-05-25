#ifndef __GOX_USER_H
#define __GOX_USER_H

#include <stdbool.h>

bool interrupted;

struct gox_ctx_t {
	int gtpu_map_fd;
	int raw_map_fd;
	int far_map_fd;
	int raw_ifindex;
	int gtpu_ifindex;
};

#endif