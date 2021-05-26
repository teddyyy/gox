#ifndef __GOX_USER_H
#define __GOX_USER_H

#include <stdbool.h>

#define UNIX_PATH_SIZE 64

bool interrupted;

struct gox_ctx_t {
    int gtpu_map_fd;
    int raw_map_fd;
    int far_map_fd;
    int raw_ifindex;
    int gtpu_ifindex;
    char unix_path[UNIX_PATH_SIZE];
};

#endif