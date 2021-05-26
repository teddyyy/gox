#ifndef __COMMAND_H
#define __COMMAND_H

#define GOX_UNIX_DOMAIN             "/var/run/gox"
#define COMMAND_MSG_BUFSIZE         256
#define COMMAND_ITEM_BUFSIZE        64

void process_gox_control(struct gox_ctx_t *gt);

#endif
