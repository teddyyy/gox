#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/un.h>

#include "common.h"


void usage(void) {
    printf("Usage: goxctl [object] [command] [params]\n");
    printf("\tobject: [ pdr | far ] \n");
    printf("\tcommand: [ add | del ] \n");
    printf("\tparams pdr add: [ifname] [ self teid | ue addr ] [far id]\n");
    printf("\tparams pdr del: [ifname] [ self teid | ue addr ]\n");
    printf("\tparams far add: [far id] <teid> <peer addr>\n");
    printf("\tparams far del: [far id]\n");
}

int create_unix_domain_socket(char *domain)
{
    int sock;
    struct sockaddr_un saddru = { .sun_family = AF_UNIX };

    strncpy(saddru.sun_path, domain, UNIX_PATH_MAX);

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&saddru, sizeof (saddru)) != 0) {
        perror("connect");
        return -1;
    }

    return sock;
}

int main(int argc, char **argv)
{
    int sock, i;
    char cmd[COMMAND_MSG_BUFSIZE] = "";
    char buf[COMMAND_MSG_BUFSIZE] = "";
    char res[COMMAND_MSG_BUFSIZE] = "";

    if (argc < 3) {
        usage();
        return -1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    if (strcmp(argv[1], "pdr") != 0 && strcmp(argv[1], "far") != 0) {
        usage();
        return -1;
    }

    if (strcmp(argv[2], "add") != 0 && strcmp(argv[2], "del") != 0) {
        usage();
        return -1;
    }

    for (i = 1; i < argc; i++) {
        strncpy (buf, cmd, sizeof(buf));
        snprintf (cmd, sizeof(cmd), "%s %s", buf, argv[i]);
    }

    sock = create_unix_domain_socket(GOX_UNIX_DOMAIN);
    if (sock < 0) {
        printf("can't create unix domain socket\n");
        return -1;
    }

    if (write(sock, cmd, sizeof(cmd)) < 0) {
        printf("can't write unix domain socket\n");
        close(sock);
        return -1;
    }

    if (read(sock, res, sizeof(res)) < 0) {
        printf("can't read unix domain socket\n");
        close(sock);
        return -1;
    }

    printf("%s\n", res);

    close(sock);

    return 0;
}