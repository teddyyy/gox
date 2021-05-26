#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/un.h>

#include "gox_user.h"
#include "common.h"
#include "command.h"

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

void copy_command_string(char *dst, char *str)
{
    char *end;

    // trim all leading spaces
    while (isspace(*str)) str++;

    if (*str == 0) return;

    // trim all trailing spaces
    end = str + strlen(str) - 1;
    while(end > str && isspace(*end)) end--;
    end[1] = '\0';

    // copy characters while combining consecutive spaces into one.
    while((*dst++ = *str++) != '\0') {
        if (*(str - 1) == ' ') while (*str == ' ') str++;
    }

}

int main(int argc, char **argv)
{
    int sock, i, option;
    char unix_path[UNIX_PATH_SIZE] = "";
    char cmd[COMMAND_MSG_BUFSIZE] = "";
    char res[COMMAND_MSG_BUFSIZE] = "";

    while((option = getopt(argc, argv, "c:p:h")) > 0) {
        switch(option) {
            case 'h':
                usage();
                return 0;
                break;
            case 'p':
                strncpy(unix_path, optarg, UNIX_PATH_SIZE - 1);
                break;
            case 'c':
                copy_command_string(cmd, optarg);
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

    if (*unix_path == '\0')
        strncpy(unix_path, GOX_UNIX_DOMAIN, UNIX_PATH_SIZE - 1);

    sock = create_unix_domain_socket(unix_path);
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