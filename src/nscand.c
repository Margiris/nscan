#include <ftw.h>
#include <dirent.h>
#include "nscan.h"

#define ERR(sockfd, format, ...)                                                                                \
    {                                                                                                           \
        syslog(LOG_INFO | LOG_DAEMON, "nscand.c:%d | errno=%d | " format "\n", __LINE__, errno, ##__VA_ARGS__); \
        exit_daemon(sockfd, errno);                                                                             \
    }
#define WARN(format, ...) syslog(LOG_INFO | LOG_DAEMON, "nscand.c:%d | warning | " format "\n", __LINE__, ##__VA_ARGS__);
#define INFO(format, ...) syslog(LOG_INFO | LOG_DAEMON, "nscand.c:%d | info | " format "\n", __LINE__, ##__VA_ARGS__);

#define PORT 4242

int remove_directory(const char *path)
{
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d)
    {
        struct dirent *p;
        r = 0;

        while (!r && (p = readdir(d)))
        {
            int r2 = -1;
            char *buf;
            size_t len;

            /* Skip the names "." and ".." as we don't want to recurse on them. */
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
                continue;

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf)
            {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf))
                {
                    if (S_ISDIR(statbuf.st_mode))
                        r2 = remove_directory(buf);
                    else
                        r2 = unlink(buf);
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }

    if (!r)
        r = rmdir(path);

    return r;
}

void exit_daemon(int sockfd, int ret)
{
    if (sockfd > 0)
    {
        INFO("Closing sockets...")
        close(sockfd);
    }

    if (remove_directory(NSCAN_DIR))
        WARN("Unable to cleanup. Remove %s before starting nscand again.", NSCAN_DIR);

    INFO("nscand daemon exited.");
    exit(ret);
}

void process_received_data(int sockfd, struct nscan_data data_received)
{
    if (data_received.action == ACTION_EXIT)
        exit_daemon(sockfd, 0);
    if (data_received.action == ACTION_FULL || data_received.action == ACTION_MINI)
    {
        struct response response = {0};
        response.f = 4;
        response.result = data_received.action == ACTION_FULL ? RESULT_FAIL : RESULT_SUCCESS;
        INFO("%d", response.result);

        if (write(sockfd, (void *)&response, sizeof(struct response)) < 0)
            WARN("Can't send data to client");
    }
}

int main()
{

    // _un - UNIX, _in - internet
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = default_socket};

    if (daemon(0, 0))
        ERR(0, "Can't daemonize nscan");

    // Set safe umask and create directory.
    umask(0022);
    if (mkdir(NSCAN_DIR, 0755) < 0)
        ERR(0, "Can't create directory %s", NSCAN_DIR);

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd <= 0)
        ERR(sockfd, "Can't create socket");

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        ERR(sockfd, "Can't bind socket to %s", addr.sun_path);

    INFO("nscand daemon started");

    while (1)
    {
        struct nscan_data data_received = {0};

        if (listen(sockfd, 4) < 0)
            ERR(sockfd, "Can't listen on socket %d (%s)", sockfd, addr.sun_path);

        int data_sockfd = accept(sockfd, 0, 0);
        if (data_sockfd < 0)
            ERR(sockfd, "Can't accept connection");

        if (read(data_sockfd, (void *)&data_received, sizeof(data_received)) == -1)
            WARN("Can't read data");

        process_received_data(data_sockfd, data_received);
    }

    return -1;
}
