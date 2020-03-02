#include "nscan.h"

#define ERR(sockfd, format, ...)                                                                                \
    {                                                                                                           \
        syslog(LOG_INFO | LOG_DAEMON, "nscand.c:%d | errno=%d | " format "\n", __LINE__, errno, ##__VA_ARGS__); \
        exit_daemon(sockfd, errno);                                                                             \
    }
#define WARN(format, ...) syslog(LOG_INFO | LOG_DAEMON, "nscand.c:%d | warning | " format "\n", __LINE__, ##__VA_ARGS__);
#define INFO(format, ...) syslog(LOG_INFO | LOG_DAEMON, "nscand.c:%d | info | " format "\n", __LINE__, ##__VA_ARGS__);

void process_received_data(int sockfd, struct nscan_data data_received);
void exit_daemon(int sockfd, int ret);

int main()
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(PORT)};
    int opt = 1;
    int addrlen = sizeof(addr);

    // if (daemon(0, 0))
    //     ERR(0, "Can't daemonize nscan");

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd <= 0)
        ERR(sockfd, "Can't create socket");

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
        ERR(sockfd, "Can't set socket options");

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        ERR(sockfd, "Can't bind socket to %s", addr.sin_addr.s_addr);

    INFO("nscand daemon started");

    while (1)
    {
        struct nscan_data data_received = {0};

        if (listen(sockfd, 1) < 0)
            ERR(sockfd, "Can't listen on socket %d (%s)", sockfd, addr.sin_addr.s_addr);

        int data_sockfd = accept(sockfd, (struct sockaddr *)&addr, (socklen_t *)&addrlen);
        if (data_sockfd < 0)
            ERR(sockfd, "Can't accept connection");

        if (read(data_sockfd, (void *)&data_received, sizeof(data_received)) == -1)
            WARN("Can't read data");

        process_received_data(data_sockfd, data_received);
    }

    return -1;
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

void exit_daemon(int sockfd, int ret)
{
    if (sockfd > 0)
    {
        INFO("Closing sockets...")
        close(sockfd);
    }

    INFO("nscand daemon exited.");
    exit(ret);
}