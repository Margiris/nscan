#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 4242

enum Action
{
    ACTION_NONE,
    ACTION_FULL,
    ACTION_MINI,
    ACTION_EXIT
};

enum Result
{
    RESULT_SUCCESS,
    RESULT_FAIL
};

struct nscan_data
{
    int a;
    char b;
    enum Action action;
};

struct response
{
    int f;
    enum Result result;
};
