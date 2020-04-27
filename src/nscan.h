#include <arpa/inet.h>
#include <unistd.h>

// ctl
#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// d
#include <syslog.h>

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
