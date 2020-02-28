#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
// #include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#define NSCAN_DIR "/var/run/nscan/"
#define default_socket NSCAN_DIR "nscan.socket"

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
