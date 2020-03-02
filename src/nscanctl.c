#include "nscan.h"

#define ERR(format, ...)                                                                            \
    {                                                                                               \
        fprintf(stderr, "nscanctl.c:%d | errno=%d | " format "\n", __LINE__, errno, ##__VA_ARGS__); \
        return EXIT_FAILURE;                                                                        \
    }

const char *argp_program_version = "nscan 0.2.3";
const char *argp_program_bug_address = "noone. Keep them to ourself ;)";

static char doc[] = "nscanctl -- client of network scanner daemon nscand\v"
                    "Actions:\n  stop\t\t\t     Stop the daemon. Outputs nothing if successful.";

static char args_doc[] = "ACTION";

static struct argp_option options[] = {
    {"verbose", 'v', 0, 0, "Show input arguments in output"},
    {"ip_address", 'a', "IP", 0, "Specify IP address. If not specified, default (127.0.0.1) will be used."},
    {0}};

struct arguments
{
    char *args[1];
    int verbose;
    char *ip_address;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp argp = {options, parse_opt, args_doc, doc};

void print_args(struct arguments args);
struct nscan_data parse_arguments_to_send(struct arguments args);

int main(int argc, char *argv[])
{
    struct arguments arguments = {.verbose = 0, .ip_address = "127.0.0.1"};

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    if (arguments.verbose)
        print_args(arguments);

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT)};

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd <= 0)
        ERR("Can't create socket");

    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    if (inet_pton(AF_INET, arguments.ip_address, &addr.sin_addr) <= 0)
        ERR("Invalid address");

    if (connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
        ERR("Can't connect to nscand at %s. Is it running?", arguments.ip_address);

    struct nscan_data data = parse_arguments_to_send(arguments);

    if (write(sockfd, (void *)&data, sizeof(data)) < 0)
        ERR("Can't send data to nscand");

    if (data.action == ACTION_FULL || data.action == ACTION_MINI)
    {
        struct response resp = {0};

        if (read(sockfd, (void *)&resp, sizeof(resp)) == -1)
            ERR("Can't read response from nscand");

        printf("%d\n%d\n", resp.result, resp.f);
    }

    exit(0);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'v':
        arguments->verbose = 1;
        break;

    case 'a':
        arguments->ip_address = arg;
        break;

    case ARGP_KEY_ARG:
        if (state->arg_num >= 1)
            argp_usage(state);

        arguments->args[state->arg_num] = arg;
        break;

    case ARGP_KEY_END:
        if (state->arg_num < 1)
            argp_usage(state);
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void print_args(struct arguments args)
{
    printf("IP address: %s\nAction: %s\n", args.ip_address, args.args[0]);
}

struct nscan_data parse_arguments_to_send(struct arguments args)
{
    struct nscan_data data;
    data.a = 0;
    data.b = 'b';

    if (!strcmp(args.args[0], "stop"))
        data.action = ACTION_EXIT;
    else if (!strcmp(args.args[0], "full"))
        data.action = ACTION_FULL;
    else if (!strcmp(args.args[0], "mini"))
        data.action = ACTION_MINI;
    else
        data.action = ACTION_NONE;

    return data;
}