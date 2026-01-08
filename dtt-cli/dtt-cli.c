#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "dtt.h"
#include "common.h"
#include "inventory.h"
#include "output.h"
#include "executor.h"

static char *module_name = "command";
static char *args = NULL;
static char *inventory_file = DEFAULT_ANSIBLE_HOSTS;
static int forks = DEFAULT_FORKS;
static int list_hosts = 0;
static char *pattern = "all";

static void print_usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [pattern] [-m module] [-a args] [-i inventory] [-f forks] [--list-hosts] [options]\n"
        "\n"
        "Define and run a single ad-hoc task against a set of hosts.\n"
        "\n"
        "Positional arguments:\n"
        "  pattern               Host pattern (default: all)\n"
        "\n"
        "Optional arguments:\n"
        "  -h, --help            Show this help message and exit\n"
        "      --version         Show program's version number and exit\n"
        "  -i, --inventory INVENTORY\n"
        "                        Specify inventory host path (default: %s)\n"
        "      --list-hosts      Output a list of matching hosts; do not execute anything else\n"
        "  -f, --forks FORKS     Specify number of parallel processes to use (default: %d)\n"
        "\n"
        "Action options:\n"
        "  -m, --module-name MODULE_NAME\n"
        "                        Name of the module to execute (default: command)\n"
        "  -a, --args MODULE_ARGS\n"
        "                        Module arguments (space-separated k=v or quoted string)\n",
        progname,
        DEFAULT_ANSIBLE_HOSTS,
        DEFAULT_FORKS
    );
}

static void parse_args(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"version",     no_argument,       0,  0 },
        {"module-name", required_argument, 0, 'm'},
        {"args",        required_argument, 0, 'a'},
        {"inventory",   required_argument, 0, 'i'},
        {"forks",       required_argument, 0, 'f'},
        {"list-hosts",  no_argument,       0,  0 },
        {0, 0, 0, 0}
    };

    int c;
    int option_index = 0;

    optind = 1;
    while ((c = getopt_long(argc, argv, "hm:a:i:f:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            print_usage(argv[0]);
            exit(0);
        case 'm':
            module_name = optarg;
            break;
        case 'a':
            args = optarg;
            break;
        case 'i':
            inventory_file = optarg;
            break;
        case 'f':
            forks = atoi(optarg);
            break;
        case 0:
            if (strcmp(long_options[option_index].name, "list-hosts") == 0) {
                list_hosts = 1;
            } else if (strcmp(long_options[option_index].name, "help") == 0) {
                print_usage(argv[0]);
                exit(0);
            } else if (strcmp(long_options[option_index].name, "version") == 0) {
                printf(" 1.0 (simplified)\n");
                exit(0);
            }
            break;
        case '?':
            print_usage(argv[0]);
            exit(1);
        default:
            exit(1);
        }
    }

    if (optind < argc) {
        pattern = argv[optind];
        if (optind + 1 < argc) {
            fprintf(stderr, "Warning: only the first non-option argument is used as pattern.\n");
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    parse_args(argc, argv);
    parse_inventory(inventory_file, pattern);

    if (get_host_count() == 0) {
        fprintf(stderr, "No hosts matched.\n");
        return 1;
    }

    if (list_hosts) {
        print_host_list();
        return 0;
    }

    dt_init();
    execute_tasks(module_name, args, forks > 0 ? forks : DEFAULT_FORKS);

    for (int i = 0; i < get_host_count(); i++)
        if (get_host_at(i)->hostname) {
            free(get_host_at(i)->hostname);
        }

    return 0;
}
