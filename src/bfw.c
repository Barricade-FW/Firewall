#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>
#include <pthread.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"

#include "include/bfw.h"
#include "include/config.h"

// Command line variables.
static char *configfile;
static int help = 0;
static int list = 0;

const struct option opts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"list", no_argument, &list, 'l'},
    {"help", no_argument, &help, 'h'},
    {NULL, 0, NULL, 0}
};

// Other variables.
static uint8_t cont = 1;
static int filtersfd = -1;
static int statsfd = -1;
static int timestampfd = -1;

void SignalHndl(int tmp)
{
    cont = 0;
}

void ParseCommandLine(int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:lh", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                configfile = optarg;

                break;

            case 'l':
                list = 1;

                break;

            case 'h':
                help = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}

void UpdateBPF(struct config_map *cfg)
{
    // Loop through all filters and delete the map.
    for (uint8_t i = 0; i < MAX_FILTERS; i++)
    {
        uint32_t key = i;

        bpf_map_delete_elem(filtersfd, &key);
    }

    // Add a filter to the filter maps.
    for (uint32_t i = 0; i < MAX_FILTERS; i++)
    {
        // Check if we have a valid ID.
        if (cfg->filters[i].id < 1)
        {
            break;
        }

        // Attempt to update BPF map.
        if (bpf_map_update_elem(filtersfd, &i, &cfg->filters[i], BPF_ANY) == -1)
        {
            fprintf(stderr, "Error updating BPF item #%d.\n", i);
        }
    }
}

int UpdateConfig(struct config_map *cfg, char *configfile)
{
    // Open config file.
    if (OpenConfig(configfile) != 0)
    {
        fprintf(stderr, "Error opening filters file :: %s\n", configfile);
        
        return -1;
    }

    SetConfigDefaults(cfg);

    for (uint16_t i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i] = (struct filter) {0};
    }

    // Read config and check for errors.
    if (ReadConfig(cfg) != 0)
    {
        fprintf(stderr, "Error reading filters file.\n");

        return -1;
    }

    return 0;
}

int FindMap(struct bpf_object *obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map '%s'.\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}


int LoadBPFObj(const char *filename)
{
    int firstfd = -1;
    struct bpf_object *obj;
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &firstfd);

    if (err)
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Num => %d.\n", filename, strerror(-err), err);

        return -1;
    }

    filtersfd = FindMap(obj, "filters_map");
    statsfd = FindMap(obj, "stats_map");
    timestampfd = FindMap(obj, "timestamp_map");

    return firstfd;
}

static int XDPDetach(int ifindex, uint32_t xdp_flags)
{
    int err;

    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    if (err < 0)
    {
        fprintf(stderr, "Error detaching XDP program. Error => %s. Error Num => %.d\n", strerror(-err), err);

        return -1;
    }

    return EXIT_SUCCESS;
}

static int XDPAttach(int ifindex, uint32_t *flags, int fd)
{
    int err;
    
    err = bpf_set_link_xdp_fd(ifindex, fd, *flags);

    if (err == -EEXIST && !(*flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        
        uint32_t oldflags = *flags;

        *flags &= ~XDP_FLAGS_MODES;
        *flags |= (oldflags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

        err = bpf_set_link_xdp_fd(ifindex, -1, *flags);

        if (!err)
        {
            err = bpf_set_link_xdp_fd(ifindex, fd, oldflags);
        }
    }

    // Check for no XDP-Native support.
    if (err)
    {
        fprintf(stdout, "XDP-Native may not be supported with this NIC. Using SKB instead.\n");

        // Remove DRV Mode flag.
        if (*flags & XDP_FLAGS_DRV_MODE)
        {
            *flags &= ~XDP_FLAGS_DRV_MODE;
        }

        // Add SKB Mode flag.
        if (!(*flags & XDP_FLAGS_SKB_MODE))
        {
            *flags |= XDP_FLAGS_SKB_MODE;
        }

        err = bpf_set_link_xdp_fd(ifindex, fd, *flags);
    }

    if (err < 0)
    {
        fprintf(stderr, "Error attaching XDP program. IfIndex => %d :: %s (%d).\n", ifindex, strerror(-err), -err);

        switch(-err)
        {
            case EEXIST:
            {
                XDPDetach(ifindex, *flags);
                fprintf(stderr, "Additional :: XDP already loaded on device.\n");

                break;
            }

            case EOPNOTSUPP:
                fprintf(stderr, "Additional :: XDP-native nor SKB not supported? Not sure how that's possible.\n");

                break;

            default:
                break;
        }

        return -1;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    // Parse the command line.
    ParseCommandLine(argc, argv);

    // Check for help menu.
    if (help)
    {
        fprintf(stdout, "Usage:\n" \
            "--config -c => Config file location (default is /etc/bfw/bfw.conf).\n" \
            "--list -l => Print config details including filters (this will exit program after done).\n" \
            "--help -h => Print help menu.\n");

        return EXIT_SUCCESS;
    }

    // Raise RLimit.
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "Error setting rlimit.\n");

        return EXIT_FAILURE;
    }

    // Check for --config argument.
    if (configfile == NULL)
    {
        // Assign default.
        configfile = "/etc/bfw/bfw.conf";
    }

    // Initialize config.
    struct config_map *cfg = malloc(sizeof(struct config_map));

    // Set config's defaults.
    SetConfigDefaults(cfg);
    
    // Create last updated variable.
    time_t lastupdated = time(NULL);
    time_t lastupdated_stats = time(NULL);

    // Update config.
    UpdateConfig(cfg, configfile);

    // Check for list option.
    if (list)
    {
        fprintf(stdout, "Details:\n");
        fprintf(stdout, "Interface Name => %s\n", cfg->interface);
        fprintf(stdout, "Update Time => %" PRIu16 "\n", cfg->updatetime);

        for (uint16_t i = 0; i < MAX_FILTERS; i++)
        {
            // Check ID.
            if (cfg->filters[i].id < 1)
            {
                break;
            }

            // General.
            fprintf(stdout, "Filter #%" PRIu16 ":\n", (i + 1));

            fprintf(stdout, "ID => %d\n", cfg->filters[i].id);
            fprintf(stdout, "Enabled => %" PRIu8 "\n", cfg->filters[i].enabled);
            fprintf(stdout, "Action => %" PRIu8 " (0 = Block, 1 = Allow).\n", cfg->filters[i].action);

            // IP addresses.
            struct sockaddr_in sin;
            sin.sin_addr.s_addr = cfg->filters[i].srcip;
            fprintf(stdout, "Source IP => %s\n", inet_ntoa(sin.sin_addr));

            struct sockaddr_in din;
            din.sin_addr.s_addr = cfg->filters[i].dstip;
            fprintf(stdout, "Destination IP => %s\n", inet_ntoa(din.sin_addr));

            // Other IP header information.
            fprintf(stdout, "Max Length => %" PRIu16 "\n", cfg->filters[i].max_len);
            fprintf(stdout, "Min Length => %" PRIu16 "\n", cfg->filters[i].min_len);
            fprintf(stdout, "Max TTL => %" PRIu8 "\n", cfg->filters[i].max_ttl);
            fprintf(stdout, "Min TTL => %" PRIu8 "\n", cfg->filters[i].min_ttl);
            fprintf(stdout, "TOS => %" PRIu8 "\n", cfg->filters[i].tos);
            fprintf(stdout, "PPS => %" PRIu64 "\n", cfg->filters[i].pps);
            fprintf(stdout, "BPS => %" PRIu64 "\n\n", cfg->filters[i].bps);
            fprintf(stdout, "Block Time => %" PRIu64 "\n\n", cfg->filters[i].blocktime);

            // TCP options.
            fprintf(stdout, "TCP Enabled => %" PRIu8 "\n", cfg->filters[i].tcpopts.enabled);
            fprintf(stdout, "TCP Source Port => %" PRIu16 "\n", cfg->filters[i].tcpopts.sport);
            fprintf(stdout, "TCP Destination Port => %" PRIu16 "\n", cfg->filters[i].tcpopts.dport);
            fprintf(stdout, "TCP URG Flag => %" PRIu8 "\n", cfg->filters[i].tcpopts.urg);
            fprintf(stdout, "TCP ACK Flag => %" PRIu8 "\n", cfg->filters[i].tcpopts.ack);
            fprintf(stdout, "TCP RST Flag => %" PRIu8 "\n", cfg->filters[i].tcpopts.rst);
            fprintf(stdout, "TCP PSH Flag => %" PRIu8 "\n", cfg->filters[i].tcpopts.psh);
            fprintf(stdout, "TCP SYN Flag => %" PRIu8 "\n", cfg->filters[i].tcpopts.syn);
            fprintf(stdout, "TCP FIN Flag => %" PRIu8 "\n\n", cfg->filters[i].tcpopts.fin);

            // UDP options.
            fprintf(stdout, "UDP Enabled => %" PRIu8 "\n", cfg->filters[i].udpopts.enabled);
            fprintf(stdout, "UDP Source Port => %" PRIu16 "\n", cfg->filters[i].udpopts.sport);
            fprintf(stdout, "UDP Destination Port => %" PRIu16 "\n\n", cfg->filters[i].udpopts.dport);

            // ICMP options.
            fprintf(stdout, "ICMP Enabled => %" PRIu8 "\n", cfg->filters[i].icmpopts.enabled);
            fprintf(stdout, "ICMP Code => %" PRIu8 "\n", cfg->filters[i].icmpopts.code);
            fprintf(stdout, "ICMP Type => %" PRIu8 "\n", cfg->filters[i].icmpopts.type);

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Get device.
    int dev;

    if ((dev = if_nametoindex(cfg->interface)) < 0)
    {
        fprintf(stderr, "Error finding device %s.\n", cfg->interface);

        return EXIT_FAILURE;
    }

    // XDP variables.
    int xdpfd;
    uint32_t xdpflags;
    char *filename = "/etc/bfw/bfw_xdp.o";

    xdpflags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    // Get XDP's ID.
    xdpfd = LoadBPFObj(filename);

    if (xdpfd <= 0)
    {
        fprintf(stderr, "Error loading BPF object file. File name => %s.\n", filename);

        return EXIT_FAILURE;
    }
    
    // Attach XDP program to device.
    if (XDPAttach(dev, &xdpflags, xdpfd) != 0)
    {
        return EXIT_FAILURE;
    }

    // Check for valid maps.
    if (filtersfd < 0)
    {
        fprintf(stderr, "Error finding 'filters_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    if (statsfd < 0)
    {
        fprintf(stderr, "Error finding 'stats_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    if (timestampfd < 0)
    {
        fprintf(stderr, "Error finding 'timestamp_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    // Update BPF maps.
    UpdateBPF(cfg);

    // Signal.
    signal(SIGINT, SignalHndl);

    // Spawn thread to handle TCP.
    pthread_t pid;

    pthread_create(&pid, NULL, TCPHandle, (void *)cfg);

    while (cont)
    {
        // Get current time.
        time_t curtime = time(NULL);

        // Update timestamp map.
        uint32_t key = 0;
        
        bpf_map_update_elem(timestampfd, &key, &curtime, BPF_ANY);

        // Check for auto-update.
        if (cfg->updatetime > 0 && (curtime - lastupdated) > cfg->updatetime)
        {
            // Update config.
            UpdateConfig(cfg, configfile);

            // Update BPF maps.
            UpdateBPF(cfg);
            
            // Update last updated variable.
            lastupdated = time(NULL);
        }

        // Update stats.
        if ((curtime - lastupdated_stats) > 2 && !cfg->nostats)
        {
            uint32_t key = 0;
            struct bfw_stats stats;
            
            bpf_map_lookup_elem(statsfd, &key, &stats);

            fflush(stdout);
            fprintf(stdout, "\rPackets Allowed: %" PRIu64 " | Packets Blocked: %" PRIu64, stats.allowed, stats.blocked);
        
            lastupdated_stats = time(NULL);
        }

        sleep(1);
    }

    // Detach XDP program.
    if (XDPDetach(dev, xdpflags) != 0)
    {
        fprintf(stderr, "Error removing XDP program from device '%s'\n", cfg->interface);

        return EXIT_FAILURE;
    }

    // Close config file.
    CloseConfig();

    // Free config.
    free(cfg);

    // Add spacing.
    fprintf(stdout, "\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}