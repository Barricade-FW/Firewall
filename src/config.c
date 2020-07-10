#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include <arpa/inet.h>

#include "include/bfw.h"
#include "include/config.h"

FILE *file;

void SetConfigDefaults(struct config_map *cfg)
{
    cfg->interface = "eth0";
    cfg->stats = 0;
    cfg->updatetime = 15;
    cfg->serverip = "";
    cfg->serverport = 0;

    for (uint16_t i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].action = 0;
        cfg->filters[i].srcip = 0;
        cfg->filters[i].dstip = 0;

        cfg->filters[i].do_min_len = 0;
        cfg->filters[i].min_len = 0;

        cfg->filters[i].do_max_len = 0;
        cfg->filters[i].max_len = 65535;

        cfg->filters[i].do_min_ttl = 0;
        cfg->filters[i].min_ttl = 0;

        cfg->filters[i].do_max_ttl = 0;
        cfg->filters[i].max_ttl = 255;

        cfg->filters[i].do_tos = 0;
        cfg->filters[i].tos = 0;

        cfg->filters[i].do_pps = 0;
        cfg->filters[i].pps = 0;
        
        cfg->filters[i].do_bps = 0;
        cfg->filters[i].bps = 0;

        cfg->filters[i].blocktime = 1;
        
        cfg->filters[i].tcpopts.enabled = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_urg = 0;
        cfg->filters[i].tcpopts.do_ack = 0;
        cfg->filters[i].tcpopts.do_rst = 0;
        cfg->filters[i].tcpopts.do_psh = 0;
        cfg->filters[i].tcpopts.do_syn = 0;
        cfg->filters[i].tcpopts.do_fin = 0;

        cfg->filters[i].udpopts.enabled = 0;
        cfg->filters[i].udpopts.do_sport = 0;
        cfg->filters[i].udpopts.do_dport = 0;

        cfg->filters[i].icmpopts.enabled = 0;
        cfg->filters[i].icmpopts.do_code = 0;
        cfg->filters[i].icmpopts.do_type = 0;
    }
}

int OpenConfig(const char *filename)
{
    // Close any existing files.
    if (file != NULL)
    {
        fclose(file);

        file = NULL;
    }

    file = fopen(filename, "r");

    if (file == NULL)
    {
        return 1;
    }

    return 0;
}

void CloseConfig()
{
    fclose(file);
}

int ReadConfig(struct config_map *cfg)
{
    // Not sure why this would be set to NULL after checking for it in OpenConfig(), but just for safety.
    if (file == NULL)
    {
        return -1;
    }

    // Create base JSON objects.
    struct json_object *parsed;

    struct json_object *interface;
    struct json_object *stats;
    struct json_object *updatetime;
    struct json_object *serverip;
    struct json_object *serverport;
    struct json_object *key;

    struct json_object *filters;

    // Initialize buffer we'll store JSON contents in.
    char buffer[4096];

    // Get config file's size by getting position at end of file.
    size_t sz;

    fseek(file, 0L, SEEK_END);
    sz = ftell(file);
    fseek(file, 0L, SEEK_SET);

    // Read config file.
    fread(buffer, sz, 1, file);

    // Parse JSON buffer.
    parsed = json_tokener_parse(buffer);

    // Check if JSON data is valid.
    if (parsed == NULL)
    {
        fprintf(stderr, "Error reading config file :: Error parsing JSON data.\n");

        return 1;
    }

    // Read interface and store into config.
    json_object_object_get_ex(parsed, "interface", &interface);
    cfg->interface = (char *) json_object_get_string(interface);

    // Read stats and store into config.
    json_object_object_get_ex(parsed, "stats", &stats);
    cfg->stats = json_object_get_boolean(stats) ? 1 : 0;

    // Read update time and store into config.
    json_object_object_get_ex(parsed, "updatetime", &updatetime);
    cfg->updatetime = (uint16_t) json_object_get_int(updatetime);

    // Read backbone server IP and store.
    if (json_object_object_get_ex(parsed, "serverip", &serverip))
    {
        cfg->serverip = (char *) json_object_get_string(serverip);
    }

    // Read backbone server port and store.
    if (json_object_object_get_ex(parsed, "serverport", &serverport))
    {
        cfg->serverport = (uint16_t) json_object_get_int(serverport);
    }

    // Read key and store.
    if (json_object_object_get_ex(parsed, "key", &key))
    {
        // Copy characters to cfg->key, but exclude null terminator (\0).
        cfg->key = (unsigned char *) json_object_get_string(key);
    }

    // Read filters.
    json_object_object_get_ex(parsed, "filters", &filters);

    // Get filters length.
    size_t filterslen = json_object_array_length(filters);

    // Loop through each filter.
    struct json_object *filter;

    for (int i = 0; i < filterslen; i++)
    {
        // Get the filter we're currently on.
        filter = json_object_array_get_idx(filters, i);

        // Assign filter ID to index.
        cfg->filters[i].id = i + 1;

        // Get and store enabled.
        struct json_object *enabled;
        if (!json_object_object_get_ex(filter, "enabled", &enabled))
        {
            // Enabled isn't optional. Warn and break.
            fprintf(stderr, "Unable to find \"enabled\" item on filter #%d. Breaking...\n", i);

            // Disable filter if it isn't already.
            cfg->filters[i].enabled = 0;

            break;
        }

        cfg->filters[i].enabled = json_object_get_boolean(enabled) ? 1 : 0;

        // Get and store action.
        struct json_object *action;

        if (!json_object_object_get_ex(filter, "action", &action))
        {
            // Action isn't optional. Warn and break.
            fprintf(stderr, "Unable to find \"action\" item on filter #%d. Breaking...\n", i);

            // Disable filter if it isn't already.
            cfg->filters[i].enabled = 0;

            break;
        }

        cfg->filters[i].action = (uint8_t) json_object_get_int(action);

        // Get and store source IP.
        struct json_object *srcip;

        if (json_object_object_get_ex(filter, "srcip", &srcip))
        {
            cfg->filters[i].srcip = inet_addr(json_object_get_string(srcip));
        }

        // Get and store destination IP.
        struct json_object *dstip;

        if (json_object_object_get_ex(filter, "dstip", &dstip))
        {
            cfg->filters[i].dstip = inet_addr(json_object_get_string(dstip));
        }

        // Get and store min length.
        struct json_object *minlen;

        if (json_object_object_get_ex(filter, "minlen", &minlen))
        {
            cfg->filters[i].do_min_len = 1;
            cfg->filters[i].min_len = (uint16_t) json_object_get_int(minlen);
        }

        // Get and store max length.
        struct json_object *maxlen;

        if (json_object_object_get_ex(filter, "maxlen", &maxlen))
        {
            cfg->filters[i].do_max_len = 1;
            cfg->filters[i].max_len = (uint16_t) json_object_get_int(maxlen);
        }

        // Get and store min TTL.
        struct json_object *minttl;

        if (json_object_object_get_ex(filter, "minttl", &minttl))
        {
            cfg->filters[i].do_min_ttl = 1;
            cfg->filters[i].min_ttl = (uint16_t) json_object_get_int(minttl);
        }

        // Get and store max TTL.
        struct json_object *maxttl;

        if (json_object_object_get_ex(filter, "maxttl", &maxttl))
        {
            cfg->filters[i].do_max_ttl = 1;
            cfg->filters[i].max_ttl = (uint16_t) json_object_get_int(maxttl);
        }

        // Get and store TOS.
        struct json_object *tos;

        if (json_object_object_get_ex(filter, "tos", &tos))
        {
            cfg->filters[i].do_tos = 1;
            cfg->filters[i].tos = (uint8_t) json_object_get_int(tos);
        }

        // Get and store PPS.
        struct json_object *pps;

        if (json_object_object_get_ex(filter, "pps", &pps))
        {
            cfg->filters[i].do_pps = 1;
            cfg->filters[i].pps = json_object_get_uint64(pps);
        }

        // Get and store BPS.
        struct json_object *bps;

        if (json_object_object_get_ex(filter, "bps", &bps))
        {
            cfg->filters[i].do_bps = 1;
            cfg->filters[i].bps = json_object_get_uint64(bps);
        }

        // Get and store block time.
        struct json_object *blocktime;

        if (json_object_object_get_ex(filter, "blocktime", &blocktime))
        {
            cfg->filters[i].blocktime = (long int) json_object_get_int(blocktime);
        }

        // Get and store TCP enabled.
        struct json_object *tcpenabled;

        if (json_object_object_get_ex(filter, "tcp_enabled", &tcpenabled))
        {
            cfg->filters[i].tcpopts.enabled = json_object_get_boolean(tcpenabled) ? 1 : 0;

            if (cfg->filters[i].tcpopts.enabled)
            {
                // Get and store TCP source port.
                struct json_object *tcpsport;

                if (json_object_object_get_ex(filter, "tcp_sport", &tcpsport))
                {
                    cfg->filters[i].tcpopts.do_sport = 1;
                    cfg->filters[i].tcpopts.sport = (uint16_t) json_object_get_int(tcpsport);
                }

                // Get and store TCP destination port.
                struct json_object *tcpdport;

                if (json_object_object_get_ex(filter, "tcp_dport", &tcpdport))
                {
                    cfg->filters[i].tcpopts.do_dport = 1;
                    cfg->filters[i].tcpopts.dport = (uint16_t) json_object_get_int(tcpdport);
                }

                // Get and store TCP URG flag.
                struct json_object *tcpurg;

                if (json_object_object_get_ex(filter, "tcp_urg", &tcpurg))
                {
                    cfg->filters[i].tcpopts.do_urg = 1;
                    cfg->filters[i].tcpopts.urg = json_object_get_boolean(tcpurg) ? 1 : 0;
                }
    
                // Get and store TCP ACK flag.
                struct json_object *tcpack;

                if (json_object_object_get_ex(filter, "tcp_ack", &tcpack))
                {
                    cfg->filters[i].tcpopts.do_ack = 1;
                    cfg->filters[i].tcpopts.ack = json_object_get_boolean(tcpack) ? 1 : 0;
                }

                // Get and store TCP RST flag.
                struct json_object *tcprst;

                if (json_object_object_get_ex(filter, "tcp_rst", &tcprst))
                {
                    cfg->filters[i].tcpopts.do_rst = 1;
                    cfg->filters[i].tcpopts.rst = json_object_get_boolean(tcprst) ? 1 : 0;
                }

                // Get and store TCP PSH flag.
                struct json_object *tcppsh;

                if (json_object_object_get_ex(filter, "tcp_psh", &tcppsh))
                {
                    cfg->filters[i].tcpopts.do_psh = 1;
                    cfg->filters[i].tcpopts.psh = json_object_get_boolean(tcppsh) ? 1 : 0;
                }

                // Get and store TCP SYN flag.
                struct json_object *tcpsyn;

                if (json_object_object_get_ex(filter, "tcp_syn", &tcpsyn))
                {
                    cfg->filters[i].tcpopts.do_syn = 1;
                    cfg->filters[i].tcpopts.syn = json_object_get_boolean(tcpsyn) ? 1 : 0;
                }

                // Get and store TCP FIN flag.
                struct json_object *tcpfin;

                if (json_object_object_get_ex(filter, "tcp_fin", &tcpfin))
                {
                    cfg->filters[i].tcpopts.do_fin = 1;
                    cfg->filters[i].tcpopts.fin = json_object_get_boolean(tcpfin) ? 1 : 0;
                }
            }
        }

        // Get and store UDP enabled.
        struct json_object *udpenabled;

        if (json_object_object_get_ex(filter, "udp_enabled", &udpenabled))
        {
            cfg->filters[i].udpopts.enabled = json_object_get_boolean(udpenabled) ? 1 : 0;

            if (cfg->filters[i].udpopts.enabled)
            {
                // Get and store UDP source port.
                struct json_object *udpsport;

                if (json_object_object_get_ex(filter, "udp_sport", &udpsport))
                {
                    cfg->filters[i].udpopts.do_sport = 1;
                    cfg->filters[i].udpopts.sport = (uint16_t) json_object_get_int(udpsport);
                }

                // Get and store UDP destination port.
                struct json_object *udpdport;

                if (json_object_object_get_ex(filter, "udp_dport", &udpdport))
                {
                    cfg->filters[i].udpopts.do_dport = 1;
                    cfg->filters[i].udpopts.dport = (uint16_t) json_object_get_int(udpdport);
                }
            }
        }

        // Get and store ICMP enabled.
        struct json_object *icmpenabled;

        if (json_object_object_get_ex(filter, "icmp_enabled", &icmpenabled))
        {
            cfg->filters[i].icmpopts.enabled = json_object_get_boolean(icmpenabled) ? 1 : 0;

            if (cfg->filters[i].icmpopts.enabled)
            {
                // Get and store ICMP code.
                struct json_object *icmpcode;

                if (json_object_object_get_ex(filter, "icmp_code", &icmpcode))
                {
                    cfg->filters[i].icmpopts.do_code = 1;
                    cfg->filters[i].icmpopts.code = (uint8_t) json_object_get_int(icmpcode);
                }

                // Get and store ICMP type.
                struct json_object *icmptype;

                if (json_object_object_get_ex(filter, "icmp_type", &icmptype))
                {
                    cfg->filters[i].icmpopts.do_type = 1;
                    cfg->filters[i].icmpopts.type = (uint8_t) json_object_get_int(icmptype);
                }
            }
        }
    }

    return 0;
}