#ifndef CONFIG_HEADER
#define CONFIG_HEADER

#include "xdpfw.h"
struct config_map
{
    char *interface;
    char *serverip;
    unsigned char *key;
    uint16_t serverport;
    uint16_t updatetime;
    unsigned int usecache : 1;
    unsigned int nostats : 1;
    struct filter filters[MAX_FILTERS];
};

void SetConfigDefaults(struct config_map *cfg);
int OpenConfig(const char *filename);
int ReadConfig(struct config_map *cfg);
#endif