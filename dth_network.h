#ifndef __DTH_NETWORK_H__
#define __DTH_NETWORK_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define CDHX_NETWORK_PARAMS_FILE_PATH	"/etc/network/interfaces"


typedef struct network_params {
	unsigned int ip;
	unsigned int mask;
	unsigned int gateway;
	// unsigned int network;
	unsigned int broadcast;
	char ifname[26];
	unsigned char mac[6];
	unsigned char up;
	unsigned char mode;
	unsigned char dhcp_flag;
	unsigned char res[1];
} network_params_t;


extern int network_repair_route(const char *config);
extern unsigned int network_get_gateway(const char *ifname);
extern int network_modify(network_params_t *params, const char *file_path);
extern int network_getstaus(network_params_t *out_array, size_t array_size);
extern int network_getstaus_single(network_params_t *out, const char *ifname);


#ifdef __cplusplus
};
#endif

#endif	/* __DTH_NETWORK_H__ */