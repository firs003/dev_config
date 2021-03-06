#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <linux/route.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

#include "dth_config.h"
#include "dth_util.h"
#include "sleng_debug.h"


#define DTH_CONFIG_SERVER_SENDBUF_SIZE 4096
#define DTH_CONFIG_SERVER_RECVBUF_SIZE 4096

// static network_params_t default_net_params = {
// 	.ip        = 0xdf00a8c0,	//192.168.0.223
// 	.mask      = 0x00ffffff,	//255.255.255.0
// 	.gateway   = 0x0100a8c0,	//192.168.0.1
// 	.ifname    = {'e','t','h','0', 0,},
// 	.mac       = {0x30,0x0a,0x09,0x11,0xe0,0x40},
// 	.dhcp_flag = 0
// };

typedef struct static_file_desc
{
	unsigned char quit_flag;
	unsigned char debug_flag;
} STATIC_FD, *PSTATIC_FD;

STATIC_FD static_fd = {0};



static void print_net_params(network_params_t *param) {
	sleng_debug("[%s](%s):\t%08x\t%08x\t%08x\t%08x\n", param->ifname, (param->up)? "up": "down", param->ip, param->mask, param->gateway, param->broadcast);
}

static char *fgets_skip_comment(char *s, int size, FILE *stream) {
	char *ret;
	do {
		ret = fgets(s, size, stream);
	} while (ret && s[0]=='#');
	return ret;
}


/**************************************************
 * System or board layer
 **************************************************/
// #define NETWORK_PARAMS_FILE_PATH "/disthen/config/network.conf"
#define NETWORK_PARAMS_FILE_PATH	"/etc/network/interfaces"
#define NETWORK_PARAMS_BACKUP_PATH	"/disthen/config/network.back"
#define NETWORK_PARAMS_DEFAULT_PATH	"/disthen/config/network.conf"
#define CDHX_IF_AMOUNT	2
static const char *ifname_list[] = {
	"eth0",
	"eth1",
	"wlan0",
	"can0",
	"can1",
	"sit0",
	"tun0",
	"lo"
};

unsigned int get_gateway(const char *ifname) {
	FILE *fp;
	char buf[256]; // 128 is enough for linux
	char iface[16];
	unsigned int dest_addr, ret;
	fp = fopen("/proc/net/route", "r");
	if (fp == NULL)
		return -1;
	/* Skip title line */
	fgets(buf, sizeof(buf), fp);
	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "%s\t%08x\t%08x", iface, &dest_addr, &ret) == 3
			&& strncmp(ifname, iface, strlen(ifname)) == 0
			&& ret != 0) {
			break;
		}
	}

	fclose(fp);
	return ret;
}

static int load_params_from_file(const char *path, network_params_t *params_array, int array_size) {
	int ret = 0;
	FILE *fp = NULL;

	do {
		int i;
		char buf[1024] = {0, };

		if (!path || !params_array || array_size != CDHX_IF_AMOUNT) {
			ret = -1;
			errno = EINVAL;
			break;
		}

		if ((fp = fopen(path, "r")) == NULL) {
			sleng_error("fopen [%s] error", path);
			break;
		}

		/* Skip the fixed header 6 lines */
		for(i = 0; i < 6; i++) {
			fgets(buf, sizeof(buf), fp);
		}
		sleng_debug("path=%s\n", path);

		memset(params_array, 0, sizeof(network_params_t) * array_size);
		/* Get eth0 and eth1 config */
		for(i = 0; i < array_size; i++) {
			int eth_index;
			fgets_skip_comment(buf, sizeof(buf), fp);
			if (sscanf(buf, "auto eth%d", &eth_index) > 0) {
				char compare[128] = {0, };
				sprintf(params_array[i].ifname, "eth%d", eth_index);
				params_array[i].up = 1;
				fgets_skip_comment(buf, sizeof(buf), fp);
				// strncpy(compare, "iface eth0 inet ", strlen("iface eth0 inet "));
				strncpy(compare, "iface eth0 inet ", sizeof(compare));
				if (eth_index == 1) compare[strlen("iface eth")] = '1';
				if (strncmp(buf, compare, strlen(compare)) == 0) {
					const char *mode = buf + strlen(compare);
					if (strncmp(mode, "dhcp", strlen("dhcp")) == 0) {
						params_array[i].dhcp_flag = 1;
					} else if (strncmp(mode, "static", strlen("static")) == 0) {
						do {
							struct in_addr addr;
							fgets_skip_comment(buf, sizeof(buf), fp);
							if (strlen(buf) > 1 && buf[strlen(buf) - 1] == '\n') buf[strlen(buf) - 1] = '\0';
							memset(&addr, 0, sizeof(struct in_addr));
							// sleng_debug("buf[%hhx]=%s, len=%d, addr=%s\n", buf[0], buf, strlen(buf), buf + strlen("address "));
							if (strncmp(buf, "address ", strlen("address ")) == 0 && inet_aton(buf + strlen("address "), &addr)) {
								params_array[i].ip = addr.s_addr;
							} else if (strncmp(buf, "netmask ", strlen("netmask ")) == 0 && inet_aton(buf + strlen("netmask "), &addr)) {
								params_array[i].mask = addr.s_addr;
							} else if (strncmp(buf, "gateway ", strlen("gateway ")) == 0 && inet_aton(buf + strlen("gateway "), &addr)) {
								params_array[i].gateway = addr.s_addr;
							} else if (strncmp(buf, "broadcast ", strlen("broadcast ")) == 0 && inet_aton(buf + strlen("broadcast "), &addr)) {
								params_array[i].broadcast = addr.s_addr;
							}
						} while(buf[0] != '\n' && !feof(fp));
					}
				}
				ret++;
			}
		}

		for(i = 0; i < CDHX_IF_AMOUNT; i++) {
			if (params_array[i].dhcp_flag == 0 && params_array[i].broadcast == 0) params_array[i].broadcast = params_array[i].ip | 0xFF000000;
		}
	} while (0);

	if (fp) {
		fclose(fp);
		fp = NULL;
	}
	return ret;
}

static int save_params_to_file(const char *path, network_params_t *params_array, int array_size) {
	int ret = 0;
	FILE *fp = NULL;

	do {
		int i;
		char buf[1024];

		if (!path || !params_array || array_size != CDHX_IF_AMOUNT) {
			ret = -1;
			errno = EINVAL;
			break;
		}

		if ((fp = fopen(path, "w")) == NULL) {
			sleng_error("fopen [%s] error", path);
			break;
		}

		/* Write the fixed header 5 lines */
		sprintf(buf, "%s%s%s%s%s%s",
			"# interfaces(5) file used by ifup(8) and ifdown(8)\n",
			"# Include files from /etc/network/interfaces.d:\n",
			"source-directory /etc/network/interfaces.d\n",
			"auto lo\n",
			"iface lo inet loopback\n",
			"\n");
		if (fwrite(buf, 1, strlen(buf), fp) == -1) {
			sleng_error("fwrite fixed 6 lines header error");
			ret = -1;
			break;
		}

		for(i = 0; i < array_size; i++) {
			if (params_array[i].up) {
				sprintf(buf, "auto eth%d\n", i);
				if (fwrite(buf, 1, strlen(buf), fp) == -1) {
					sleng_error("fwrite enable(up) for if[%d] error", i);
					ret = -1;
					break;
				}

				if (params_array[i].dhcp_flag) {
					sprintf(buf, "iface eth%d inet dhcp\n", i);
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite dhcp for if[%d] error", i);
						ret = -1;
						break;
					}
				} else {
					struct in_addr addr;

					sprintf(buf, "iface eth%d inet static\n", i);
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite static for if[%d] error", i);
						ret = -1;
						break;
					}

					addr.s_addr = params_array[i].ip;
					sprintf(buf, "address %s\n", inet_ntoa(addr));
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite address for if[%d] error", i);
						ret = -1;
						break;
					}

					addr.s_addr = params_array[i].mask;
					sprintf(buf, "netmask %s\n", inet_ntoa(addr));
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite netmask for if[%d] error", i);
						ret = -1;
						break;
					}

					addr.s_addr = params_array[i].gateway;
					sprintf(buf, "gateway %s\n", inet_ntoa(addr));
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite gateway for if[%d] error", i);
						ret = -1;
						break;
					}

					addr.s_addr = params_array[i].broadcast;
					sprintf(buf, "broadcast %s\n", inet_ntoa(addr));
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite broadcast for if[%d] error", i);
						ret = -1;
						break;
					}

					sprintf(buf, "\n");
					if (fwrite(buf, 1, strlen(buf), fp) == -1) {
						sleng_error("fwrite \\n for if[%d] error", i);
						ret = -1;
						break;
					}
				}
			}
		}
	} while (0);

	if (fp) {
		fclose(fp);
		fp = NULL;
	}
	return ret;
}

static int check_param_valid(network_params_t *new, network_params_t *old_array, int array_size) {
	int ret = 1;
	if (new->dhcp_flag) {
		new->ip = new->mask = new->gateway = 0;
	} else {
		if ((new->ip & new->mask) != (new->gateway & new->mask)) {
			ret = 0;
		}
		if (((htonl(new->ip)&0xff000000) == 0) || ((htonl(new->ip)&0xff) == 0xff)) {
			ret = 0;
		} else if ((new->mask == 0) || (new->mask == 0xffffffff) || ((htonl(new->mask) & 0xff000000) == 0)
				   || ((htonl(new->mask) & 0xff0000) == 0) ){//|| ((htonl(new->mask)&0xff00) == 0)) { //linxj2011-06-01
			ret = 0;
		} else if (((htonl(new->gateway)  & 0xff000000) == 0) || ((htonl(new->gateway) & 0xff) == 0xff)) {
			ret = 0;
		} else if ((new->ip == new->mask) || (new->ip == new->gateway) || (new->mask == new->gateway)) {
			ret = 0;
		}
		if ((strncmp(new->ifname, old_array[0].ifname, sizeof(new->ifname)) == 0 && (new->ip & new->mask) != (old_array[1].ip & old_array[1].mask))
		 || (strncmp(new->ifname, old_array[1].ifname, sizeof(new->ifname)) == 0 && (new->ip & new->mask) != (old_array[0].ip & old_array[0].mask))) {
			ret = 0;
		}
	}

	return ret;
}

static int gen_netconf_file(const char *path, network_params_t *params) {
	int ret = 0;
	FILE *fp = NULL;

	do {
		int i;
		network_params_t paramv[CDHX_IF_AMOUNT];

		if (!path || !params) {
			ret = -1;
			errno = EINVAL;
			break;
		}

		for(i = 0; i < CDHX_IF_AMOUNT && strncmp(params->ifname, ifname_list[i], sizeof(params->ifname)); i++);
		if (i == CDHX_IF_AMOUNT) {
			ret = -1;
			errno = EINVAL;
			break;
		}

		/* Get params from system config file */
		if (load_params_from_file(path, paramv, CDHX_IF_AMOUNT) == -1) {
		// if (load_params_from_file(NETWORK_PARAMS_BACKUP_PATH, paramv, CDHX_IF_AMOUNT) == -1) {
			sleng_error("load_params_from_file[%s] error", path);
			ret = -1;
			break;
		}

		/* Change the specified param */
		for(i = 0; i < CDHX_IF_AMOUNT; i++) {
			print_net_params(paramv + i);
			if (strncmp(params->ifname, paramv[i].ifname, sizeof(paramv[i].ifname)) == 0) {
				if (check_param_valid(params, paramv, CDHX_IF_AMOUNT)) paramv[i] = *params;
			}
		}

		if (save_params_to_file(path, paramv, CDHX_IF_AMOUNT) == -1) {
		// if (save_params_to_file(NETWORK_PARAMS_DEFAULT_PATH, paramv, CDHX_IF_AMOUNT) == -1) {
			sleng_error("save_params_to_file[%s] error", path);
			ret = -1;
			break;
		}

	} while (0);

	if (fp) {
		fclose(fp);
		fp = NULL;
	}
	return ret;
}

static void signal_handler(int signo) {
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		signal(signo, SIG_DFL);
		static_fd.quit_flag = 1;
	default:
		signal(signo, SIG_DFL);
	}
}

#if 0
static int network_setmac(network_params_t *params) {
	struct ifreq ifr;
	int sockfd;

	memset(&ifr, 0, sizeof(struct ifreq));
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        sleng_error("socket");
		return -1;
	}

	//steven 09-27-09, set macAddr
	strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		sleng_error("get MAC err\n");
		close(sockfd);
		return -1;
	}

	strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, params->mac, IFHWADDRLEN);
	if (ioctl(sockfd, SIOCSIFHWADDR, &ifr) < 0) {
        sleng_error("set macaddr err");
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return 0;
}

static int network_load_params(network_params_t *params, const char *path) {
	int n, i, ret = 0;
	unsigned char temp = 0;
	FILE *fp = NULL;

	do {
		if ((fp = fopen(NETWORK_PARAMS_FILE_PATH, "rb")) == NULL) {
			sleng_debug("fopen netconf file for read error\n");
			// memcpy(params, &default_net_params, sizeof(network_params_t));
			ret = -1;
			break;
		}

		if ((n = fread(params, 1, sizeof(network_params_t), fp)) <= 0) {
			sleng_error("fread netconf file error");
			ret = -1;
			break;
		}
		if (n != sizeof(network_params_t)) {
			sleng_debug("net config file maybe destoryed, use default\n");
			ret = -1;
			break;
		}
		fclose(fp);

		if (params->dhcp_flag) {
			params->ip = params->mask = params->gateway = 0;
			ret = 0;
			return 0;
		}
		if ((params->ip&params->mask) != (params->gateway&params->mask)) {
			ret = -1;
			break;
		}
		if (((htonl(params->ip)&0xff000000) == 0) || ((htonl(params->ip)&0xff) == 0xff) || (htonl(params->ip) >= 0xe0000000)) {
			ret = -1;
			break;
		} else if ((params->mask == 0) || (params->mask == 0xffffffff) || ((htonl(params->mask)&0xff000000) == 0)
				   || ((htonl(params->mask)&0xff0000) == 0) ){//|| ((htonl(params->mask)&0xff00) == 0)) { //linxj2011-06-01
			ret = -1;
			break;
		} else if (((htonl(params->gateway)&0xff000000) == 0) || ((htonl(params->gateway)&0xff) == 0xff)) {
			ret = -1;
			break;
		} else if ((params->ip == params->mask) || (params->ip == params->gateway) || (params->mask == params->gateway)) {
			ret = -1;
			break;
		}
		for (i=0; i<6; i++)
			temp |= params->mac[i];
		if (temp == 0x0) {
			ret = -1;
			break;
		}
	}while (0);

	// if (ret == 1) {
	// 	// memcpy(params, &default_net_params, sizeof(network_params_t));
	// 	*params = default_net_params;
	// }

	if (fp) fclose(fp);
	return ret;
}
#endif

static int network_modify(network_params_t *params, const char *file_path) {
	int ret = 0;
	FILE *fp = NULL;
	struct ifreq ifr;
	struct rtentry rt;
	int sockfd;
	struct sockaddr_in sa = {
		sin_family:	PF_INET,
		sin_port:	0
	};

	do {
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
			sleng_error("socket");
			ret = -1;
			break;
		}

		memset(&ifr, 0, sizeof(struct ifreq));
		//steven 09-27-09, set macAddr
		strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
		sleng_debug("%s:%d ifr_name=%s\n", __FILE__, __LINE__, ifr.ifr_name);
		if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
			sleng_error("get MAC err");
			ret = -1;
			break;
		}
		// strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
		memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, params->mac, IFHWADDRLEN);
		// print_in_hex(ifr.ifr_ifru.ifru_hwaddr.sa_data, IFHWADDRLEN, "New Mac", NULL);
		if (ioctl(sockfd, SIOCSIFHWADDR, &ifr) < 0) {
			sleng_error("set macaddr err");
			ret = -1;
			break;
		}

		if (params->dhcp_flag) {
			char cmd[64] = {0, };
			params->ip = params->mask = params->gateway = 0;
			sleng_debug("\n\n\n------------------------------------net_cfg.dhcp_flag = %d\n", params->dhcp_flag);
			sprintf(cmd, "dhclient %s", params->ifname);
			if (system(cmd)) {
				sleng_debug("dhclient %s failed!\n", params->ifname);
				ret = -1;
				break;
			}
	//		if (-1 == net_getstatus(params)) {
	//			sleng_debug("[E]net_modify get net status error\n");
	//			return -1;
	//		}
			// if (-1 == network_setmac(params)) {
			// 	sleng_debug("[E]net_modify set mac error\n");
			// 	return -1;
			// }
			// sleng_debug("ipAddr=0x%x\n", params->ip);
			// sleng_debug("mask=0x%x\n", params->mask);
			// sleng_debug("mac=%02hhx %02hhx %02hhx %02hhx %02hhx %02hhx\n\n\n", params->mac[0], params->mac[1], params->mac[2], params->mac[3], params->mac[4], params->mac[5]);

			// return 0;
		} else {	/* Static IP */
			strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);

			//steven 09-27-09, set ipaddr
			sa.sin_addr.s_addr = params->ip;
			// strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
			memcpy((char *) &ifr.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
			if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
				sleng_error("set ipaddr err\n");
				ret = -1;
				break;
			}

			//steven 09-27-09, set mask
			sa.sin_addr.s_addr = params->mask;
			// strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
			memcpy((char *) &ifr.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
			if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
				sleng_error("set mask err");
				//return -1;    //sp 12-02-09 cut a bug
				ret = -1;
				break;
			}

			//steven 09-27-09, set gateway Addr
			// Clean out the RTREQ structure.
			memset((char *) &rt, 0, sizeof(struct rtentry));
			// Fill in the other fields.
			rt.rt_flags = (RTF_UP | RTF_GATEWAY);
			rt.rt_dst.sa_family = PF_INET;
			rt.rt_genmask.sa_family = PF_INET;
			sa.sin_addr.s_addr = params->gateway;
			memcpy((char *) &rt.rt_gateway, (char *) &sa, sizeof(struct sockaddr));
			// Tell the kernel to accept this route.
			if (ioctl(sockfd, SIOCADDRT, &rt) < 0 && errno != EEXIST) {
				sleng_error("set route err");
				//return -1;    //sp 12-02-09 cut a bug
				// ret = -1;
				// break;
			}
		}

		if (file_path) {
#if 0
			if ((fp = fopen(file_path, "wb")) == NULL) {
				sleng_error("fopen netconf file for write err");
				ret = -1;
				break;
			} else {
				if (fwrite(params, 1, sizeof(network_params_t), fp) <= 0) {
					sleng_error("fwrite netconf file err");
					ret = -1;
					break;
				}
			}
#else
			if (gen_netconf_file(file_path, params) == -1) {
				sleng_error("gen_netconf_file error");
				ret = -1;
				break;
			}
#endif
		}
	} while (0);

	if (sockfd > 0) close(sockfd);
	if (fp) fclose(fp);

	return ret;
}

#define DTH_CONFIG_SERVER_TMP_IFR_COUNT 32
static int get_if_num(void) {
	int sockfd, ret = 0;
	struct ifreq *ifr_array = NULL;
	struct ifconf ifc;
	do {
		ifr_array = calloc(DTH_CONFIG_SERVER_TMP_IFR_COUNT, sizeof(struct ifreq));
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			sleng_error("socket");
			ret = -1;
			break;
		}
		ifc.ifc_len = DTH_CONFIG_SERVER_TMP_IFR_COUNT * sizeof(struct ifreq);
		ifc.ifc_buf = (void *)ifr_array;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			sleng_error("set ipaddr err\n");
			ret = -1;
			break;
		}
		ret = ifc.ifc_len/sizeof(struct ifreq);
	} while (0);
	if(sockfd > 0) close(sockfd);
	if(ifr_array) free(ifr_array);

	return ret;
}

static int network_getstaus(void *buf, ssize_t bufsize) {
	int ret = 0;
	struct ifreq ifr;
	int sockfd;
	network_params_t *param = (network_params_t *)buf;
	struct sockaddr_in sa = {
		sin_family:	PF_INET,
		sin_port:	0
	};
	struct ifreq *ifr_array = NULL;
	struct ifconf ifc;

	do {
		int i;
		ifr_array = calloc(DTH_CONFIG_SERVER_TMP_IFR_COUNT, sizeof(struct ifreq));
		if(ifr_array == NULL) {
			sleng_error("calloc");
			ret = -1;
			break;
		}
		memset(&ifr, 0, sizeof(struct ifreq));
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			sleng_error("socket");
			ret = -1;
			break;
		}
		ifc.ifc_len = DTH_CONFIG_SERVER_TMP_IFR_COUNT * sizeof(struct ifreq);
		ifc.ifc_buf = (void *)ifr_array;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			sleng_error("set ipaddr err\n");
			ret = -1;
			break;
		}

		sleng_debug("%s[%d]:ifr_count=%d\n", __func__, __LINE__, ifc.ifc_len/sizeof(struct ifreq));
		for (i=0; i<ifc.ifc_len/sizeof(struct ifreq); i++, param++) {
			sleng_debug("%s[%d]:%d.ifname=%s\n", __func__, __LINE__, i, ifr_array[i].ifr_name);
			strncpy(param->ifname, ifr_array[i].ifr_name, IFNAMSIZ);
			//steven 09-27-09, set ipaddr
			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
				sleng_error("set ipaddr err\n");
				ret = -1;
				break;
			}
			memcpy((char *)&sa, (char *)&ifr.ifr_addr, sizeof(struct sockaddr));
			param->ip = sa.sin_addr.s_addr;

			//steven 09-27-09, get mask
			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
				sleng_error("get mask err");
				//ret = -1;
				//break;    //sp 12-02-09 cut a bug
			}
			memcpy((char *)&sa, (char *)&ifr.ifr_addr, sizeof(struct sockaddr));
			param->mask = sa.sin_addr.s_addr;

			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
				sleng_error("get MAC err\n");
				ret = -1;
				break;
			}
			memcpy(param->mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, IFHWADDRLEN);

			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
				sleng_error("get flags err\n");
				ret = -1;
				break;
			}
			param->up = ifr.ifr_flags & IFF_UP;

#if 0
			//how to get GATEWAY? ls, 2013-02-25
			//steven 09-27-09, set gateway Addr
			// Clean out the RTREQ structure.
			memset((char *) &rt, 0, sizeof(struct rtentry));
			// Fill in the other fields.
			rt.rt_flags = (RTF_UP | RTF_GATEWAY);
			rt.rt_dst.sa_family = PF_INET;
			rt.rt_genmask.sa_family = PF_INET;

			sa.sin_addr.s_addr = param->gateway;
			memcpy((char *) &rt.rt_gateway, (char *) &sa, sizeof(struct sockaddr));
			// Tell the kernel to accept this route.
			if (ioctl(sockfd, SIOCADDRT, &rt) < 0) {
				close(sockfd);
				sleng_error("set gateway err");
				//return -1;    //sp 12-02-09 cut a bug
			}
#else
			param->gateway = get_gateway(param->ifname);
			sleng_debug("param[%s]->gateway=%08x\n", param->ifname, param->gateway);
#endif
		}
	} while (0);

	if (sockfd > 0) close(sockfd);
	if (ifr_array) free(ifr_array);
	return ret;
}

static unsigned int _get_block_size(const char *path) {
	struct stat statbuf;
	memset(&statbuf, 0, sizeof(statbuf));
	return (stat(path, &statbuf) == -1)? -1: statbuf.st_blksize;
}

static int _cp(const char *src, const char *dst) {
	int ret = 0;
	unsigned int block_size = _get_block_size(src);
	void *buf = malloc(block_size);
	FILE *fp_src = fopen(src, "r");
	FILE *fp_dst = fopen(dst, "w");

	do {
		int readlen, writelen;
		if (buf == NULL) {
			sleng_error("malloc failure");
			ret = -1;
			break;
		}
		if (fp_src == NULL) {
			sleng_error("open src[%s] failure", src);
			ret = -1;
			break;
		}
		if (fp_dst == NULL) {
			sleng_error("open dst[%s] failure", dst);
			ret = -1;
			break;
		}

		while(!feof(fp_src)) {
			readlen = fread(buf, 1, block_size, fp_src);
			if (readlen < 0) {
				sleng_error("fread from src[%s] failure", src);
				ret = -1;
				break;
			}
			writelen = fwrite(buf, 1, readlen, fp_dst);
			if (writelen != readlen) {
				sleng_error("write to dst[%s] failure", dst);
				ret = -1;
				break;
			}
		}

		if (chmod(dst, 0755) == -1) {
			sleng_error("chmod +x for dst[%s] failure", dst);
			ret = -1;
			break;
		}
	} while (0);

	if (fp_dst) fclose(fp_dst);
	if (fp_src) fclose(fp_src);
	if (buf) free(buf);
	return ret;
}

static int _dth_config_tcp_listen_fd_setup(unsigned int ipaddr, unsigned short port, int maxch, struct timeval *timeout)
{
	int ret = 0;
	int listenfd = 0;
	int opt = 1;
	struct timeval tv = {5, 0};
	struct sockaddr_in servaddr;

	do
	{
		if (timeout)
		{
			tv = *timeout;
		}

		if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			sleng_error("socket");
			ret = -1;
			break;
		}

		if ( setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0 ) {
			sleng_error("setsockopt reuse");
			ret = -1;
			break;
		}
		if (setsockopt(listenfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval)) < 0) {
			sleng_error("setsockopt timeout");
			ret = -1;
			break;
		}

		bzero(&servaddr, sizeof(servaddr));
		memset(&servaddr, 0, sizeof(struct sockaddr_in));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = (ipaddr) ? ipaddr : htonl(INADDR_ANY);
		servaddr.sin_port = htons(port);
		if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
			sleng_error("bind");
			ret = -1;
			break;
		}

		if (listen(listenfd, maxch) < 0) {
			sleng_error("listen");
			ret = -1;
		}

		ret = listenfd;
	} while (0);

	if (ret == -1 && listenfd > 0)
	{
		close(listenfd);
		listenfd = -1;
	}
	return ret;
}	/* End of _dth_config_set_tcp_listen_fd() */


static ssize_t _dth_config_recv_msg(int prot, int sockfd, void *buf, size_t buf_size, int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t ret = 0;

	do
	{
		switch (prot)
		{
		case SOCK_DGRAM:
			ret = recvfrom(sockfd, buf, buf_size, flags, addr, addrlen);
			break;

		case SOCK_STREAM:
			ret = recv(sockfd, buf, buf_size, flags);
			break;

		default:
			break;
		}
	} while (0);

	return ret;
}	/* End of _dth_recv_msg() */

static ssize_t _dth_config_send_msg(int prot, int sockfd, void *buf, size_t buf_size, int flags, struct sockaddr *addr, socklen_t addrlen)
{
	ssize_t ret = 0;

	do
	{
		switch (prot)
		{
		case SOCK_DGRAM:
			ret = sendto(sockfd, buf, buf_size, flags, addr, addrlen);
			break;

		case SOCK_STREAM:
			ret = send(sockfd, buf, buf_size, flags);
			break;

		default:
			break;
		}
	} while (0);

	return ret;
}	/* End of _dth_send_msg() */

struct file_trans_args {
	pthread_mutex_t *mutex;
	upgrade_head_t *up_head;
	unsigned char *sendbuf;
	int send_sock;
	struct sockaddr_in remote_addr;
	int protocol;
	sem_t *sem_ready;
} file_trans_args_t;

#define DOWNLOAD_DIR "/disthen/download"
#define BACKUP_DIR "/disthen/backup"

static void *_file_trans_server(void *args) {
	PSTATIC_FD fd = &static_fd;
	struct file_trans_args *trans_args = (struct file_trans_args *)args;
	int ret = 0;
	// int process_flag = 0;
	dth_head_t *send_head = (dth_head_t *)trans_args->sendbuf;
	char x_flag = 0;
	unsigned long long trans_count = 0;
	// unsigned int file_size = get_file_size(trans_args->up_head->remote_path);
	const char *base_name = NULL;
	int i;
	struct timeval tv_begin, tv_end;
	unsigned long long tv_diff_usecs = 0;
	double speed_stat = 0.0;

	pthread_detach(pthread_self());

	do {
		send_head->sync[0] = 'd';
		send_head->sync[1] = 't';
		send_head->sync[2] = 'h';
		send_head->sync[3] = '\0';
		send_head->type    = DTH_ACK_FILE_TRANS;
		send_head->length  = 0;
		send_head->res[0]  = DTH_CONFIG_ACK_VALUE_OK;

		if (access(DOWNLOAD_DIR, F_OK)) {
			sleng_debug("make download dir[%s]...", DOWNLOAD_DIR);
			if (mkdir(DOWNLOAD_DIR, 0755)) {
				sleng_debug("failed! %s\n", strerror(errno));
				send_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
				break;
			}
			sleng_debug("OK!\n");
		}
		if (access(BACKUP_DIR, F_OK)) {
			sleng_debug("make backup dir[%s]...", BACKUP_DIR);
			if (mkdir(BACKUP_DIR, 0755)) {
				sleng_debug("failed! %s\n", strerror(errno));
				send_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
				break;
			}
			sleng_debug("OK!\n");
		}

#if 0
		/* Kill the running process */
		sprintf(cmd, "ps aux | grep %s | grep -v grep", basename(trans_args->up_head->local_path));
		ret = system(cmd);
		sleng_debug("Check the upgrade process, cmd=%s, ret=%d\n", cmd, ret);
		if (ret == 0) {	/* Upgrade process exist */
			sprintf(cmd, "busybox killall %s", basename(trans_args->up_head->local_path));
			ret = system(cmd);
			sleng_debug("Kill the upgrade process, cmd=%s, ret=%d\n", cmd, ret);
			process_flag = 1;
		}
#endif

		//backup orig file if nessery
		//exec prev cmd
		//file trans

		switch (trans_args->up_head->trans_mode) {
		case FILE_TRANS_MODE_R2L_NEGATIVE:
		{
			int listen_fd = -1;
			struct timeval recv_timeout = {5, 0};
			struct sockaddr_in address;
			// int val = 1;
			int client_fd = -1;
			socklen_t addr_len = sizeof(struct sockaddr_in);
			int recvlen = -1, writelen = -1, leftlen = 0;
			FILE *fp = NULL;
			unsigned char *recvbuf = NULL;
			int recvbuf_size = sizeof(dth_head_t) + DTH_CONFIG_SERVER_RECVBUF_SIZE;
			// int rcvbuf_resize = 8192;
			char back_path[128] = {0, };
			char tmp_path[128] = {0, };
			unsigned char local_md5[16] = {0, };
			struct in_addr addr;
			dth_head_t *recv_head = NULL;
			unsigned char *payload = NULL;

			do {
				if (trans_args->up_head->backup_flag)
				{
					sprintf(tmp_path, "%s/%s_tftp_%ld", DOWNLOAD_DIR, basename(trans_args->up_head->remote_path), pthread_self());
				}
				else
				{
					sprintf(tmp_path, "%s", trans_args->up_head->remote_path);
				}

				if (trans_args->up_head->trans_protocol == FILE_TRANS_PROTOCOL_USER) {
					recvbuf = (unsigned char *)malloc(recvbuf_size);
					if (recvbuf == NULL)
					{
						sleng_error("malloc for file recv buf failed");
						ret = -1;
						break;
					}

					// if((listen_fd = socket(AF_INET,SOCK_STREAM,0)) == -1){
					if((listen_fd = _dth_config_tcp_listen_fd_setup(0, DTH_CONFIG_FILE_TRANFER_TCP_PORT, 1, NULL)) == -1)
					{
						ret = -1;
						break;
					}

					send_head->res[0] = DTH_CONFIG_ACK_VALUE_READY;
					pthread_mutex_lock(trans_args->mutex);
					ret = _dth_config_send_msg(trans_args->protocol, trans_args->send_sock, trans_args->sendbuf, sizeof(dth_head_t) + send_head->length, 0, (struct sockaddr *)&trans_args->remote_addr, sizeof(struct sockaddr));
					if (ret < 0) {
						sleng_error("send file_trans ready ack failed");
					}
					pthread_mutex_unlock(trans_args->mutex);
					sem_post(trans_args->sem_ready);

					client_fd = accept(listen_fd, (struct sockaddr *)&address, &addr_len);
					if (client_fd < 0) {
						sleng_error("accept error");
						ret = -1;
						break;
					}

					if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&recv_timeout, sizeof(struct timeval)) < 0) {
						sleng_error("setsockopt timeout failed");
						ret = -1;
						break;
					}

					// if (setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, (const void *)&rcvbuf_resize, sizeof(rcvbuf_resize)) < 0) {
					// 	sleng_error("setsockopt recv_buff_size failed");
					// 	ret = -1;
					// 	break;
					// }

					fp = fopen(tmp_path, "w");
					if (fp == NULL)
					{
						sleng_error("open [%s] failed", tmp_path);
						ret = -1;
						break;
					}

					for (i = strlen(trans_args->up_head->remote_path); i > 0 && trans_args->up_head->remote_path[i] != '/'; i--)
						;
					base_name = trans_args->up_head->remote_path + i + 1;

					printf("%s: %3d%%", base_name, 0);
					fflush(stdout);
					gettimeofday(&tv_begin, NULL);

					recv_head = (dth_head_t *)recvbuf;
					payload = recvbuf + sizeof(dth_head_t);
					do {
						// recvlen = recv(client_fd, recvbuf, recvbuf_size, 0);
						// if (recvlen < sizeof(dth_head_t) || recv_head->length > recvlen - sizeof(dth_head_t))
						recvlen = recv(client_fd, recv_head, sizeof(dth_head_t), MSG_WAITALL);
						if (recvlen < sizeof(dth_head_t))
						{
							sleng_error("recv error, recvlen(%d) < sizeof(head)(%d)", recvlen, sizeof(dth_head_t));
							ret = -1;
							break;
						}

						if (recv_head->sync[0] != 'd' || recv_head->sync[1] != 't' || recv_head->sync[2] != 'h' || recv_head->sync[3] != '\0'
							|| (recv_head->type != DTH_FILE_PUT && recv_head->type != DTH_FILE_EOF))
						{
							sleng_error("sync(%c%c%c%c) mismatch or invalid type(%d)", recv_head->sync[0], recv_head->sync[1], recv_head->sync[2], recv_head->sync[3], recv_head->type);
							ret = -1;
							break;
						}

						if (recv_head->type == DTH_FILE_EOF)
						{
							break;
						}

						recvlen = recv(client_fd, payload, recv_head->length, MSG_WAITALL);
						if (recvlen < recv_head->length)
						{
							sleng_error("recv error, recvlen(%d) < recv_head->len(%u)", recvlen, recv_head->length);
							ret = -1;
							break;
						}

						writelen = fwrite(payload, 1, recv_head->length, fp);
						if (writelen < recv_head->length)
						{
							sleng_error("fwrite error, writelen(%d) != recv_head->length(%u)", writelen, recv_head->length);
							ret = -1;
							break;
						}
						// sleng_debug("recv_head->length=%u, writelen=%d, trans_count=%llu, file_size=%u\n", recv_head->length, writelen, trans_count, trans_args->up_head->file_size);
						trans_count += recv_head->length;
						// printf("\b\b\b\b%3llu%%", trans_count * 100 / trans_args->up_head->file_size);
						printf("\r%s: %3llu%%", base_name, trans_count * 100 / trans_args->up_head->file_size);
						fflush(stdout);

						leftlen = recvlen - sizeof(dth_head_t) - recv_head->length;
						if (leftlen == sizeof(dth_head_t)
							&& recvbuf[sizeof(dth_head_t) + recv_head->length + 0] == 'd'
							&& recvbuf[sizeof(dth_head_t) + recv_head->length + 1] == 't'
							&& recvbuf[sizeof(dth_head_t) + recv_head->length + 2] == 'h'
							&& recvbuf[sizeof(dth_head_t) + recv_head->length + 3] == '\0'
							&& recvbuf[sizeof(dth_head_t) + recv_head->length + 4] == DTH_FILE_EOF)
						{
							break;
						}

					} while(recvlen > 0);
#if 0
					// pthread_mutex_lock(trans_args->mutex);
					ret = send(client_fd, trans_args->sendbuf, sizeof(dth_head_t) + send_head->length, 0);
					sleng_debug("send return %d\n", ret);
					print_in_hex(trans_args->sendbuf, ret, "reply done ack", NULL);
					if (ret < 0)
					{
						sleng_error("send file_trans done ack failed");
					}
					// pthread_mutex_unlock(trans_args->mutex);
#endif
					gettimeofday(&tv_end, NULL);
					tv_diff_usecs = TIMEVAL_DIFF_USEC(&tv_end, &tv_begin);
					speed_stat = trans_count * 1000000 / tv_diff_usecs;
					if (speed_stat >= 1000000)
					{
						printf("  %llu  %.1f MB/s\n", trans_count, speed_stat / 1000000);
					} else if (speed_stat >= 1000 && speed_stat < 1000000)
					{
						printf("  %llu  %.0f KB/s\n", trans_count, speed_stat / 1000);
					} else if (speed_stat >= 0 && speed_stat < 1000)
					{
						printf("  %llu  %.0f B/s\n", trans_count, speed_stat);
					}
					fclose(fp);
					fp = NULL;
				}
				else if (trans_args->up_head->trans_protocol == FILE_TRANS_PROTOCOL_TFTP)
				{
					char cmd[512] = {0,};

					memset(&addr, 0, sizeof(struct in_addr));
					addr.s_addr = trans_args->up_head->remote_ip;
					//TODO, is FTP cmd like the format of TFTP cmd?
					if (trans_args->up_head->trans_protocol == FILE_TRANS_PROTOCOL_TFTP) {
						sprintf(cmd, "%s -l %s -r %s -g %s",
							"busybox tftp",
							tmp_path,
							trans_args->up_head->remote_path,
							inet_ntoa(addr));
					} else {
						send_head->res[0] = DTH_CONFIG_ACK_VALUE_NOT_SUPPORT;
						break;
					}
					ret = system(cmd);
					sleng_debug("Tftp for [%s], cmd=%s, ret=%d\n", trans_args->up_head->remote_path, cmd, ret);
					if(ret) {
						send_head->res[0] = DTH_CONFIG_ACK_VALUE_POSITIVE_DOWNLOAD_FIALED;
						break;
					}
				}

				//exec post cmd
				/* Filesize Check */
				if (get_file_size(tmp_path) != trans_args->up_head->file_size)
				{
					sleng_error("File size check error, local_file(%s:%u) != param(%u)", tmp_path, get_file_size(tmp_path), trans_args->up_head->file_size);
					send_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
					break;
				}
				sleng_debug("File size check success, local_file(%u) == param(%u)\n", get_file_size(tmp_path), trans_args->up_head->file_size);

				/* MD5 Check */
				memset(local_md5, 0, sizeof(local_md5));
				// sleng_debug("memcmp md5 return %d\n", memcmp(trans_args->up_head->md5, local_md5, sizeof(trans_args->up_head->md5)));
				if (memcmp(trans_args->up_head->md5, local_md5, sizeof(trans_args->up_head->md5))) {	//trans_md5 is not all 0x00;
					int i;
					get_md5sum(tmp_path, local_md5, sizeof(local_md5));
#if 0
					char tmp[3] = {0, };
					char buf[128] = {0, };

					FILE *fp = NULL;
					memset(cmd, 0, sizeof(cmd));
					sprintf(cmd, "md5sum %s", tmp_path);
					do {
						fp = popen(cmd, "r");
						if (fp == NULL) {
							sleng_error("popen md5sum failed");
							send_head->res[0] = DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED;
							break;
						}
						fread(buf, 1, sizeof(buf), fp);
						sleng_debug("buf=%s\n", buf);
					} while (0);
					if (fp) pclose(fp);

					for (i = 0; i < 32; i += 2) {
						tmp[0] = buf[i];
						tmp[1] = buf[i+1];
						tmp[2] = '\0';
						local_md5[i/2] = atox(tmp);
						// sleng_debug("tmp=%s, local_md5[%d]=%02hhx\n", tmp, i/2, local_md5[i/2]);
					}
					if (buf[i] != ' ') {
						sleng_debug("local md5sum format error\n");
						send_head->res[0] = DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED;
						break;
					}
#endif
					if (fd->debug_flag) {
						sleng_debug("local_md5 =");
						for (i=0; i<sizeof(local_md5); i++) printf("%02hhx", local_md5[i]);
						printf("\n");
						sleng_debug("remote_md5=");
						for (i=0; i<sizeof(trans_args->up_head->md5); i++) printf("%02hhx", trans_args->up_head->md5[i]);
						printf("\n");
					}
					if (memcmp(trans_args->up_head->md5, local_md5, sizeof(trans_args->up_head->md5)) == 0) {
						sleng_debug("md5 check success!\n");
					} else {
						sleng_debug("md5 check failed!\n");
						send_head->res[0] = DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED;
						break;
					}
				}

				/* Backup old file */
				if (trans_args->up_head->backup_flag) {
					sprintf(back_path, "%s/%s", BACKUP_DIR, basename(trans_args->up_head->remote_path));
					if (access(back_path, F_OK) == 0)
					{
						unlink(back_path);
					}
					if (access(trans_args->up_head->remote_path, F_OK) == 0)
					{
						if (_cp(trans_args->up_head->remote_path, back_path)) {
							sleng_error("cp1, %s -> %s", trans_args->up_head->remote_path, back_path);
							// send_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
							// break;
						}
						x_flag = !access(trans_args->up_head->remote_path, X_OK);
						sleng_debug("[%s@%d]:x_flag = %hhd\n", __func__, __LINE__, x_flag);
						unlink(trans_args->up_head->remote_path);
					}

					/* Copy the new file */
					if (_cp(tmp_path, trans_args->up_head->remote_path)) {
						sleng_error("cp2, %s -> %s", tmp_path, trans_args->up_head->remote_path);
						send_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
						break;
					}
					if (x_flag) chmod(trans_args->up_head->remote_path, 0755);
					if (unlink(tmp_path)) {
						sleng_error("unlink");
						send_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
						break;
					}
				}

				/* Resume the upgraded process */
				/* TODO, with params */
#if 0
				if (process_flag) {
					sprintf(cmd, "%s%s &", (trans_args->up_head->remote_path[0] != '/')? "./": "", trans_args->up_head->remote_path);
					system(cmd);
					sleng_debug("Resume the upgraded process[%s], cmd=%s, ret=%d\n", trans_args->up_head->remote_path, cmd, ret);
				}
#endif
				send_head->res[0] = DTH_CONFIG_ACK_VALUE_OK;
			} while(0);

#if 1
			pthread_mutex_lock(trans_args->mutex);
			ret = send(client_fd, trans_args->sendbuf, sizeof(dth_head_t) + send_head->length, 0);
			// print_in_hex(trans_args->sendbuf, ret, "reply done ack", NULL);
			if (ret < 0)
			{
				sleng_error("send file_trans done ack failed");
			}
			pthread_mutex_unlock(trans_args->mutex);
#endif
			if (fp)
			{
				fclose(fp);
				fp = NULL;
			}
			if (client_fd)
			{
				close(client_fd);
				client_fd = -1;
			}
			if (listen_fd > 0)
			{
				close(listen_fd);
				listen_fd = -1;
			}
			if (recvbuf)
			{
				free(recvbuf);
				recvbuf = NULL;
			}

			break;
		}

		case FILE_TRANS_MODE_L2R_NEGATIVE:
		{
			int listen_fd = -1;
			struct timeval send_timeout = {5, 0};
			struct sockaddr_in address;
			int val = 1;
			int client_fd = -1;
			socklen_t addr_len = sizeof(struct sockaddr_in);
			int sendlen = -1, readlen = -1;
			FILE *fp = NULL;
			unsigned char *sendbuf = NULL;
			// int rcvbuf_resize = 8192;

			do {
				if (trans_args->up_head->trans_protocol == FILE_TRANS_PROTOCOL_USER) {
					sendbuf = (unsigned char *)malloc(DTH_CONFIG_SERVER_SENDBUF_SIZE);
					if (sendbuf == NULL)
					{
						sleng_error("malloc for file send buf failed");
						ret = -1;
						break;
					}

					if((listen_fd = socket(AF_INET,SOCK_STREAM,0)) == -1){
						ret = -1;
						break;
					}

					memset(&address, 0, sizeof(struct sockaddr_in));
					address.sin_family = AF_INET;
					address.sin_addr.s_addr = htonl(INADDR_ANY);
					address.sin_port = htons(DTH_CONFIG_FILE_TRANFER_TCP_PORT);

					if (setsockopt(listen_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&send_timeout, sizeof(struct timeval)) < 0) {
						sleng_error("setsockopt timeout failed");
						ret = -1;
						break;
					}

					if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0 ) {
						sleng_error("set setsockopt failed");
						ret = -1;
						break;
					}

					if (-1 == bind(listen_fd, (struct sockaddr *)&address, sizeof(address))) {
						sleng_error("bind failed");
						ret = -1;
						break;
					}

					if (listen(listen_fd, 1) < 0) {
						sleng_error("listen failed");
						ret = -1;
						break;
					}

					send_head->res[0] = DTH_CONFIG_ACK_VALUE_READY;
					pthread_mutex_lock(trans_args->mutex);
					ret = _dth_config_send_msg(trans_args->protocol, trans_args->send_sock, trans_args->sendbuf, sizeof(dth_head_t) + send_head->length, 0, (struct sockaddr *)&trans_args->remote_addr, sizeof(struct sockaddr));
					if (ret < 0) {
						sleng_error("sendto self_report ack failed");
					}
					pthread_mutex_unlock(trans_args->mutex);

					client_fd = accept(listen_fd, (struct sockaddr *)&address, &addr_len);
					if (client_fd < 0) {
						sleng_error("accept error");
						ret = -1;
						break;
					}

					if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&send_timeout, sizeof(struct timeval)) < 0) {
						sleng_error("setsockopt timeout failed");
						ret = -1;
						break;
					}

					// if (setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, (const void *)&rcvbuf_resize, sizeof(rcvbuf_resize)) < 0) {
					// 	sleng_error("setsockopt send_buff_size failed");
					// 	ret = -1;
					// 	break;
					// }

					fp = fopen(trans_args->up_head->remote_path, "r");
					if (fp == NULL)
					{
						sleng_error("open [%s] failed", trans_args->up_head->remote_path);
						ret = -1;
						break;
					}

					for (i = strlen(trans_args->up_head->remote_path); i > 0 && trans_args->up_head->remote_path[i] != '/'; i--)
						;
					base_name = trans_args->up_head->remote_path + i + 1;

					printf("%s: %3d%%", base_name, 0);
					fflush(stdout);
					gettimeofday(&tv_begin, NULL);

					while (!feof(fp))
					{
						readlen = fread(sendbuf, 1, DTH_CONFIG_SERVER_SENDBUF_SIZE, fp);
						if (readlen == -1)
						{
							sleng_error("fread from send file[%s] error", trans_args->up_head->remote_path);
							ret = -1;
							break;
						}
						sendlen = send(client_fd, sendbuf, readlen, 0);
						if (sendlen < readlen)
						{
							sleng_error("send error, sendlen(%d) != readlen(%d)", sendlen, readlen);
							ret = -1;
							break;
						}
						// sleng_debug("sendlen=%d, read_len=%d\n", sendlen, readlen);
						trans_count += sendlen;
						// sleng_debug("sendlen=%d, read_len=%d, trans_count=%d(%d), file_size=%u\n", sendlen, readlen, trans_count, trans_count * 100, file_size);
						printf("\r%s: %3llu%%", base_name, trans_count * 100 / trans_args->up_head->file_size);
						fflush(stdout);
					}
					gettimeofday(&tv_end, NULL);
					tv_diff_usecs = TIMEVAL_DIFF_USEC(&tv_end, &tv_begin);
					speed_stat = trans_count * 1000000 / tv_diff_usecs;
					if (speed_stat >= 1000000)
					{
						printf("  %llu  %.1f MB/s\n", trans_count, speed_stat / 1000000);
					} else if (speed_stat >= 1000 && speed_stat < 1000000)
					{
						printf("  %llu  %.0f KB/s\n", trans_count, speed_stat / 1000);
					} else if (speed_stat >= 0 && speed_stat < 1000)
					{
						printf("  %llu  %.0f B/s\n", trans_count, speed_stat);
					}
				}
			} while(0);

			if (fp)
			{
				fclose(fp);
				fp = NULL;
			}
			if (client_fd)
			{
				close(client_fd);
				client_fd = -1;
			}
			if (listen_fd > 0)
			{
				close(listen_fd);
				listen_fd = -1;
			}
			if (sendbuf)
			{
				free(sendbuf);
				sendbuf = NULL;
			}

			break;
		}

		case FILE_TRANS_MODE_R2L_POSITIVE:
		{
			break;
		}

		case FILE_TRANS_MODE_L2R_POSITIVE:
		{
			break;
		}

		default :
			send_head->res[0] = DTH_CONFIG_ACK_VALUE_NOT_SUPPORT;
			break;
		}

	} while (0);

	//send back file trans result
	// pthread_mutex_lock(trans_args->mutex);
	// ret = _dth_config_send_msg(trans_args->protocol, trans_args->send_sock, trans_args->sendbuf, sizeof(dth_head_t) + send_head->length, 0, (struct sockaddr *)&trans_args->remote_addr, sizeof(struct sockaddr));
	// if (ret < 0) {
	// 	sleng_error("send done ack failed");
	// }
	// pthread_mutex_unlock(trans_args->mutex);
	// sleng_debug("Upgrade [%s] %s!\n", trans_args->up_head->local_path, (send_head->res[0] == DTH_CONFIG_ACK_VALUE_OK)? "Success": "Failure");

	return (void *)ret;
}

static int _dth_config_do_request(int prot, int sockfd, const unsigned char *recvbuf, int recvlen, pthread_mutex_t *send_mutex, struct sockaddr_in *remote_addr, socklen_t remote_addr_len)
{
	PSTATIC_FD fd = &static_fd;
	int ret = 0;
	unsigned char sendbuf[DTH_CONFIG_SERVER_SENDBUF_SIZE] = {0, };
	pthread_t file_trans_tid;
	struct file_trans_args trans_args;

	do
	{
		if (recvlen >= 0 && recvlen >= sizeof(dth_head_t))
		{
			dth_head_t *dth_head = (dth_head_t *)recvbuf;
			if (fd->debug_flag)
				sleng_debug("recv from [ip=%08x, port=%hu]\n", (unsigned int)remote_addr->sin_addr.s_addr, ntohs(remote_addr->sin_port));
			if (dth_head->sync[0] != 'd' || dth_head->sync[1] != 't' || dth_head->sync[2] != 'h' || dth_head->sync[3] != '\0')
			{
				// if(fd->debug_flag) sleng_debug("bad sync, just drop! dth ... ... ... ...\n");
				continue;
			}
			// if (dth_head->length > DTH_CONFIG_SERVER_RECVBUF_SIZE - sizeof(dth_head_t));	//TODO
			switch (dth_head->type)
			{
			case DTH_REQ_RESTART:
			{
				dth_head = (dth_head_t *)sendbuf;
				dth_head->sync[0] = 'd';
				dth_head->sync[1] = 't';
				dth_head->sync[2] = 'h';
				dth_head->sync[3] = '\0';
				dth_head->type = DTH_ACK_RESTART;
				dth_head->length = 0;
				sleng_debug("Restart Service");
				dth_head->res[0] = system("service dmservice restart");
				pthread_mutex_lock(send_mutex);
				ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
				if (ret < 0)
				{
					sleng_error("sendto self_report ack failed");
				}
				pthread_mutex_unlock(send_mutex);
				break;
			}

			case DTH_REQ_REBOOT:
			{
				dth_head = (dth_head_t *)sendbuf;
				dth_head->sync[0] = 'd';
				dth_head->sync[1] = 't';
				dth_head->sync[2] = 'h';
				dth_head->sync[3] = '\0';
				dth_head->type = DTH_ACK_REBOOT;
				dth_head->length = 0;
				// dth_head->res[0] = DTH_CONFIG_ACK_VALUE_OK;
				pthread_mutex_lock(send_mutex);
				ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
				if (ret < 0)
				{
					sleng_error("sendto self_report ack failed");
				}
				pthread_mutex_unlock(send_mutex);
				sleng_debug("Rebooting");
				system("reboot");
				break;
			}

			case DTH_REQ_POWEROFF:
			{
				dth_head = (dth_head_t *)sendbuf;
				dth_head->sync[0] = 'd';
				dth_head->sync[1] = 't';
				dth_head->sync[2] = 'h';
				dth_head->sync[3] = '\0';
				dth_head->type = DTH_ACK_POWEROFF;
				dth_head->length = 0;
				// dth_head->res[0] = DTH_CONFIG_ACK_VALUE_OK;
				pthread_mutex_lock(send_mutex);
				ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
				if (ret < 0)
				{
					sleng_error("sendto self_report ack failed");
				}
				pthread_mutex_unlock(send_mutex);
				sleng_debug("Poweroff");
				system("poweroff");
				break;
			}

			case DTH_REQ_REPORT_SELF:
			{
				if (prot == SOCK_DGRAM)
				{
					struct sockaddr_in bcst_addr;
					int sockopt = 0;
					int bcst_sockfd = -1, if_num = get_if_num();
					do
					{
						if ((bcst_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
						{
							sleng_error("refresh socket");
							break;
						}
						sockopt = 1;
						if (setsockopt(bcst_sockfd, SOL_SOCKET, SO_BROADCAST, (char *)&sockopt, sizeof(sockopt)))
						{
							sleng_error("set setsockopt failed");
							break;
						}
						memset(sendbuf, 0, sizeof(sendbuf)); //Clean the sendbuf in order to make sure client can parse to string in python
						dth_head = (dth_head_t *)sendbuf;
						dth_head->sync[0] = 'd';
						dth_head->sync[1] = 't';
						dth_head->sync[2] = 'h';
						dth_head->sync[3] = '\0';
						dth_head->type = DTH_ACK_REPORT_SELF;
						dth_head->length = sizeof(network_params_t) * if_num;
						if (fd->debug_flag)
							sleng_debug("length=%d(%dx%d), sendbuf[8]=%02hhx\n", dth_head->length, sizeof(network_params_t), if_num, sendbuf[8]);
						if (fd->debug_flag)
							print_in_hex(sendbuf, sizeof(dth_head_t), "0.sendbuf=", NULL);
						if (network_getstaus(sendbuf + sizeof(dth_head_t), DTH_CONFIG_SERVER_SENDBUF_SIZE - sizeof(dth_head_t)) < 0)
						{
							sleng_error("Get working if status failed");
							break;
						}
						if (fd->debug_flag)
							print_in_hex(sendbuf, sizeof(dth_head_t), "1.sendbuf0=", NULL);

						memset(&bcst_addr, 0, sizeof(struct sockaddr_in));
						bcst_addr.sin_family = AF_INET;
						bcst_addr.sin_addr.s_addr = INADDR_BROADCAST;
						bcst_addr.sin_port = htons(DTH_CONFIG_REMOTE_DEFAULT_UDP_PORT);
						pthread_mutex_lock(send_mutex);
						if (fd->debug_flag)
							print_in_hex(sendbuf, sizeof(dth_head_t) + dth_head->length, "sendbuf=", NULL);
						ret = sendto(bcst_sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)&bcst_addr, sizeof(struct sockaddr));
						if (ret < 0)
						{
							sleng_error("sendto self_report ack failed");
							pthread_mutex_unlock(send_mutex);
							break;
						}
						pthread_mutex_unlock(send_mutex);
						sleng_debug("sendto return %d\n", ret);
					} while (0);
					if (bcst_sockfd > 0)
						close(bcst_sockfd);
				}
				else if (prot == SOCK_STREAM)
				{
					int if_num = get_if_num();
					memset(sendbuf, 0, sizeof(sendbuf)); //Clean the sendbuf in order to make sure client can parse to string in python
					dth_head = (dth_head_t *)sendbuf;
					dth_head->sync[0] = 'd';
					dth_head->sync[1] = 't';
					dth_head->sync[2] = 'h';
					dth_head->sync[3] = '\0';
					dth_head->type = DTH_ACK_REPORT_SELF;
					dth_head->length = sizeof(network_params_t) * if_num;
					if (fd->debug_flag)
						sleng_debug("length=%d(%dx%d), sendbuf[8]=%02hhx\n", dth_head->length, sizeof(network_params_t), if_num, sendbuf[8]);
					if (fd->debug_flag)
						print_in_hex(sendbuf, sizeof(dth_head_t), "0.sendbuf=", NULL);
					if (network_getstaus(sendbuf + sizeof(dth_head_t), DTH_CONFIG_SERVER_SENDBUF_SIZE - sizeof(dth_head_t)) < 0)
					{
						sleng_error("Get working if status failed");
						break;
					}
					if (fd->debug_flag)
						print_in_hex(sendbuf, sizeof(dth_head_t), "1.sendbuf0=", NULL);

					pthread_mutex_lock(send_mutex);
					ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
					if (ret < 0)
					{
						sleng_error("sendto self_report ack failed");
					}
					pthread_mutex_unlock(send_mutex);
				}

				break;
			}

			case DTH_REQ_FILE_TRANS:
			{
				sem_t sem_ready;
				if (sem_init(&sem_ready, 0, 0) == -1)
				{
					sleng_error("sem_init for sem_ready error");;
					ret = -1;
					break;
				}

				// sleng_debug("length=%u, sizeof(upgrade_head_t)=%d, payload_head=%s\n", dth_head->length, sizeof(upgrade_head_t), &recvbuf[sizeof(dth_head_t)]);
				if (dth_head->length == sizeof(upgrade_head_t) && recvbuf[sizeof(dth_head_t) + 0] == 'd' && recvbuf[sizeof(dth_head_t) + 1] == 'u' && recvbuf[sizeof(dth_head_t) + 2] == 'f' && recvbuf[sizeof(dth_head_t) + 3] == '\0')
				{
					trans_args.mutex       = send_mutex;
					trans_args.up_head     = (upgrade_head_t *)(recvbuf + sizeof(dth_head_t));
					trans_args.sendbuf     = sendbuf;
					trans_args.send_sock   = sockfd;
					trans_args.remote_addr = *remote_addr;
					trans_args.protocol    = prot;
					trans_args.sem_ready   = &sem_ready;
					if (pthread_create(&file_trans_tid, NULL, _file_trans_server, &trans_args) < 0)
					{
						sleng_error("create file_trans_thread failed");
						dth_head = (dth_head_t *)sendbuf;
						dth_head->sync[0] = 'd';
						dth_head->sync[1] = 't';
						dth_head->sync[2] = 'h';
						dth_head->sync[3] = '\0';
						dth_head->type = DTH_ACK_FILE_TRANS;
						dth_head->length = 0;
						dth_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_THREAD_FAILED;
						pthread_mutex_lock(send_mutex);
						ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
						if (ret < 0)
						{
							sleng_error("sendto self_report ack failed");
						}
						pthread_mutex_unlock(send_mutex);
					}
					sem_wait(&sem_ready);
#if 0
					memset(sendbuf, 0, sizeof(sendbuf)); //Clean the sendbuf in order to make sure client can parse to string in python
					dth_head = (dth_head_t *)sendbuf;
					dth_head->sync[0] = 'd';
					dth_head->sync[1] = 't';
					dth_head->sync[2] = 'h';
					dth_head->sync[3] = '\0';
					dth_head->type    = DTH_ACK_FILE_TRANS;
					dth_head->res[0]  = DTH_CONFIG_ACK_VALUE_FILE_TRANS_STARTED;
					pthread_mutex_lock(send_mutex);
					ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t), 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
					if (ret < 0)
					{
						sleng_error("sendto self_report ack failed");
					}
					pthread_mutex_unlock(send_mutex);
#endif
				}
				break;
			}

			case DTH_REQ_SET_NETWORK_PARAMS:
			{
				if (dth_head->length == sizeof(network_params_t))
				{
					network_params_t *params = (network_params_t *)(recvbuf + sizeof(dth_head_t));
					dth_head = (dth_head_t *)sendbuf;
					dth_head->sync[0] = 'd';
					dth_head->sync[1] = 't';
					dth_head->sync[2] = 'h';
					dth_head->sync[3] = '\0';
					dth_head->type = DTH_ACK_SET_NETWORK_PARAMS;
					dth_head->length = 0;
					dth_head->res[0] = DTH_CONFIG_ACK_VALUE_OK;
					print_in_hex(recvbuf, sizeof(dth_head_t) + sizeof(network_params_t), NULL, NULL);
					if (network_modify(params, NETWORK_PARAMS_FILE_PATH))
					{
						dth_head->res[0] = DTH_CONFIG_ACK_VALUE_ERR;
					}
					pthread_mutex_lock(send_mutex);
					ret = _dth_config_send_msg(prot, sockfd, sendbuf, sizeof(dth_head_t) + dth_head->length, 0, (struct sockaddr *)remote_addr, sizeof(struct sockaddr));
					if (ret < 0)
					{
						sleng_error("sendto self_report ack failed");
					}
					pthread_mutex_unlock(send_mutex);
				}
				break;
			}

			default:
				if (fd->debug_flag) sleng_debug("Invalid type [%d]\n", dth_head->type);
			}
		}
	} while (0);

	return ret;
}	/* End of _do_request() */


typedef struct thread_arg
{
	unsigned int ipaddr;
	unsigned short port;
} THREAD_ARG_S, *PTHREAD_ARG_S;
#define THREAD_ARG_S_LEN sizeof(THREAD_ARG_S)

static void *_dth_config_udp_body(void *arg)
{
	PSTATIC_FD fd = &static_fd;
	void *rc = THREAD_SUCCESS;
	PTHREAD_ARG_S args = (PTHREAD_ARG_S)arg;
	// int ret = 0;
	// network_params_t netparams;
	unsigned int ipaddr = (args && args->ipaddr > 0) ? args->ipaddr : 0;
	unsigned short port = (args && args->port > 0) ? args->port : DTH_CONFIG_BOARD_DEFAULT_UDP_PORT;
	int ucst_sockfd = -1, sockopt;
	struct sockaddr_in local_addr, remote_addr;
	socklen_t remote_addr_len = sizeof(struct sockaddr);
	struct timeval tv = {2, 0};

	unsigned char recvbuf[DTH_CONFIG_SERVER_RECVBUF_SIZE];
	pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;


	do
	{
		ucst_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (-1 == ucst_sockfd)
		{
			sleng_error("socket error");
			rc = THREAD_FAILURE;
			break;
		}

		sockopt = 1;
		// sleng_debug("%s:%d\n", __FILE__, __LINE__);
		if (setsockopt(ucst_sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
		{
			sleng_error("set setsockopt failed");
			rc = THREAD_FAILURE;
			break;
		}
		if (setsockopt(ucst_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)	//2s timeout
		{
			sleng_error("setsockopt timeout");
			rc = THREAD_FAILURE;
			break;
		}

		// sleng_debug("%s:%d\n", __FILE__, __LINE__);
		memset(&local_addr, 0, sizeof(struct sockaddr_in));
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = (ipaddr) ? ipaddr : htonl(INADDR_ANY);
		local_addr.sin_port = htons(port);
		if (bind(ucst_sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1)
		{
			sleng_error("unicast socket bind");
			rc = THREAD_FAILURE;
			break;
		}

		// sleng_debug("%s:%d\n", __func__, __LINE__);
		while (!fd->quit_flag)
		{
			int recvlen;

			recvbuf[0] = recvbuf[1] = recvbuf[2] = recvbuf[3] = 0; //make sure do NOT use the prev value
			// recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_SERVER_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
			recvlen = _dth_config_recv_msg(SOCK_DGRAM, ucst_sockfd, recvbuf, DTH_CONFIG_SERVER_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
			if (fd->debug_flag && recvlen >= 0)
			{
				sleng_debug("recvlen=%d, sizeof(dth_head_t)=%d, buf=\n", recvlen, sizeof(dth_head_t));
				// if (recvlen >= 0) {
				print_in_hex(recvbuf, recvlen, NULL, NULL);
				// }
			}

			if (recvlen > 0) {
				if (recvbuf[0] != 'd' || recvbuf[1] != 't' || recvbuf[2] != 'h' || recvbuf[3] != '\0') {
					sleng_error("bad message, just drop!\n");
					continue;
				}

				if (fd->debug_flag)
				{
					sleng_debug("recvlen=%d, sizeof(dth_head_t)=%d, buf=\n", recvlen, sizeof(dth_head_t));
					print_in_hex(recvbuf, recvlen, NULL, NULL);
				}

				_dth_config_do_request(SOCK_DGRAM, ucst_sockfd, recvbuf, recvlen, &send_mutex, &remote_addr, remote_addr_len);
			}
		}
	} while (0);

	sleng_debug("Stop udp thread...\n");
	if (ucst_sockfd > 0)
		close(ucst_sockfd);
	pthread_mutex_destroy(&send_mutex);
	return rc;
} /* End of _udp_body() */

static void *_dth_config_tcp_body(void *arg)
{
	PSTATIC_FD fd = &static_fd;
	void *rc = THREAD_SUCCESS;
	PTHREAD_ARG_S args = (PTHREAD_ARG_S)arg;
	unsigned int ipaddr = (args && args->ipaddr > 0) ? args->ipaddr : 0;
	unsigned short port = (args && args->port > 0) ? args->port : DTH_CONFIG_BOARD_DEFAULT_TCP_PORT;
	unsigned char recvbuf[DTH_CONFIG_SERVER_RECVBUF_SIZE];
	pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
	int connfd = -1, listenfd = -1;
	struct sockaddr_in cliaddr;
	socklen_t cliaddr_len = sizeof(struct sockaddr_in);

	do
	{
		/* Listen fd setup */
		// if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		if ((listenfd = _dth_config_tcp_listen_fd_setup(ipaddr, port, 10, NULL)) == -1) {
			sleng_error("setup listen fd error");
			rc = THREAD_FAILURE;
			break;
		}

		while (!fd->quit_flag)
		{
			int recvlen;

			recvbuf[0] = recvbuf[1] = recvbuf[2] = recvbuf[3] = 0; //make sure do NOT use the prev value
			if (connfd != -1)
			{
				close(connfd);
				connfd = -1;
			}
			memset(&cliaddr, 0, sizeof(cliaddr));
			cliaddr_len = sizeof(cliaddr);
			connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len);
			if (connfd == 0 || (connfd == -1 && errno == EAGAIN))
			{
				// sleng_debug("accept timeout\n");
				continue;
			}

			if (connfd == -1 && errno != EAGAIN)
			{
				sleng_error("accept error");
				rc = THREAD_FAILURE;
				break;
			}

			recvlen = _dth_config_recv_msg(SOCK_STREAM, connfd, recvbuf, DTH_CONFIG_SERVER_RECVBUF_SIZE, 0, NULL, NULL);
			if (recvlen > 0) {
				if (recvbuf[0] != 'd' || recvbuf[1] != 't' || recvbuf[2] != 'h' || recvbuf[3] != '\0') {
					sleng_error("bad message, just drop!\n");
					continue;
				}

				if (fd->debug_flag)
				{
					sleng_debug("recvlen=%d, sizeof(dth_head_t)=%d, buf=\n", recvlen, sizeof(dth_head_t));
					print_in_hex(recvbuf, recvlen, NULL, NULL);
				}

				_dth_config_do_request(SOCK_STREAM, connfd, recvbuf, recvlen, &send_mutex, &cliaddr, cliaddr_len);
			}

			close(connfd);
			connfd = -1;
		}
	} while (0);

	if (listenfd >= 0) close(listenfd);
	if (connfd >= 0) close(connfd);
	return rc;
}	/* End of _tcp_body() */


int main(int argc, char const *argv[])
{
	PSTATIC_FD fd = &static_fd;
	int ret = 0;
	pthread_t tid_udp = 0, tid_tcp = 0;
	THREAD_ARG_S udp_args = {0, 0}, tcp_args = {0, 0};
	void *thread_ret = THREAD_SUCCESS;

	const char short_options[] = "p:da:";
	const struct option long_options[] = {
		{"addr", required_argument, NULL, 'a'},
		{"udp-port", required_argument, NULL, 'p'},
		{"debug", no_argument, 		NULL, 'd'},
		{0, 0, 0, 0}
	};
	int opt, index;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	do {
		opt = getopt_long(argc, (char *const *)argv, short_options, long_options, &index);

		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 0 :
			break;
		case 'a' :
		{
			struct in_addr addr;
			memset(&addr, 0, sizeof(struct in_addr));
			if (inet_aton(optarg, &addr)) {
				udp_args.ipaddr = addr.s_addr;
			} else {
				sleng_error("inet_aton error");
			}
			break;
		}
		case 'p' :
			udp_args.port = atoi(optarg);
			sleng_debug("%s: port = %d\n", __FILE__, udp_args.port);
			break;
		case 'd' :
			fd->debug_flag = 1;
			break;
		default :
			sleng_debug("Param(%c) is invalid\n", opt);
			break;
		}
	} while (1);

	// sleng_debug("%s:%d, sizeof(struct ifreq)=%d\n", __FILE__, __LINE__, sizeof(struct ifreq));
	sleng_debug("Start dth_config_server...\n");
#if 0	/* Use system to setup network, do NOT use this any more */
	memset(&netparams, 0, sizeof(network_params_t));
	if (network_load_params(&netparams, NETWORK_PARAMS_FILE_PATH) != -1) {
		ret = network_modify(&netparams, NULL);
	}
	// sleng_debug("%s@%s:%d\n", __FILE__, __func__, __LINE__);
#endif

	if (pthread_create(&tid_udp, NULL, _dth_config_udp_body, (void *)&udp_args) == -1)
	{
		sleng_error("pthread_create for _udp_body error");
		tid_udp = -1;
	}

	if (pthread_create(&tid_tcp, NULL, _dth_config_tcp_body, (void *)&tcp_args) == -1)
	{
		sleng_error("pthread_create for _tcp_body error");
		tid_tcp = -1;
	}

	if (tid_udp > 0) {
		pthread_join(tid_udp, &thread_ret);
		printf("%s thread return %s\n", "udp_thread", thread_ret? "failure": "success");
	}
	if (tid_tcp > 0) {
		pthread_join(tid_tcp, &thread_ret);
		printf("%s thread return %s\n", "tcp_thread", thread_ret? "failure": "success");
	}

	sleng_debug("Stop dth_config_server...\n");
	return ret;
}
