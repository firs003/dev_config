#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <linux/route.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <libgen.h>

#include "dth_config.h"

#define NETWORK_PARAMS_FILE_PATH "/disthen/config/network.conf"
#define DTH_CONFIG_SERVER_SENDBUF_SIZE 2048
#define DTH_CONFIG_SERVER_RECVBUF_SIZE 2048

static network_params_t default_net_params = {
	.ip        = 0xdf00a8c0,	//192.168.0.223
	.mask      = 0x00ffffff,	//255.255.255.0
	.gateway   = 0x0100a8c0,	//192.168.0.1
	.ifname    = {'e','t','h','0', 0,},
	.mac       = {0x30,0x0a,0x09,0x11,0xe0,0x40},
	.dhcp_flag = 0
};

int gquit_flag = 0;	//global quit flag

static void signal_handler(int signo) {
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		signal(signo, SIG_DFL);
		gquit_flag = 1;
	default:
		signal(signo, SIG_DFL);
	}
}

static int network_setmac(network_params_t *params) {
	struct ifreq ifr;
	int sockfd;

	memset(&ifr, 0, sizeof(struct ifreq));
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket");
		return -1;
	}

	//steven 09-27-09, set macAddr
	strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("get MAC err\n");
		close(sockfd);
		return -1;
	}

	strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, params->mac, IFHWADDRLEN);
	if (ioctl(sockfd, SIOCSIFHWADDR, &ifr) < 0) {
        perror("set macaddr err");
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return 0;
}

static int network_load_params(network_params_t *params, const char *path) {
	int n, i, err = 0;
    unsigned char temp = 0;
    FILE *fp;

    if ((fp = fopen(NETWORK_PARAMS_FILE_PATH, "rb")) == NULL) {
        printf("fopen netconf file for read err, use default\n");
		memcpy(params, &default_net_params, sizeof(network_params_t));
        err = 1;
    }

    if (err == 0) {
        if ((n = fread(params, 1, sizeof(network_params_t), fp)) <= 0) {
            perror("fread netconf file err");
            err = 1;
        }
        if (n != sizeof(network_params_t)) {
	        printf("net config file maybe destoryed, use default\n");
	        err = 1;
        }
        fclose(fp);

		if (params->dhcp_flag) {
			params->ip = params->mask = params->gateway = 0;
			err = 0;
			return 0;
		}
        if ((params->ip&params->mask) != (params->gateway&params->mask)) {
            err = 1;
        }
        if (((htonl(params->ip)&0xff000000) == 0) || ((htonl(params->ip)&0xff) == 0xff) || (htonl(params->ip) >= 0xe0000000)) {
            err = 1;
        } else if ((params->mask == 0) || (params->mask == 0xffffffff) || ((htonl(params->mask)&0xff000000) == 0)
                   || ((htonl(params->mask)&0xff0000) == 0) ){//|| ((htonl(params->mask)&0xff00) == 0)) { //linxj2011-06-01
            err = 1;
        } else if (((htonl(params->gateway)&0xff000000) == 0) || ((htonl(params->gateway)&0xff) == 0xff)) {
            err = 1;
        } else if ((params->ip == params->mask) || (params->ip == params->gateway) || (params->mask == params->gateway)) {
            err = 1;
        }
        for (i=0; i<6; i++)
            temp |= params->mac[i];
        if (temp == 0x0) {
            err = 1;
        }
    }

    if (err == 1) {
		// memcpy(params, &default_net_params, sizeof(network_params_t));
		*params = default_net_params;
    }

    return 0;
}

static int network_modify(network_params_t *params, const char *file_path) {
    FILE *fp;
	struct ifreq ifr;
	struct rtentry rt;
	int sockfd;
	struct sockaddr_in sa = {
		sin_family:	PF_INET,
		sin_port:	0
	};

	if (params->dhcp_flag) {
		params->ip = params->mask = params->gateway = 0;
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	if (file_path) {
	    if ((fp = fopen(file_path, "wb")) == NULL) {
	        perror("fopen netconf file for write err");
	    } else {
	    	if (fwrite(params, 1, sizeof(network_params_t), fp) <= 0) {
	        	perror("fwrite netconf file err");
	    	}
	    	fclose(fp);
	    }
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);
	if (params->dhcp_flag) {
		printf("\n\n\n------------------------------------net_cfg.dhcp_flag = %d\n", params->dhcp_flag);
		system("dhclient");
//		if (-1 == net_getstatus(params)) {
//			printf("[E]net_modify get net status error\n");
//			return -1;
//		}
		if (-1 == network_setmac(params)) {
			printf("[E]net_modify set mac error\n");
			return -1;
		}
		printf("ipAddr=0x%x\n", params->ip);
		printf("mask=0x%x\n", params->mask);
		printf("mac=%02hhx %02hhx %02hhx %02hhx %02hhx %02hhx\n\n\n", params->mac[0], params->mac[1], params->mac[2], params->mac[3], params->mac[4], params->mac[5]);

		return 0;
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	memset(&ifr, 0, sizeof(struct ifreq));
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket");
		return -1;
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	//steven 09-27-09, set macAddr
	strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("get MAC err\n");
		close(sockfd);
		return -1;
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	// strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, params->mac, IFHWADDRLEN);
	// print_in_hex(ifr.ifr_ifru.ifru_hwaddr.sa_data, IFHWADDRLEN, "New Mac", NULL);
	if (ioctl(sockfd, SIOCSIFHWADDR, &ifr) < 0) {
        perror("set macaddr err");
		close(sockfd);
		return -1;
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	//steven 09-27-09, set ipaddr 
	sa.sin_addr.s_addr = params->ip;
	// strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	memcpy((char *) &ifr.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
		close(sockfd);
		perror("set ipaddr err\n");
		return -1;
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	//steven 09-27-09, set mask
	sa.sin_addr.s_addr = params->mask;
	// strncpy(ifr.ifr_name, params->ifname, IFNAMSIZ);
	memcpy((char *) &ifr.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
	if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
		close(sockfd);
        perror("set mask err");
		//return -1;    //sp 12-02-09 cut a bug
	}
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	//steven 09-27-09, set gateway Addr
	// Clean out the RTREQ structure.
	memset((char *) &rt, 0, sizeof(struct rtentry));
	// Fill in the other fields.
	rt.rt_flags = (RTF_UP | RTF_GATEWAY);
	rt.rt_dst.sa_family = PF_INET;
	rt.rt_genmask.sa_family = PF_INET;
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	sa.sin_addr.s_addr = params->gateway;
	memcpy((char *) &rt.rt_gateway, (char *) &sa, sizeof(struct sockaddr));
	// Tell the kernel to accept this route.
	if (ioctl(sockfd, SIOCADDRT, &rt) < 0) {
		close(sockfd);
        perror("set gateway err");
		//return -1;    //sp 12-02-09 cut a bug
	}
	close(sockfd);
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

    return 0;
}

#define DTH_CONFIG_SERVER_TMP_IFR_COUNT 32
static int get_if_num(void) {
	int sockfd, ret = 0;
	struct ifreq *ifr_array = NULL;
	struct ifconf ifc;
	do {
		ifr_array = calloc(DTH_CONFIG_SERVER_TMP_IFR_COUNT, sizeof(struct ifreq));
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("socket");
			ret = -1;
			break;
		}
		ifc.ifc_len = DTH_CONFIG_SERVER_TMP_IFR_COUNT * sizeof(struct ifreq);
		ifc.ifc_buf = (void *)ifr_array;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			perror("set ipaddr err\n");
			ret = -1;
			break;
		}
		ret = ifc.ifc_len/sizeof(struct ifreq);
	} while (0);
	if(sockfd > 0) close(sockfd);
	if(ifr_array) free(ifr_array);

	return ret;
}

static int network_getstaus(void *buf, size_t bufsize) {
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
			perror("calloc");
			ret = -1;
			break;
		}
		memset(&ifr, 0, sizeof(struct ifreq));
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	        perror("socket");
			ret = -1;
			break;
		}
		ifc.ifc_len = DTH_CONFIG_SERVER_TMP_IFR_COUNT * sizeof(struct ifreq);
		ifc.ifc_buf = (void *)ifr_array;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			perror("set ipaddr err\n");
			ret = -1;
			break;
		}

		printf("%s[%d]:ifr_count=%d\n", __func__, __LINE__, ifc.ifc_len/sizeof(struct ifreq));
		for (i=0; i<ifc.ifc_len/sizeof(struct ifreq); i++, param++) {
			printf("%s[%d]:%d.ifname=%s\n", __func__, __LINE__, i, ifr_array[i].ifr_name);
			strncpy(param->ifname, ifr_array[i].ifr_name, IFNAMSIZ);
			//steven 09-27-09, set ipaddr 
			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
				perror("set ipaddr err\n");
				ret = -1;
				break;
			}
			memcpy((char *)&sa, (char *)&ifr.ifr_addr, sizeof(struct sockaddr));
			param->ip = sa.sin_addr.s_addr;

			//steven 09-27-09, set mask
			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
		        perror("get mask err");
				//ret = -1;
				//break;    //sp 12-02-09 cut a bug
			}
			memcpy((char *)&sa, (char *)&ifr.ifr_addr, sizeof(struct sockaddr));
			param->mask = sa.sin_addr.s_addr;

			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
				perror("get MAC err\n");
				ret = -1;
				break;
			}
			memcpy(param->mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, IFHWADDRLEN);

			strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
				perror("get flags err\n");
				ret = -1;
				break;
			}
			param->up = ifr.ifr_flags & IFF_UP;

		/*	//how to get GATEWAY? ls, 2013-02-25
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
		        perror("set gateway err");
				//return -1;    //sp 12-02-09 cut a bug
			}
		*/
		}
	} while (0);

	if (sockfd > 0) close(sockfd);
	if (ifr_array) free(ifr_array);
	return ret;
}

struct file_trans_args {
	pthread_mutex_t *mutex;
	upgrade_head_t *up_head;
	unsigned char *sendbuf;
	int send_sock;
	struct sockaddr_in remote_addr;
} file_trans_args_t;

static inline unsigned char atox(const char *str) {
	unsigned char low, high, l, h;
	low = (strlen(str) == 1)? str[0]: str[1];
	high = (strlen(str) == 1)? '0': str[0];
	if (low >= '0' && low <= '9') {
		l = low - '0';
	} else if (low >= 'a' && low <= 'f') {
		l = low - 'a' + 10;
	}
	if (high >= '0' && high <= '9') {
		h = high - '0';
	} else if (high >= 'a' && high <= 'f') {
		h = high - 'a' + 10;
	}
	return (h<<4)|l;
}

#define DOWNLOAD_DIR "/disthen/download"
#define BACKUP_DIR "/disthen/backup"

static void *file_trans_thread_func(void *args) {
	struct file_trans_args *trans_args = (struct file_trans_args *)args;
	char cmd[256] = {0,};
	unsigned char local_md5[16] = {0, };
	int ret = 0;
	dth_head_t *dth_head = (dth_head_t *)trans_args->sendbuf;
	pthread_detach(pthread_self());

	dth_head->sync[0] = 'd';
	dth_head->sync[1] = 't';
	dth_head->sync[2] = 'h';
	dth_head->sync[3] = '\0';
	dth_head->type = DTH_ACK_FILE_TRANS;
	dth_head->length = 0;
	dth_head->res[0] = DTH_CONFIG_ACK_VALUE_OK;
	switch (trans_args->up_head->trans_mode) {
	case FILE_TRANS_MODE_R2L_POSITIVE:
		do {
			char back_path[128] = {0, };
			char tmp_path[128] = {0, };
			struct in_addr addr;
			//backup orig file if nessery
			//exec prev cmd
			//file trans
			
			memset(&addr, 0, sizeof(struct in_addr));
			addr.s_addr = trans_args->up_head->remote_ip;
			//TODO, is FTP cmd like the format of TFTP cmd?
			if (trans_args->up_head->trans_protocol == FILE_TRANS_PROTOCOL_TFTP) {
				sprintf(tmp_path, "%s/%s_tftp_%ld", DOWNLOAD_DIR, basename(trans_args->up_head->local_path), pthread_self());
				sprintf(cmd, "%s -l %s -r %s -g %s", 
					"tftp",
					tmp_path,
					trans_args->up_head->remote_path,
					inet_ntoa(addr));
			} else {
				dth_head->res[0] = DTH_CONFIG_ACK_VALUE_NOT_SUPPORT;
				break;
			}
			ret = system(cmd);
			printf("cmd=%s, system() return %d\n", cmd, ret);
			if(ret) {
				dth_head->res[0] = DTH_CONFIG_ACK_VALUE_POSITIVE_DOWNLOAD_FIALED;
				break;
			}
			//exec post cmd
			//md5 check
			memset(local_md5, 0, sizeof(local_md5));
			// printf("memcmp md5 return %d\n", memcmp(trans_args->up_head->md5, local_md5, sizeof(trans_args->up_head->md5)));
			if (memcmp(trans_args->up_head->md5, local_md5, sizeof(trans_args->up_head->md5))) {	//trans_md5 is not all 0x00;
				char tmp[3] = {0, };
				char buf[128] = {0, };
				int i;
				FILE *fp = NULL;
				memset(cmd, 0, sizeof(cmd));
				sprintf(cmd, "md5sum %s", tmp_path);
				do {
					fp = popen(cmd, "r");
					if (fp == NULL) {
						perror("popen md5sum failed");
						dth_head->res[0] = DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED;
						break;
					}
					fread(buf, 1, sizeof(buf), fp);
					printf("buf=%s\n", buf);
				} while (0);
				if (fp) pclose(fp);

				for (i = 0; i < 32; i+=2) {
					tmp[0] = buf[i];
					tmp[1] = buf[i+1];
					tmp[2] = '\0';
					local_md5[i/2] = atox(tmp);
					// printf("tmp=%s, local_md5[%d]=%02hhx\n", tmp, i/2, local_md5[i/2]);
				}
				if (buf[i] != ' ') {
					printf("local md5sum format error\n");
					dth_head->res[0] = DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED;
					break;
				}
				printf("local_md5 =");
				for (i=0; i<sizeof(local_md5); i++) printf("%02hhx", local_md5[i]);
				printf("\n");
				printf("remote_md5=");
				for (i=0; i<sizeof(trans_args->up_head->md5); i++) printf("%02hhx", trans_args->up_head->md5[i]);
				printf("\n");
				if (memcmp(trans_args->up_head->md5, local_md5, sizeof(trans_args->up_head->md5)) == 0) {
					printf("md5 check success!\n");
				} else {
					printf("md5 check failed!\n");
					dth_head->res[0] = DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED;
					break;
				}
			}
			sprintf(back_path, "%s/%s", BACKUP_DIR, basename(trans_args->up_head->local_path));
			unlink(back_path);
			if (link(trans_args->up_head->local_path, back_path)) {
				perror("link1");
				// dth_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
				// break;
			}
			unlink(trans_args->up_head->local_path);
			if (link(tmp_path, trans_args->up_head->local_path)) {
				perror("link2");
				dth_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
				break;
			}
			if (unlink(tmp_path)) {
				perror("unlink");
				dth_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED;
				break;
			}
		} while(0);
		break;

	default :
		dth_head->res[0] = DTH_CONFIG_ACK_VALUE_NOT_SUPPORT;
		break;
	}
	//send back file trans result
	pthread_mutex_lock(trans_args->mutex);
	ret = sendto(trans_args->send_sock, trans_args->sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&trans_args->remote_addr, sizeof(struct sockaddr));
	if (ret < 0) {
		perror("sendto self_report ack failed");
	}
	pthread_mutex_unlock(trans_args->mutex);

	return (void *)0;
}

int main(int argc, char const *argv[])
{
	int ret;
	network_params_t netparams;
	unsigned short port = DTH_CONFIG_BOARD_DEFAULT_UDP_PORT;
	int ucst_sockfd = -1, sockopt;
	struct sockaddr_in local_addr, remote_addr;
	socklen_t	remote_addr_len = sizeof(struct sockaddr);
	struct timeval tv = {2, 0};
	unsigned char sendbuf[DTH_CONFIG_SERVER_SENDBUF_SIZE];
	unsigned char recvbuf[DTH_CONFIG_SERVER_RECVBUF_SIZE];
	pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_t file_trans_tid;
	struct file_trans_args trans_args;

    const char short_options[] = "p:";
    const struct option long_options[] = {
		{"port", required_argument, NULL, 'p'},
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
        case 'p' :
        	port = atoi(optarg);
            printf("%s: port = %d\n", __FILE__, port);
            break;
        default :
        	printf("Param(%c) is invalid\n", opt);
        	break;
        }
    } while (1);

    printf("%s:%d, sizeof(struct ifreq)=%d\n", __FILE__, __LINE__, sizeof(struct ifreq));
	memset(&netparams, 0, sizeof(network_params_t));
	ret = network_load_params(&netparams, NETWORK_PARAMS_FILE_PATH);
	ret = network_modify(&netparams, NULL);
	printf("%s@%s:%d\n", __FILE__, __func__, __LINE__);

	ucst_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == ucst_sockfd) {
		perror("socket error");
		return -1;
	}
	printf("%s:%d\n", __FILE__, __LINE__);
	memset(&local_addr, 0, sizeof(struct sockaddr_in));
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(port);
	if (bind(ucst_sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1) {
		perror("unicast socket bind");
		close(ucst_sockfd);
	}
	sockopt = 1;
	printf("%s:%d\n", __FILE__, __LINE__);
	if (setsockopt(ucst_sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0 ) {
		perror("set setsockopt failed");
	}
	if (setsockopt(ucst_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) < 0) {	//2s timeout
	    perror("setsockopt timeout");
	}
	printf("%s:%d\n", __func__, __LINE__);
	while (!gquit_flag) {
		int recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_SERVER_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
		// printf("%s:%d\n", __FILE__, __LINE__);
		if (recvlen != -1) {
			dth_head_t *dth_head = (dth_head_t *)recvbuf;
			printf("%s: recvfrom [ip=%08x, port=%hu]\n", __FILE__, (unsigned int)remote_addr.sin_addr.s_addr, ntohs(remote_addr.sin_port));
			if (dth_head->sync[0]!='d' || dth_head->sync[1]!='t' || dth_head->sync[2]!='h' || dth_head->sync[3]!='\0') {
				printf("bad sync, just drop! dth ... ... ... ...\n");
				continue;
			}
			// if (dth_head->length > DTH_CONFIG_SERVER_RECVBUF_SIZE - sizeof(dth_head_t));	//TODO
			switch (dth_head->type) {
			case DTH_REQ_REPORT_SELF: {
				struct sockaddr_in bcst_addr;
				int bcst_sockfd = -1, if_num = get_if_num();
				do {
					if ((bcst_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
					    perror("refresh socket");
					    break;
					}
					sockopt = 1;
					if (setsockopt(bcst_sockfd, SOL_SOCKET, SO_BROADCAST, (char*)&sockopt, sizeof(sockopt))) {
						perror("set setsockopt failed");
						break;
					}
					dth_head = (dth_head_t *)sendbuf;
					dth_head->sync[0] = 'd';
					dth_head->sync[1] = 't';
					dth_head->sync[2] = 'h';
					dth_head->sync[3] = '\0';
					dth_head->type = DTH_ACK_REPORT_SELF;
					dth_head->length = sizeof(network_params_t) * if_num;
					if (network_getstaus(sendbuf + sizeof(dth_head_t), DTH_CONFIG_SERVER_SENDBUF_SIZE - sizeof(dth_head_t)) < 0) {
						printf("Get working if status failed\n");
						break;
					}

					memset(&bcst_addr, 0, sizeof(struct sockaddr_in));
					bcst_addr.sin_family = AF_INET;
					bcst_addr.sin_addr.s_addr = INADDR_BROADCAST;
					bcst_addr.sin_port = htons(DTH_CONFIG_REMOTE_DEFAULT_UDP_PORT);
					pthread_mutex_lock(&send_mutex);
					ret = sendto(bcst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&bcst_addr, sizeof(struct sockaddr));
					if (ret < 0) {
						perror("sendto self_report ack failed");
						pthread_mutex_unlock(&send_mutex);
						break;
					}
					pthread_mutex_unlock(&send_mutex);
				} while(0);
				if (bcst_sockfd > 0) close(bcst_sockfd);
				break;
			}

			case DTH_REQ_FILE_TRANS: {
				if (dth_head->length == sizeof(upgrade_head_t) 
					&& recvbuf[sizeof(dth_head_t)+0] == 'd'
					&& recvbuf[sizeof(dth_head_t)+1] == 'u'
					&& recvbuf[sizeof(dth_head_t)+2] == 'f'
					&& recvbuf[sizeof(dth_head_t)+3] == '\0') {
					trans_args.mutex = &send_mutex;
					trans_args.up_head = (upgrade_head_t *)(recvbuf + sizeof(dth_head_t));
					trans_args.sendbuf = sendbuf;
					trans_args.send_sock = ucst_sockfd;
					trans_args.remote_addr = remote_addr;
					if (pthread_create(&file_trans_tid, NULL, file_trans_thread_func, &trans_args) < 0) {
						perror("create file_trans_thread failed");
						dth_head = (dth_head_t *)sendbuf;
						dth_head->sync[0] = 'd';
						dth_head->sync[1] = 't';
						dth_head->sync[2] = 'h';
						dth_head->sync[3] = '\0';
						dth_head->type = DTH_ACK_FILE_TRANS;
						dth_head->length = 0;
						dth_head->res[0] = DTH_CONFIG_ACK_VALUE_CREATE_THREAD_FAILED;
						pthread_mutex_lock(&send_mutex);
						ret = sendto(ucst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr));
						if (ret < 0) {
							perror("sendto self_report ack failed");
						}
						pthread_mutex_unlock(&send_mutex);
					}
				}
				break;
			}

			default :
				printf("Invalid type [%d]\n", dth_head->type);
			}
		}
	}

	if (ucst_sockfd > 0) close(ucst_sockfd);
	pthread_mutex_destroy(&send_mutex);
	return 0;
}