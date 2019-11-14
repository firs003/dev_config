#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <linux/if.h>
#include <sys/time.h>

#include "dth_config.h"
#include "sleng_test.h"

#define	DTH_CONFIG_CLIENT_SENDBUF_SIZE	2048
#define	DTH_CONFIG_CLIENT_RECVBUF_SIZE	2048


/**********************************************************************
 * function:print info in format like Ultra Edit
 * input:	buf to print,
 * 			length to print,
 * 			prestr before info,
 * 			endstr after info
 * output:	void
 **********************************************************************/
void print_in_hex(void *buf, int len, char *pre, char *end) {
	int i, j, k, row=(len>>4);
	if (buf == NULL) {
		printf("params invalid, buf=%p", buf);
		return;
	}
	if (pre) printf("%s:\n", pre);
	for (i=0, k=0; k<row; ++k) {
		printf("\t[0%02d0] ", k);
		for (j=0; j<8; ++j, ++i) printf("%02hhx ", *((unsigned char *)buf+i));
		printf("  ");
		for (j=8; j<16; ++j, ++i) printf("%02hhx ", *((unsigned char *)buf+i));
		printf("\n");
	}
	if (len&0xf) {
		printf("\t[0%02d0] ", k);
		for (k=0; k<(len&0xf); ++k, ++i) {
			if (k==4) printf("  ");
			printf("%02hhx ", *((unsigned char *)buf+i));
		}
		printf("\n");
	}
	if (end) printf("%s", end);
	printf("\n");
}

#define DTH_CONFIG_SERVER_TMP_IFR_COUNT 8

unsigned int get_local_ip(const char *ifname) {
	int ret = 0;
	struct ifreq ifr;
	int sockfd;
	struct sockaddr_in sa = {
		sin_family:	PF_INET,
		sin_port:	0
	};
	struct ifreq *ifr_array = NULL;
	struct ifconf ifc;

	do {
		if (ifname) {
			strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		} else {	//Get ifname auto
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

			printf("%s[%d]:ifr_count=%ld\n", __func__, __LINE__, ifc.ifc_len/sizeof(struct ifreq));
			for (i=0; i<ifc.ifc_len/sizeof(struct ifreq); i++) {
				// printf("%s[%d]:%d.ifname=%s\n", __func__, __LINE__, i, ifr_array[i].ifr_name);
				if (strncmp("lo", ifr_array[i].ifr_name, IFNAMSIZ)) {
					//steven 09-27-09, get ipaddr
					strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
				}
			}
		}
		if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
			perror("set ipaddr err\n");
			ret = -1;
			break;
		}
		memcpy((char *)&sa, (char *)&ifr.ifr_addr, sizeof(struct sockaddr));
		ret = sa.sin_addr.s_addr;
	} while (0);

	if (sockfd > 0) close(sockfd);
	if (ifr_array) free(ifr_array);
	return ret;
}

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
	// printf("h=%hhx, h<<8=%hhx, hl=%hhx\n", h, (h<<4), (h<<4)|l);
	return (h<<4)|l;
}

static int _file_transfer(const char *path, const unsigned int dest_ip, const unsigned short dest_port)
{
	int ret = 0;
	FILE *fp = NULL;
	int client_socket = -1;
	struct sockaddr_in client_addr, server_addr;
	unsigned char *sendbuf = NULL;
	int sendlen, readlen;

	do {
		if (path == NULL)
		{
			errno = EINVAL;
			ret = -1;
			break;
		}

		sendbuf = (unsigned char *)malloc(4096);
		if (sendbuf == NULL)
		{
			sleng_error("malloc for sendbuf for file transfer error");
			ret = -1;
			break;
		}

		client_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (client_socket < 0)
		{
			sleng_error("Create Socket Failed!");
			ret = -1;
			break;
		}

		bzero(&client_addr, sizeof(client_addr));
		client_addr.sin_family = AF_INET;
		client_addr.sin_addr.s_addr = htons(INADDR_ANY);
		client_addr.sin_port = htons(0);
		//把客户机的socket和客户机的socket地址结构联系起来
		if (bind(client_socket, (const struct sockaddr *)&client_addr, sizeof(client_addr)))
		{
			sleng_error("Client Bind Port Failed!");
			ret = -1;
			break;
		}

		bzero(&server_addr, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = dest_ip;
		server_addr.sin_port = htons(dest_port);
		if ((ret = connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0)
		{
			sleng_error("Can Not Connect To %x : %hu!", server_addr.sin_addr.s_addr, server_addr.sin_port);
			ret = -1;
			break;
		}

		fp = fopen(path, "r");
		if (fp == NULL)
		{
			sleng_error("open [%s] failed", path);
			ret = -1;
			break;
		}

		while (!feof(fp))
		{
			readlen = fread(sendbuf, 1, 4096, fp);
			if (readlen == -1)
			{
				sleng_error("fread from send file[%s] error", path);
				ret = -1;
				break;
			}
			sendlen = send(client_socket, sendbuf, readlen, 0);
			if (sendlen < readlen)
			{
				sleng_error("send error, sendlen(%d) != readlen(%d)", sendlen, readlen);
				ret = -1;
				break;
			}
		}
	} while(0);

	if (fp)
	{
		fclose(fp);
		fp = NULL;
	}
	if (client_socket > 0)
	{
		close(client_socket);
		client_socket = 0;
	}
	if (sendbuf)
	{
		free(sendbuf);
		sendbuf = NULL;
	}

	return ret;
}

enum long_opt_val {
	LONG_OPT_VAL_LOCAL_IP       = 200,
	LONG_OPT_VAL_REMOTE_IP      = 201,
	LONG_OPT_VAL_LOCAL_PATH     = 202,
	LONG_OPT_VAL_REMOTE_PATH    = 203,
	LONG_OPT_VAL_TRANS_MODE     = 204,
	LONG_OPT_VAL_TRANS_PROTOCOL = 205,
	LONG_OPT_VAL_PREV_CMD       = 206,
	LONG_OPT_VAL_POST_CMD       = 207,
	LONG_OPT_VAL_SERVER_IP		= 208,
	LONG_OPT_VAL_NETSET_IP		= 209,
	LONG_OPT_VAL_NETSET_MAC		= 210,
	LONG_OPT_VAL_NETSET_GW		= 211,
	LONG_OPT_VAL_NETSET_MASK	= 212,
	LONG_OPT_VAL_NETSET_DHCP	= 213,
	LONG_OPT_VAL_REBOOT			= 214,
	LONG_OPT_VAL_POWEROFF		= 215,
};

int main(int argc, char const *argv[])
{
	/*
	 * -b broadcast for self report
	 *
	 * -u upgrade
	 */
	int do_netset_flag = 0, do_upgrade_flag = 0, do_reboot_flag = 0, do_poweroff_flag = 0;
	int ret;
	unsigned short port = DTH_CONFIG_REMOTE_DEFAULT_UDP_PORT;
	int ucst_sockfd = -1, sockopt;
	struct sockaddr_in local_addr, remote_addr;
	socklen_t	remote_addr_len = sizeof(struct sockaddr);
	struct timeval tv = {2, 0};
	unsigned char sendbuf[DTH_CONFIG_CLIENT_SENDBUF_SIZE];
	unsigned char recvbuf[DTH_CONFIG_CLIENT_RECVBUF_SIZE];
	unsigned int dest_ip = 0;
	const char short_options[] = "bu:p:m:n:l:r:";
	const struct option long_options[] = {
		{"broadcast",	no_argument,		NULL,	'b'},
		{"reboot",		required_argument,	NULL,	LONG_OPT_VAL_REBOOT},
		{"poweroff",	required_argument,	NULL,	LONG_OPT_VAL_POWEROFF},
		{"upgrade",		required_argument,	NULL,	'u'},
		{"port", 		required_argument,	NULL,	'p'},
		{"md5",			required_argument,	NULL,	'm'},
		{"localip",		required_argument,	NULL,	LONG_OPT_VAL_LOCAL_IP},
		{"serverip",	required_argument,	NULL,	LONG_OPT_VAL_REMOTE_IP},
		{"localpath",	required_argument,	NULL,	'l'},
		{"remotepath",	required_argument,	NULL,	'r'},
		{"transmode",	required_argument,	NULL,	LONG_OPT_VAL_TRANS_MODE},
		{"transproto",	required_argument,	NULL,	LONG_OPT_VAL_TRANS_PROTOCOL},
		{"prevcmd",		required_argument,	NULL,	LONG_OPT_VAL_PREV_CMD},
		{"postcmd",		required_argument,	NULL,	LONG_OPT_VAL_POST_CMD},
		{"serverip",	required_argument,	NULL,	LONG_OPT_VAL_SERVER_IP},
		{"netset",		required_argument,	NULL,	'n'},
		{"netset-ip",	required_argument,	NULL,	LONG_OPT_VAL_NETSET_IP},
		{"netset-mac",	required_argument,	NULL,	LONG_OPT_VAL_NETSET_MAC},
		{"netset-gw",	required_argument,	NULL,	LONG_OPT_VAL_NETSET_GW},
		{"netset-mask",	required_argument,	NULL,	LONG_OPT_VAL_NETSET_MASK},
		{"netset-dhcp",	required_argument,	NULL,	LONG_OPT_VAL_NETSET_DHCP},
		{0, 0, 0, 0}
	};
	int opt, index, recvlen, sendlen;
	upgrade_head_t uphead = {
		.sync = {'d', 'u', 'f', '\0'},
		.md5 = {0, },
		.trans_mode = FILE_TRANS_MODE_R2L_POSITIVE,
		.trans_protocol = FILE_TRANS_PROTOCOL_TFTP,
		.remote_port = 0,
		.remote_ip = get_local_ip(NULL),
		.remote_path = {0, },
		.local_path = {0, },
		.prev_cmd = {0, },
		.post_cmd = {0, },
	};

	ucst_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == ucst_sockfd) {
		perror("socket error");
		goto cleanup;
	}
	memset(&local_addr, 0, sizeof(struct sockaddr_in));
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(port);
	if (bind(ucst_sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1) {
		printf("unicast bind return %d:%s\n", errno, strerror(errno));
		goto cleanup;
	}
	sockopt = 1;
	// printf("%s:%d\n", __FILE__, __LINE__);
	if (setsockopt(ucst_sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0 ) {
		perror("set setsockopt failed");
	}
	if (setsockopt(ucst_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) < 0) {	//2s timeout
		perror("setsockopt timeout");
	}

	do {
		opt = getopt_long(argc, (char *const *)argv, short_options, long_options, &index);

		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 0 :
			break;
		case LONG_OPT_VAL_REBOOT : {
			struct in_addr addr;
			memset(&addr, 0, sizeof(struct in_addr));
			if (inet_aton(optarg, &addr)) {
				dest_ip = addr.s_addr;
				do_reboot_flag = 1;
				printf("%s:%d\n", __FILE__, __LINE__);
			} else {
				perror("inet_aton");
			}
			break;
		}
		case LONG_OPT_VAL_POWEROFF : {
			struct in_addr addr;
			memset(&addr, 0, sizeof(struct in_addr));
			if (inet_aton(optarg, &addr)) {
				dest_ip = addr.s_addr;
				do_poweroff_flag = 1;
				printf("%s:%d\n", __FILE__, __LINE__);
			} else {
				perror("inet_aton");
			}
			break;
		}
		case 'p' :	//May be a bug if -p comes after -b, -b will use default port, sleng 20180720(do_action mask can solve this issue)
			port = atoi(optarg);
			printf("%s: port = %d\n", __FILE__, port);
			break;
		case 'b' : {
			int board_count = 0;
			struct sockaddr_in bcst_addr;
			int bcst_sockfd = -1;
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
				dth_head_t *dth_head = (dth_head_t *)sendbuf;
				dth_head->sync[0] = 'd';
				dth_head->sync[1] = 't';
				dth_head->sync[2] = 'h';
				dth_head->sync[3] = '\0';
				dth_head->type = DTH_REQ_REPORT_SELF;
				dth_head->length = 0;

				memset(&bcst_addr, 0, sizeof(struct sockaddr_in));
				bcst_addr.sin_family = AF_INET;
				bcst_addr.sin_addr.s_addr = INADDR_BROADCAST;
				bcst_addr.sin_port = htons(DTH_CONFIG_BOARD_DEFAULT_UDP_PORT);
				ret = sendto(bcst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&bcst_addr, sizeof(struct sockaddr));
				if (ret < 0) {
					perror("sendto self_report req failed");
					break;
				}
				sleng_debug("sendto return %d\n", ret);

				while (1) {
					int i;
					dth_head_t *dth_head = (dth_head_t *)recvbuf;
					network_params_t *param = NULL;
					recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_CLIENT_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
					if (recvlen <= 0) {
						break;
					}
					print_in_hex(recvbuf, sizeof(dth_head_t)+sizeof(network_params_t)*8, NULL, NULL);

					printf("%s: recvfrom [ip=%08x, port=%hu]\n", __FILE__, (unsigned int)remote_addr.sin_addr.s_addr, ntohs(remote_addr.sin_port));
					if (dth_head->sync[0]!='d' || dth_head->sync[1]!='t' || dth_head->sync[2]!='h' || dth_head->sync[3]!='\0' || dth_head->type != DTH_ACK_REPORT_SELF) {
						printf("Invalid sync head or type\n");
						continue;
					}
					board_count++;
					param = (network_params_t *)(recvbuf + sizeof(dth_head_t));
					for (i = 0; i < dth_head->length/sizeof(network_params_t); i++) {
						struct in_addr addr;
						memset(&addr, 0, sizeof(struct in_addr));
						printf("Board[%d]:if%d, param@%p\n", board_count, i, param);
						printf("\tifname:%s(%s)\n", param[i].ifname, param[i].up? "up": "down");
						addr.s_addr = param[i].ip;
						printf("\tip:%s\n", inet_ntoa(addr));
						addr.s_addr = param[i].mask;
						printf("\tmask:%s\n", inet_ntoa(addr));
						addr.s_addr = param[i].gateway;
						printf("\tgateway:%s\n", inet_ntoa(addr));
						printf("\tmac:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", param[i].mac[0], param[i].mac[1], param[i].mac[2], param[i].mac[3], param[i].mac[4], param[i].mac[5]);
						printf("\tdhcp_enable:%d\n", param[i].dhcp_flag);
						printf("\n");
					}
				}
			} while(0);
			if (bcst_sockfd > 0) close(bcst_sockfd);
			break;
		}
		case 'u' : {
			struct in_addr addr;
			memset(&addr, 0, sizeof(struct in_addr));
			if (inet_aton(optarg, &addr)) {
				dest_ip = addr.s_addr;
				do_upgrade_flag = 1;
			} else {
				perror("inet_aton");
			}
			break;
		}
		case 'l' :
			strncpy(uphead.local_path, optarg, sizeof(uphead.local_path));
			do_upgrade_flag = 1;
			break;
		case 'r' :
			strncpy(uphead.remote_path, optarg, sizeof(uphead.remote_path));
			do_upgrade_flag = 1;
			break;
		case LONG_OPT_VAL_REMOTE_IP : {
			struct in_addr addr;
			memset(&addr, 0, sizeof(struct in_addr));
			if (inet_aton(optarg, &addr)) {
				uphead.remote_ip = addr.s_addr;
				do_upgrade_flag = 1;
			} else {
				perror("inet_aton");
			}
			break;
		}
		case 'm' : {
			char tmp[3] = {0, };
			int i;
			if (strlen(optarg) == 32) {
				for (i = 0; i < strlen(optarg); i+=2) {
					tmp[0] = optarg[i];
					tmp[1] = optarg[i+1];
					tmp[2] = '\0';
					uphead.md5[i/2] = atox(tmp);
				}
			}
			break;
		}
		case 'n' : {
			struct in_addr addr;
			memset(&addr, 0, sizeof(struct in_addr));
			if (inet_aton(optarg, &addr)) {
				dest_ip = addr.s_addr;
				do_netset_flag = 1;
			} else {
				perror("inet_aton");
			}
			break;
		}
		default :
			printf("Param(%c) is invalid\n", opt);
			break;
		}
	} while (1);

	// printf("%s:%d\n", __func__, __LINE__);

	if (do_reboot_flag) {
		do {
			dth_head_t *dth_head = (dth_head_t *)sendbuf;
			dth_head->sync[0] = 'd';
			dth_head->sync[1] = 't';
			dth_head->sync[2] = 'h';
			dth_head->sync[3] = '\0';
			dth_head->type = DTH_REQ_REBOOT;
			dth_head->length = 0;

			remote_addr.sin_addr.s_addr = dest_ip;
			remote_addr.sin_port = htons(DTH_CONFIG_BOARD_DEFAULT_UDP_PORT);
			sendlen = sendto(ucst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&remote_addr, remote_addr_len);
			if (sendlen <= 0) {
				perror("sendto");
				break;
			}

			dth_head = (dth_head_t *)recvbuf;
			recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_CLIENT_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
			if (recvlen <= 0) {
				perror("recvfrom");
				break;
			}
			// print_in_hex(recvbuf, sizeof(dth_head_t)+sizeof(network_params_t)*8, NULL, NULL);

			printf("%s: recvfrom [ip=%08x, port=%hu]\n", __FILE__, (unsigned int)remote_addr.sin_addr.s_addr, ntohs(remote_addr.sin_port));
			if (dth_head->sync[0]!='d' || dth_head->sync[1]!='t' || dth_head->sync[2]!='h' || dth_head->sync[3]!='\0' || dth_head->type != DTH_ACK_REBOOT) {
				printf("Invalid sync head or type\n");
				break;
			} else {
				printf("Reboot Success\n");
			}
		} while (0);
	}

	if (do_poweroff_flag) {
		do {
			dth_head_t *dth_head = (dth_head_t *)sendbuf;
			dth_head->sync[0] = 'd';
			dth_head->sync[1] = 't';
			dth_head->sync[2] = 'h';
			dth_head->sync[3] = '\0';
			dth_head->type = DTH_REQ_POWEROFF;
			dth_head->length = 0;

			remote_addr.sin_addr.s_addr = dest_ip;
			remote_addr.sin_port = htons(DTH_CONFIG_BOARD_DEFAULT_UDP_PORT);
			sendlen = sendto(ucst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&remote_addr, remote_addr_len);
			if (sendlen <= 0) {
				perror("sendto");
				break;
			}

			dth_head = (dth_head_t *)recvbuf;
			recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_CLIENT_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
			if (recvlen <= 0) {
				perror("recvfrom");
				break;
			}
			// print_in_hex(recvbuf, sizeof(dth_head_t)+sizeof(network_params_t)*8, NULL, NULL);

			printf("%s: recvfrom [ip=%08x, port=%hu]\n", __FILE__, (unsigned int)remote_addr.sin_addr.s_addr, ntohs(remote_addr.sin_port));
			if (dth_head->sync[0]!='d' || dth_head->sync[1]!='t' || dth_head->sync[2]!='h' || dth_head->sync[3]!='\0' || dth_head->type != DTH_ACK_POWEROFF) {
				printf("Invalid sync head or type\n");
				break;
			} else {
				printf("Reboot Success\n");
			}
		} while (0);
	}

	if (do_upgrade_flag) {
		do {
			dth_head_t *dth_head = (dth_head_t *)sendbuf;
			dth_head->sync[0] = 'd';
			dth_head->sync[1] = 't';
			dth_head->sync[2] = 'h';
			dth_head->sync[3] = '\0';
			dth_head->type = DTH_REQ_FILE_TRANS;
			dth_head->length = sizeof(upgrade_head_t);

			uphead.trans_mode = FILE_TRANS_MODE_R2L_NEGATIVE;
			uphead.trans_protocol = FILE_TRANS_PROTOCOL_USER;
			memcpy(sendbuf+sizeof(dth_head_t), &uphead, dth_head->length);
			// printf("%s:%d\n", __func__, __LINE__);

			remote_addr.sin_addr.s_addr = dest_ip;
			remote_addr.sin_port = htons(DTH_CONFIG_BOARD_DEFAULT_UDP_PORT);
			sendlen = sendto(ucst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&remote_addr, remote_addr_len);
			if (sendlen <= 0) {
				perror("sendto");
				break;
			}

			/* Transfer file to board via custom tcp protocol */
			if (uphead.trans_mode == FILE_TRANS_MODE_R2L_NEGATIVE && uphead.trans_protocol == FILE_TRANS_PROTOCOL_USER)
			{
				sleep(1);
				_file_transfer(uphead.local_path, dest_ip, DTH_CONFIG_FILE_TRANFER_TCP_PORT);
			}

			dth_head = (dth_head_t *)recvbuf;
			recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_CLIENT_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
			if (recvlen <= 0) {
				perror("recvfrom");
				break;
			}
			// print_in_hex(recvbuf, sizeof(dth_head_t)+sizeof(network_params_t)*8, NULL, NULL);



			printf("%s: recvfrom [ip=%08x, port=%hu]\n", __FILE__, (unsigned int)remote_addr.sin_addr.s_addr, ntohs(remote_addr.sin_port));
			if (dth_head->sync[0]!='d' || dth_head->sync[1]!='t' || dth_head->sync[2]!='h' || dth_head->sync[3]!='\0' || dth_head->type != DTH_ACK_FILE_TRANS) {
				printf("Invalid sync head or type\n");
				break;
			} else {
				printf("Upgrade %s! Return %hhd\n", dth_head->res[0]? "Failed": "Success", dth_head->res[0]);
			}
		}while (0);
	}

	if (do_netset_flag) {
		do {
			network_params_t params = {
				.ifname = {'e', 't', 'h', '1', '\0', },
				.mac = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5},
			};
			dth_head_t *dth_head = (dth_head_t *)sendbuf;
			dth_head->sync[0] = 'd';
			dth_head->sync[1] = 't';
			dth_head->sync[2] = 'h';
			dth_head->sync[3] = '\0';
			dth_head->type = DTH_REQ_SET_NETWORK_PARAMS;
			dth_head->length = sizeof(network_params_t);
			if (1) {
				struct in_addr addr;
				// memset(&params, 0, sizeof(params));
				memset(&addr, 0, sizeof(struct in_addr));
				inet_aton("192.168.0.221", &addr);
				params.ip = addr.s_addr;
				memset(&addr, 0, sizeof(struct in_addr));
				inet_aton("255.255.255.0", &addr);
				params.mask = addr.s_addr;
				memset(&addr, 0, sizeof(struct in_addr));
				inet_aton("192.168.0.1", &addr);
				params.gateway = addr.s_addr;
				// params.ifname = {'e', 't', 'h', '1', '\0', };
				// params.mac = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5};
				params.up = params.dhcp_flag = 0;
				memcpy(sendbuf+sizeof(dth_head_t), &params, sizeof(params));
			}
			remote_addr.sin_addr.s_addr = dest_ip;
			remote_addr.sin_port = htons(DTH_CONFIG_BOARD_DEFAULT_UDP_PORT);
			sendlen = sendto(ucst_sockfd, sendbuf, sizeof(dth_head_t)+dth_head->length, 0, (struct sockaddr *)&remote_addr, remote_addr_len);
			if (sendlen <= 0) {
				perror("sendto");
				break;
			}

			dth_head = (dth_head_t *)recvbuf;
			recvlen = recvfrom(ucst_sockfd, recvbuf, DTH_CONFIG_CLIENT_RECVBUF_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
			if (recvlen <= 0) {
				perror("recvfrom");
				break;
			}
			// print_in_hex(recvbuf, sizeof(dth_head_t)+sizeof(network_params_t)*8, NULL, NULL);

			printf("%s: recvfrom [ip=%08x, port=%hu]\n", __FILE__, (unsigned int)remote_addr.sin_addr.s_addr, ntohs(remote_addr.sin_port));
			if (dth_head->sync[0]!='d' || dth_head->sync[1]!='t' || dth_head->sync[2]!='h' || dth_head->sync[3]!='\0' || dth_head->type != DTH_ACK_SET_NETWORK_PARAMS) {
				printf("Invalid sync head or type\n");
				break;
			} else {
				printf("Upgrade %s! Return %hhd\n", dth_head->res[0]? "Failed": "Success", dth_head->res[0]);
			}
		}while (0);
	}


cleanup:
	if(ucst_sockfd > 0) close(ucst_sockfd);
	return 0;
}
