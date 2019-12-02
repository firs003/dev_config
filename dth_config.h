#ifndef __DTH_CONFIG_H__
#define __DTH_CONFIG_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define DTH_CONFIG_BOARD_DEFAULT_UDP_PORT 23333
#define DTH_CONFIG_REMOTE_DEFAULT_UDP_PORT 23334
#define DTH_CONFIG_FILE_TRANFER_TCP_PORT 23335

typedef enum dth_config_payload_type {
	DTH_CONFIG_PAYLOAD_TYPE_UNKNOWN = -1,
	DTH_CONFIG_PAYLOAD_TYPE_DEFAULT = 0,

	DTH_PAYLOAD_TYPE_BASE = 0,
	DTH_REQ_RESTART = DTH_PAYLOAD_TYPE_BASE,	/**< Restart the dmservice */
	DTH_ACK_RESTART,
	DTH_REQ_REBOOT,								/**< Reboot system */
	DTH_ACK_REBOOT,
	DTH_REQ_POWEROFF,
	DTH_ACK_POWEROFF,

	DTH_REQ_REPORT_SELF,
	DTH_ACK_REPORT_SELF,
	DTH_REQ_FILE_TRANS,
	DTH_ACK_FILE_TRANS,

	DTH_BOARDINFO_BASE = 0x100,
	DTH_REQ_GET_BDINFO = DTH_BOARDINFO_BASE,
	DTH_ACK_GET_BDINFO,
	DTH_REQ_SET_BDINFO,
	DTH_ACK_SET_BDINFO,
	DTH_REQ_GET_NETWORK_PARAMS,
	DTH_ACK_GET_NETWORK_PARAMS,
	DTH_REQ_SET_NETWORK_PARAMS,
	DTH_ACK_SET_NETWORK_PARAMS,

} dth_payload_type_e;

typedef enum dth_config_ack_value {
	DTH_CONFIG_ACK_VALUE_ERR = -1,
	DTH_CONFIG_ACK_VALUE_OK = 0,
	DTH_CONFIG_ACK_VALUE_READY,
	DTH_CONFIG_ACK_VALUE_NOT_SUPPORT,
	DTH_CONFIG_ACK_VALUE_ILLEGAL,
	DTH_CONFIG_ACK_VALUE_CREATE_THREAD_FAILED,
	DTH_CONFIG_ACK_VALUE_POSITIVE_DOWNLOAD_FIALED,
	DTH_CONFIG_ACK_VALUE_MD5_CHECK_FAILED,
	DTH_CONFIG_ACK_VALUE_CREATE_FILE_FAILED,
	DTH_CONFIG_ACK_VALUE_SET_NETWORK_PARAMS_FAILED,
} dth_ack_value_e;

typedef struct network_params {
	unsigned int ip;
	unsigned int mask;
	unsigned int gateway;
	// unsigned int network;
	unsigned int broadcast;
	char ifname[26];
	unsigned char mac[6];
	short up;
	short dhcp_flag;
} network_params_t;


/**************************************************
 * R: Remote, L: Local
 * POSITIVE: Local-client, Remote-server
 * NAGATIVE: Local-server, Remote-client
 * HIGHBIT: Direction 0 means R->L and 1 means L->R
 * LOWBIT: Server, 0 means on board(N), 1 means on remote(P)
 **************************************************/
typedef enum file_trans_mode {
	FILE_TRANS_MODE_R2L_NEGATIVE = 0x00,		/**< Transfer file from remote(PC) to local(Board), the board listen on custom protocol via tcp */
	FILE_TRANS_MODE_L2R_NEGATIVE = 0x01,		/**< Transfer file from local(Board) to remote(PC), the board connect on custom protocol via tcp */
	FILE_TRANS_MODE_R2L_POSITIVE = 0x10,		/**< Transfer file from remote(PC) to local(Board), the board call tftp to get file positive */
	FILE_TRANS_MODE_L2R_POSITIVE = 0x11,		/**< Transfer file from local(Board) to remote(PC), the board call tftp to put file positive */
} trans_mode_e;

typedef enum file_trans_protocol {
	FILE_TRANS_PROTOCOL_USER,
	FILE_TRANS_PROTOCOL_TFTP,
	FILE_TRANS_PROTOCOL_FTP
} trans_protocol_e;

typedef enum file_type {
	FILE_TYPE_BIN,		/**< Binary */
	FILE_TYPE_ASCII,	/**< Ascii */
	FILE_TYPE_PACK,		/**< Package files in one */
} file_type_e;

/*********************************
 * DTH_REQ_UPGRADE_FIRMWARE_POSITIVE message layout, payload begins with the upgrade_head in front and the real file followed
 * | DTH_SYNC | DTH_TYPE | DTH_LEN | DTH_RES | DTH_PAYLOAD([upgrade_sync|md5|mode|port|ip|src_path|dth_path|prev_cmd|post_cmd|Real_File]) |
 *********************************/
typedef struct upgrade_file_head {
	unsigned char sync[4];		/**< must be duf\0, Disthen Upgrade Firmware */
	unsigned char md5[16];
	unsigned char trans_mode;	/**< direction and mode, defined in file_trans_mod enum */
	unsigned char trans_protocol;
	unsigned char file_type;
	unsigned char res[3];
	unsigned short remote_port;
	unsigned int remote_ip;
	unsigned int file_size;
	char remote_path[128];
	char local_path[128];
	char prev_cmd[128];
	char post_cmd[128];
} upgrade_head_t;

typedef struct dth_config_head {
	unsigned char sync[4];		/**< must be dth\0, DisTHen */
	dth_payload_type_e type;	/**< payload type */
	unsigned int length;		/**< payload length, exclude of head, <=2048-4-4-4-4 */
	unsigned char res[4];		/**< res[0] for ack value */
} dth_head_t;


#ifdef __cplusplus
};
#endif

#endif /* __DTH_CONFG_H__ */
