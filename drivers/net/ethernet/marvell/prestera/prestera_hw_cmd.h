/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef PRESTERA_HW_CMD_H_
#define PRESTERA_HW_CMD_H_

#include "prestera.h"
#include "prestera_acl.h"

#include <linux/types.h>
#include <linux/if_ether.h>

#ifndef __KERNEL__
typedef uint8_t u8;
typedef uint32_t u32;
#define __packed __attribute__ ((__packed__))
#endif

enum prestera_cmd_type_t {
	PRESTERA_CMD_TYPE_SWITCH_INIT = 0x1,
	PRESTERA_CMD_TYPE_SWITCH_ATTR_SET = 0x2,

	PRESTERA_CMD_TYPE_KEEPALIVE_INIT = 0x3,
	PRESTERA_CMD_TYPE_SWITCH_RESET = 0x4,

	PRESTERA_CMD_TYPE_SWITCH_SCT_RATELIMIT_SET = 0x5,
	PRESTERA_CMD_TYPE_SWITCH_SCT_RATELIMIT_GET = 0x6,

	PRESTERA_CMD_TYPE_IPG_GET = 0xFE,
	PRESTERA_CMD_TYPE_IPG_SET = 0xFF,

	PRESTERA_CMD_TYPE_PORT_ATTR_SET = 0x100,
	PRESTERA_CMD_TYPE_PORT_ATTR_GET = 0x101,
	PRESTERA_CMD_TYPE_PORT_INFO_GET = 0x110,
	PRESTERA_CMD_TYPE_PORT_RATE_LIMIT_MODE_SET = 0x111,

	PRESTERA_CMD_TYPE_VLAN_CREATE = 0x200,
	PRESTERA_CMD_TYPE_VLAN_DELETE = 0x201,
	PRESTERA_CMD_TYPE_VLAN_PORT_SET = 0x202,
	PRESTERA_CMD_TYPE_VLAN_PVID_SET = 0x203,
	PRESTERA_CMD_TYPE_VLAN_FLOOD_DOMAIN_SET = 0x204,

	PRESTERA_CMD_TYPE_FDB_ADD = 0x300,
	PRESTERA_CMD_TYPE_FDB_DELETE = 0x301,
	PRESTERA_CMD_TYPE_FDB_FLUSH_PORT = 0x310,
	PRESTERA_CMD_TYPE_FDB_FLUSH_VLAN = 0x311,
	PRESTERA_CMD_TYPE_FDB_FLUSH_PORT_VLAN = 0x312,
	PRESTERA_CMD_TYPE_FDB_MACVLAN_ADD = 0x320,
	PRESTERA_CMD_TYPE_FDB_MACVLAN_DEL = 0x321,
	PRESTERA_CMD_TYPE_FDB_ROUTED_ADD = 0x322,
	PRESTERA_CMD_TYPE_FDB_ROUTED_DEL = 0x323,

	PRESTERA_CMD_TYPE_LOG_LEVEL_SET = 0x3FF,

	PRESTERA_CMD_TYPE_BRIDGE_CREATE = 0x400,
	PRESTERA_CMD_TYPE_BRIDGE_DELETE = 0x401,
	PRESTERA_CMD_TYPE_BRIDGE_PORT_ADD = 0x402,
	PRESTERA_CMD_TYPE_BRIDGE_PORT_DELETE = 0x403,
	PRESTERA_CMD_TYPE_BRIDGE_TEP_ADD = 0x404,
	PRESTERA_CMD_TYPE_BRIDGE_TEP_DELETE = 0x405,

	PRESTERA_CMD_TYPE_COUNTER_GET = 0x510,
	PRESTERA_CMD_TYPE_COUNTER_ABORT = 0x511,
	PRESTERA_CMD_TYPE_COUNTER_TRIGGER = 0x512,
	PRESTERA_CMD_TYPE_COUNTER_BLOCK_GET = 0x513,
	PRESTERA_CMD_TYPE_COUNTER_BLOCK_RELEASE = 0x514,
	PRESTERA_CMD_TYPE_COUNTER_CLEAR = 0x515,

	PRESTERA_CMD_TYPE_VTCAM_CREATE = 0x540,
	PRESTERA_CMD_TYPE_VTCAM_DESTROY = 0x541,
	PRESTERA_CMD_TYPE_VTCAM_RULE_ADD = 0x550,
	PRESTERA_CMD_TYPE_VTCAM_RULE_DELETE = 0x551,
	PRESTERA_CMD_TYPE_VTCAM_IFACE_BIND = 0x560,
	PRESTERA_CMD_TYPE_VTCAM_IFACE_UNBIND = 0x561,

	PRESTERA_CMD_TYPE_ROUTER_RIF_CREATE = 0x600,
	PRESTERA_CMD_TYPE_ROUTER_RIF_DELETE = 0x601,
	PRESTERA_CMD_TYPE_ROUTER_RIF_SET = 0x602,
	PRESTERA_CMD_TYPE_ROUTER_LPM_ADD = 0x610,
	PRESTERA_CMD_TYPE_ROUTER_LPM_DELETE = 0x611,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_SET = 0x622,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_GET = 0x644,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_BLK_GET = 0x645,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_ADD = 0x623,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_DELETE = 0x624,
	PRESTERA_CMD_TYPE_ROUTER_VR_CREATE = 0x630,
	PRESTERA_CMD_TYPE_ROUTER_VR_DELETE = 0x631,
	PRESTERA_CMD_TYPE_ROUTER_VR_ABORT = 0x632,
	PRESTERA_CMD_TYPE_ROUTER_MP_HASH_SET = 0x650,

	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_CREATE = 0x700,
	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_DESTROY = 0x701,
	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_PORTS_SET = 0x702,
	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_PORTS_RESET = 0x703,

	PRESTERA_CMD_TYPE_MDB_CREATE = 0x704,
	PRESTERA_CMD_TYPE_MDB_DESTROY = 0x705,

	PRESTERA_CMD_TYPE_RXTX_INIT = 0x800,

	PRESTERA_CMD_TYPE_LAG_ADD = 0x900,
	PRESTERA_CMD_TYPE_LAG_DELETE = 0x901,
	PRESTERA_CMD_TYPE_LAG_ENABLE = 0x902,
	PRESTERA_CMD_TYPE_LAG_DISABLE = 0x903,
	PRESTERA_CMD_TYPE_LAG_ROUTER_LEAVE = 0x904,

	PRESTERA_CMD_TYPE_STP_PORT_SET = 0x1000,

	PRESTERA_CMD_TYPE_SPAN_GET = 0X1100,
	PRESTERA_CMD_TYPE_SPAN_INGRESS_BIND = 0X1101,
	PRESTERA_CMD_TYPE_SPAN_INGRESS_UNBIND = 0X1102,
	PRESTERA_CMD_TYPE_SPAN_RELEASE = 0X1103,
	PRESTERA_CMD_TYPE_SPAN_EGRESS_BIND = 0X1104,
	PRESTERA_CMD_TYPE_SPAN_EGRESS_UNBIND = 0X1105,

	PRESTERA_CMD_TYPE_L2TUN_ADD = 0x1180,
	PRESTERA_CMD_TYPE_L2TUN_TEP_ADD = 0x1183,
	PRESTERA_CMD_TYPE_L2TUN_TEP_DEL = 0x1184,
	PRESTERA_CMD_TYPE_L2TUN_TEP_SET = 0x1185,
	PRESTERA_CMD_TYPE_L2TUN_TT_ADD = 0x1186,
	PRESTERA_CMD_TYPE_L2TUN_TT_DEL = 0x1187,

	PRESTERA_CMD_TYPE_NAT_PORT_NEIGH_UPDATE = 0X1200,

	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_ADD = 0X1211,
	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_SET = 0X1212,
	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_DEL = 0X1213,
	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_GET = 0X1214,

	PRESTERA_CMD_TYPE_QOS_DSCP_PRIO_MAP_UPDATE = 0X1301,
	PRESTERA_CMD_TYPE_QOS_TRUST_MODE_SET = 0X1302,
	PRESTERA_CMD_TYPE_QOS_DEFAULT_PRIO_SET = 0X1303,

	PRESTERA_CMD_TYPE_SCHED_CREATE = 0X1401,
	PRESTERA_CMD_TYPE_SCHED_RELEASE = 0X1402,
	PRESTERA_CMD_TYPE_SCHED_SET = 0X1403,
	PRESTERA_CMD_TYPE_SCHED_PORT_SET = 0X1404,
	PRESTERA_CMD_TYPE_SCHED_PORT_GET = 0X1405,

	PRESTERA_CMD_TYPE_SHAPER_PORT_QUEUE_CONFIGURE = 0X1411,
	PRESTERA_CMD_TYPE_SHAPER_PORT_QUEUE_DISABLE = 0X1412,

	PRESTERA_CMD_TYPE_PORT_QUEUE_STATS_GET = 0X1421,

	PRESTERA_CMD_TYPE_WRED_PORT_QUEUE_ENABLE = 0X1431,
	PRESTERA_CMD_TYPE_WRED_PORT_QUEUE_DISABLE = 0X1432,

	PRESTERA_CMD_TYPE_POLICER_CREATE = 0x1500,
	PRESTERA_CMD_TYPE_POLICER_RELEASE = 0x1501,
	PRESTERA_CMD_TYPE_POLICER_SET = 0x1502,

	PRESTERA_CMD_TYPE_CPU_CODE_COUNTERS_GET = 0x2000,

	PRESTERA_CMD_TYPE_ACK = 0x10000,
	PRESTERA_CMD_TYPE_MAX
};

enum {
	PRESTERA_CMD_PORT_ATTR_MTU = 3,
	PRESTERA_CMD_PORT_ATTR_MAC = 4,
	PRESTERA_CMD_PORT_ATTR_ACCEPT_FRAME_TYPE = 6,
	PRESTERA_CMD_PORT_ATTR_LEARNING = 7,
	PRESTERA_CMD_PORT_ATTR_FLOOD = 8,
	PRESTERA_CMD_PORT_ATTR_CAPABILITY = 9,
	PRESTERA_CMD_PORT_ATTR_LOCKED = 10,
	PRESTERA_CMD_PORT_ATTR_PHY_MODE = 12,
	PRESTERA_CMD_PORT_ATTR_STATS = 17,
	PRESTERA_CMD_PORT_ATTR_MAC_AUTONEG_RESTART = 18,
	PRESTERA_CMD_PORT_ATTR_PHY_AUTONEG_RESTART = 19,
	PRESTERA_CMD_PORT_ATTR_SOURCE_ID_DEFAULT = 20,
	PRESTERA_CMD_PORT_ATTR_SOURCE_ID_FILTER = 21,
	PRESTERA_CMD_PORT_ATTR_MAC_MODE = 22,
	PRESTERA_CMD_PORT_ATTR_MAX
};

enum {
	PRESTERA_CMD_SWITCH_ATTR_MAC = 1,
	PRESTERA_CMD_SWITCH_ATTR_AGEING = 2,
	PRESTERA_CMD_SWITCH_ATTR_TRAP_POLICER = 3,
};

enum {
	PRESTERA_CMD_ACK_OK,
	PRESTERA_CMD_ACK_FAILED,
	PRESTERA_CMD_ACK_MAX
};

enum {
	PRESTERA_PORT_GOOD_OCTETS_RCV_CNT,
	PRESTERA_PORT_BAD_OCTETS_RCV_CNT,
	PRESTERA_PORT_MAC_TRANSMIT_ERR_CNT,
	PRESTERA_PORT_BRDC_PKTS_RCV_CNT,
	PRESTERA_PORT_MC_PKTS_RCV_CNT,
	PRESTERA_PORT_PKTS_64_OCTETS_CNT,
	PRESTERA_PORT_PKTS_65TO127_OCTETS_CNT,
	PRESTERA_PORT_PKTS_128TO255_OCTETS_CNT,
	PRESTERA_PORT_PKTS_256TO511_OCTETS_CNT,
	PRESTERA_PORT_PKTS_512TO1023_OCTETS_CNT,
	PRESTERA_PORT_PKTS_1024TOMAX_OCTETS_CNT,
	PRESTERA_PORT_EXCESSIVE_COLLISIONS_CNT,
	PRESTERA_PORT_MC_PKTS_SENT_CNT,
	PRESTERA_PORT_BRDC_PKTS_SENT_CNT,
	PRESTERA_PORT_FC_SENT_CNT,
	PRESTERA_PORT_GOOD_FC_RCV_CNT,
	PRESTERA_PORT_DROP_EVENTS_CNT,
	PRESTERA_PORT_UNDERSIZE_PKTS_CNT,
	PRESTERA_PORT_FRAGMENTS_PKTS_CNT,
	PRESTERA_PORT_OVERSIZE_PKTS_CNT,
	PRESTERA_PORT_JABBER_PKTS_CNT,
	PRESTERA_PORT_MAC_RCV_ERROR_CNT,
	PRESTERA_PORT_BAD_CRC_CNT,
	PRESTERA_PORT_COLLISIONS_CNT,
	PRESTERA_PORT_LATE_COLLISIONS_CNT,
	PRESTERA_PORT_GOOD_UC_PKTS_RCV_CNT,
	PRESTERA_PORT_GOOD_UC_PKTS_SENT_CNT,
	PRESTERA_PORT_MULTIPLE_PKTS_SENT_CNT,
	PRESTERA_PORT_DEFERRED_PKTS_SENT_CNT,
	PRESTERA_PORT_GOOD_OCTETS_SENT_CNT,
	PRESTERA_PORT_CNT_MAX,
};

enum {
	PRESTERA_FC_NONE,
	PRESTERA_FC_SYMMETRIC,
	PRESTERA_FC_ASYMMETRIC,
	PRESTERA_FC_SYMM_ASYMM,
};

enum {
	PRESTERA_PORT_TP_NA,
	PRESTERA_PORT_TP_MDI,
	PRESTERA_PORT_TP_MDIX,
	PRESTERA_PORT_TP_AUTO
};

enum {
	PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT = 0,
	PRESTERA_HW_FDB_ENTRY_TYPE_LAG = 1,
	PRESTERA_HW_FDB_ENTRY_TYPE_BRIDGE = 2,
	PRESTERA_HW_FDB_ENTRY_TYPE_TEP = 3,
	PRESTERA_HW_FDB_ENTRY_TYPE_MAX = 4,
};

enum {
	PRESTERA_PORT_FLOOD_TYPE_UC = 0,
	PRESTERA_PORT_FLOOD_TYPE_MC = 1,
	PRESTERA_PORT_FLOOD_TYPE_BC = 2,
};

enum {
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_REG_PORT = 0,
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_LAG = 1,
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_TEP = 2,
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_VLAN_GRP = 3,
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_MAX = 4,
};

enum {
	PRESTERA_HW_SCHED_SP,
	PRESTERA_HW_SCHED_SDWRR
};

enum {
	PRESTERA_POLICER_MODE_SR_TCM
};

struct prestera_msg_cmd {
	__le32 type;
};

struct prestera_msg_ret {
	struct prestera_msg_cmd cmd;
	__le32 status;
};

struct prestera_msg_common_req {
	struct prestera_msg_cmd cmd;
};

struct prestera_msg_common_resp {
	struct prestera_msg_ret ret;
};

struct prestera_msg_switch_attr_req {
	struct prestera_msg_cmd cmd;
	__le32 attr;
	union {
		__le32 ageing_timeout_ms;
		__le32 trap_policer_profile;
		struct {
			u8 mac[ETH_ALEN];
			u8 __pad[2];
		};
	} param;
};

struct prestera_msg_switch_init_resp {
	struct prestera_msg_ret ret;
	__le32 port_count;
	__le32 mtu_max;
	__le32 size_tbl_router_nexthop;
	u8 switch_id;
	u8 lag_max;
	u8 lag_member_max;
};

struct prestera_msg_event_port_param {
	union {
		struct {
			__le32 mode;
			__le32 speed;
			u8 oper;
			u8 duplex;
			u8 fc;
			u8 fec;
		} __packed mac; /* make sure always 12 bytes size */
		struct {
			__le64 lmode_bmap;
			u8 mdix;
			u8 fc;
			u8 __pad[2];
		} __packed phy; /* make sure always 12 bytes size */
	};
};

struct prestera_msg_port_cap_param {
	__le64 link_mode;
	u8  type;
	u8  fec;
	u8  fc;
	u8  transceiver;
};

struct prestera_msg_port_flood_param {
	u8 type;
	u8 enable;
	u8 __pad[2];
};

union prestera_msg_port_param {
	__le32 source_id_default;
	__le32 source_id_filter;
	__le32 mtu;
	u8 oper_state;
	u8 mac[ETH_ALEN];
	u8 accept_frm_type;
	u8 learning;
	u8 type;
	u8 br_locked;
	union {
		struct {
			u8 admin;
			u8 fc;
			u8 ap_enable;
			u8 __reserved[5];
			union {
				struct {
					__le32 mode;
					__le32 speed;
					u8 inband;
					u8 duplex;
					u8 fec;
					u8 fec_supp;
				} reg_mode;
				struct {
					__le32 mode;
					__le32 speed;
					u8 fec;
					u8 fec_supp;
					u8 __pad[2];
				} ap_modes[PRESTERA_AP_PORT_MAX];
			};
		} mac;
		struct {
			__le64 modes;
			__le32 mode;
			u8 admin;
			u8 adv_enable;
			u8 mdix;
			u8 __pad;
		} phy;
	} link;

	struct prestera_msg_port_cap_param cap;
	struct prestera_msg_port_flood_param flood_ext;
	struct prestera_msg_event_port_param link_evt;
};

struct prestera_msg_port_attr_req {
	struct prestera_msg_cmd cmd;
	__le32 attr;
	__le32 port;
	__le32 dev;
	union prestera_msg_port_param param;
};

struct prestera_msg_port_attr_resp {
	struct prestera_msg_ret ret;
	union prestera_msg_port_param param;
};

struct prestera_msg_port_stats_resp {
	struct prestera_msg_ret ret;
	__le64 stats[PRESTERA_PORT_CNT_MAX];
};

struct prestera_msg_port_info_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
};

struct prestera_msg_port_info_resp {
	struct prestera_msg_ret ret;
	__le32 hw_id;
	__le32 dev_id;
	__le16 fp_id;
	u8 pad[2];
};

struct prestera_msg_port_storm_control_cfg_set_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le32 storm_type;
	__le32 kbyte_per_sec_rate;
};

struct prestera_msg_vlan_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 vid;
	u8  is_member;
	u8  is_tagged;
};

struct prestera_msg_vlan_attr_req {
	struct prestera_msg_cmd cmd;
	__le16 vid;
	__le16 __reserved;
	__le32 flood_domain_idx;
};

struct prestera_msg_fdb_req {
	struct prestera_msg_cmd cmd;
	__le32 flush_mode;
	union {
		struct {
			__le32 port;
			__le32 dev;
		};
		__le16 lag_id;
	} dest;
	__le16 vid;
	u8 dest_type;
	u8 dynamic;
	u8 mac[ETH_ALEN];
	u8 __pad[2];
};

struct prestera_msg_log_lvl_set_req {
	struct prestera_msg_cmd cmd;
	__le32 lib;
	__le32 type;
};

struct prestera_msg_iface {
	union {
		struct {
			__le32 dev;
			__le32 port;
		};
		__le16 lag_id;
	};
	__le16 vr_id;
	__le16 vid;
	u8 type;
	u8 pad[3];
};

enum prestera_msg_ip_addr_v {
	PRESTERA_MSG_IPV4 = 0,
	PRESTERA_MSG_IPV6
};

struct prestera_msg_ip_addr {
	union {
		__be32 ipv6[4];
		__be32 ipv4;
	} u;
	u8 v; /* enum prestera_msg_ip_addr_v */
	u8 pad[3];
};

struct prestera_msg_nh {
	struct prestera_msg_iface oif;
	__le32 hw_id;
	u8 mac[ETH_ALEN];
	u8 is_active;
	u8 pad;
};

struct prestera_msg_nh_mangle_info {
	struct prestera_msg_nh nh;
	__be32 sip;
	__be32 dip;
	__be16 l4_src;
	__be16 l4_dst;
	u8 l4_src_valid:1;
	u8 l4_dst_valid:1;
	u8 sip_valid:1;
	u8 dip_valid:1;
	u8 pad[3];
};

struct prestera_msg_nh_mangle_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_nh_mangle_info info;
	__le32 nh_id;
};

struct prestera_msg_nh_mangle_resp {
	struct prestera_msg_ret ret;
	struct prestera_msg_nh_mangle_info info;
	__le32 nh_id;
};

struct prestera_msg_acl_action {
	__le32 id;
	__le32 __reserved;
	union {
		struct {
			u8 hw_tc;
		} trap;
		struct {
			__le32 id;
		} police;
		struct {
			__le32 nh_id;
		} nh;
		struct {
			__be32 old_addr;
			__be32 new_addr;
			__le32 port;
			__le32 dev;
			__le32 flags;
			__le32 __pad;
		} nat;
		struct {
			__le32 index;
		} jump;
		struct {
			__le32 id;
		} count;
		struct {
			u32 dscp;
		} remark;
	};
};

struct prestera_msg_vtcam_create_req {
	struct prestera_msg_cmd cmd;
	__le32 keymask[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	u8 direction;
	u8 lookup;
	u8 pad[2];
};

struct prestera_msg_vtcam_destroy_req {
	struct prestera_msg_cmd cmd;
	__le32 vtcam_id;
};

struct prestera_msg_vtcam_rule_add_req {
	struct prestera_msg_cmd cmd;
	__le32 key[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	__le32 keymask[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	__le32 vtcam_id;
	__le32 prio;
	__le32 n_act;
};

struct prestera_msg_vtcam_rule_del_req {
	struct prestera_msg_cmd cmd;
	__le32 vtcam_id;
	__le32 id;
};

struct prestera_msg_vtcam_bind_req {
	struct prestera_msg_cmd cmd;
	union {
		struct {
			__le32 hw_id;
			__le32 dev_id;
		} port;
		__le32 index;
	};
	__le32 vtcam_id;
	__le16 pcl_id;
	__le16 type;
};

struct prestera_msg_vtcam_resp {
	struct prestera_msg_ret ret;
	__le32 vtcam_id;
	__le32 rule_id;
};

struct prestera_msg_counter_req {
	struct prestera_msg_cmd cmd;
	__le32 client;
	__le32 block_id;
	__le32 num_counters;
};

struct prestera_msg_counter_stats {
	__le64 packets;
	__le64 bytes;
};

struct prestera_msg_counter_resp {
	struct prestera_msg_ret ret;
	__le32 block_id;
	__le32 offset;
	__le32 num_counters;
	__le32 done;
	struct prestera_msg_counter_stats stats[0];
};

struct prestera_msg_nat_port_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	u8 neigh_mac[ETH_ALEN];
	u8 __pad[2];
};

struct prestera_msg_span_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	u8 id;
	u8 pad[3];
};

struct prestera_msg_span_resp {
	struct prestera_msg_ret ret;
	u8 id;
	u8 pad[3];
};

struct prestera_msg_event {
	__le16 type;
	__le16 id;
};

struct prestera_msg_event_log {
	struct prestera_msg_event id;
	__le32 log_string_size;
	u8 log_string[0];
};

union prestera_msg_event_fdb_param {
	u8 mac[ETH_ALEN];
};

struct prestera_msg_event_fdb {
	struct prestera_msg_event id;
	__le32 vid;
	union {
		__le32 port_id;
		__le16 lag_id;
	} dest;
	union prestera_msg_event_fdb_param param;
	u8 dest_type;
};

struct prestera_msg_event_port {
	struct prestera_msg_event id;
	__le32 port_id;
	struct prestera_msg_event_port_param param;
};

struct prestera_msg_bridge_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 bridge;
	u8 pad[2];
};

struct prestera_msg_bridge_resp {
	struct prestera_msg_ret ret;
	__le16 bridge;
	u8 pad[2];
};

struct prestera_msg_macvlan_req {
	struct prestera_msg_cmd cmd;
	__le16 vr_id;
	__le16 vid;
	u8 mac[ETH_ALEN];
	u8 pad[2];
	/* iface will be removed as well as vr_id during fw logic migration
	 * For now it is necessary to calculate priv vid on fw side
	 */
	struct prestera_msg_iface iface;
};

struct prestera_msg_stp_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 vid;
	u8  state;
	u8 __pad;
};

struct prestera_msg_rif_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_iface iif;
	__le32 mtu;
	__le16 rif_id;
	__le16 __reserved;
	u8 mac[ETH_ALEN];
	u8 __pad[2];
};

struct prestera_msg_rif_resp {
	struct prestera_msg_ret ret;
	__le16 rif_id;
	__le16 __pad;
};

struct prestera_msg_lpm_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_ip_addr dst;
	__le32 grp_id;
	__le32 dst_len;
	__le16 vr_id;
	__le16 __pad;
};

struct prestera_msg_nh_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_nh nh[PRESTERA_NHGR_SIZE_MAX];
	__le32 size;
	__le32 grp_id;
};

struct prestera_msg_nh_resp {
	struct prestera_msg_ret ret;
	struct prestera_msg_nh nh[PRESTERA_NHGR_SIZE_MAX];
};

struct prestera_msg_nh_chunk_req {
	struct prestera_msg_cmd cmd;
	__le32 offset;
};

struct prestera_msg_nh_chunk_resp {
	struct prestera_msg_ret ret;
	u8 hw_state[PRESTERA_MSG_CHUNK_SIZE];
};

struct prestera_msg_nh_grp_req {
	struct prestera_msg_cmd cmd;
	__le32 grp_id;
	__le32 size;
};

struct prestera_msg_nh_grp_resp {
	struct prestera_msg_ret ret;
	__le32 grp_id;
};

struct prestera_msg_mp_req {
	struct prestera_msg_cmd cmd;
	u8 hash_policy;
	u8 __pad[3];
};

struct prestera_msg_rxtx_req {
	struct prestera_msg_cmd cmd;
	u8 use_sdma;
	u8 pad[3];
};

struct prestera_msg_rxtx_resp {
	struct prestera_msg_ret ret;
	__le32 map_addr;
};

struct prestera_msg_vr_req {
	struct prestera_msg_cmd cmd;
	__le16 vr_id;
	__le16 __pad;
};

struct prestera_msg_vr_resp {
	struct prestera_msg_ret ret;
	__le16 vr_id;
	__le16 __pad;
};

struct prestera_msg_lag_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 lag_id;
	__le16 vr_id;
};

struct prestera_msg_l2tun_cmd {
	struct prestera_msg_cmd cmd;
	__le16 bridge_id;
};

struct prestera_msg_l2tun_ret {
	struct prestera_msg_ret ret;
	__le32 hw_tun_id;
};

struct prestera_msg_l2tun_tep_cmd {
	struct prestera_msg_cmd cmd;
	__le32 hw_tep_id;
	__le32 source_id;
	__le32 vni;
	struct prestera_msg_iface oif;
	struct prestera_msg_ip_addr dst_ip;
	struct prestera_msg_ip_addr src_ip;
	u8 mac[ETH_ALEN];
	__le16 dst_port;
	__le16 src_port;
	u8 enabled;
};

struct prestera_msg_l2tun_tep_ret {
	struct prestera_msg_ret ret;
	__le32 hw_tep_id;
};

struct prestera_msg_l2tun_tt_cmd {
	struct prestera_msg_cmd cmd;
	__le32 hw_tt_id;
	struct prestera_msg_ip_addr match_ip;
	struct prestera_msg_ip_addr match_ip_src;
	__le32 prio;
	__le32 match_vni;
	__le32 source_id;
	__le32 tep_id;
	__le16 match_udp;
	__le16 match_psngr_etype;
	__le16 match_psngr_etype_mask;
	__le16 match_psngr_vtag;
	__le16 match_psngr_vtag_mask;
	__le16 pvid;
	u8 match_ip_src_valid;
	u8 set_pvid_tagged;
};

struct prestera_msg_l2tun_tt_ret {
	struct prestera_msg_ret ret;
	__le32 hw_tt_id;
};

struct prestera_msg_keepalive_init_req {
	struct prestera_msg_cmd cmd;
	__le32 pulse_timeout_ms;
};

struct prestera_msg_cpu_code_counter_req {
	struct prestera_msg_cmd cmd;
	u8 counter_type;
	u8 code;
	u8 pad[2];
};

struct prestera_msg_cpu_code_counter_resp {
	struct prestera_msg_ret ret;
	__le64 packet_count;
};

struct prestera_msg_flood_domain_create_req {
	struct prestera_msg_cmd cmd;
};

struct prestera_msg_flood_domain_create_resp {
	struct prestera_msg_ret ret;
	__le32 flood_domain_idx;
};

struct prestera_msg_flood_domain_destroy_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
};

struct prestera_msg_flood_domain_ports_set_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
	__le32 ports_num;
};

struct prestera_msg_flood_domain_ports_reset_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
};

struct prestera_msg_flood_domain_port {
	union {
		struct {
			__le32 port_num;
			__le32 dev_num;
		};
		__le16 lag_id;
	};
	__le16 vid;
	__le16 port_type;
};

struct prestera_msg_mdb_create_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
	__le16 vid;
	u8 mac[ETH_ALEN];
};

struct prestera_msg_mdb_destroy_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
	__le16 vid;
	u8 mac[ETH_ALEN];
};

struct prestera_msg_qos_req {
	struct prestera_msg_cmd cmd;
	u32 port;
	u32 dev;
	u32 priority;
	u32 mode;
	u8  dscp[64];
};

struct prestera_msg_sched_req {
	struct prestera_msg_cmd cmd;
	__le32 dev;
	__le32 port;
	__le32 id;
};

struct prestera_msg_sched_resp {
	struct prestera_msg_ret ret;
	__le32 id;
};

struct prestera_msg_sched_attr_req {
	struct prestera_msg_cmd cmd;
	union {
		struct {
			__le32 weight;
		} sdwrr;
	};
	__le32 dev;
	__le32 port;
	__le32 id;
	u8 type;
	u8 tc;
};

struct prestera_msg_shaper_req {
	struct prestera_msg_cmd cmd;
	u32 port;
	u32 dev;
	u32 tc;
	u32 burst;
	u32 rate;
};

struct prestera_msg_shaper_stats_resp {
	struct prestera_msg_ret ret;
	u64 pkts;
	u64 bytes;
	u64 drops;
};

struct prestera_msg_wred_req {
	struct prestera_msg_cmd cmd;
	u32 port;
	u32 dev;
	u32 tc;
	u32 min;
	u32 max;
	u32 prob;
};

struct prestera_msg_sct_ratelimit_set_req {
	struct prestera_msg_cmd cmd;
	u32 rate_pps;
	u8 group;
};

struct prestera_msg_sct_ratelimit_get_req {
	struct prestera_msg_cmd cmd;
	u8 group;
};

struct prestera_msg_sct_ratelimit_get_resp {
	struct prestera_msg_ret ret;
	u32 rate_pps;
};

struct prestera_msg_ipg_set_req {
	struct prestera_msg_cmd cmd;
	u32 ipg;
} __packed __aligned(4);

struct prestera_msg_ipg_get_resp {
	struct prestera_msg_ret ret;
	u32 ipg;
} __packed __aligned(4);

struct prestera_msg_policer_req {
	struct prestera_msg_cmd cmd;
	__le32 id;
	union {
		struct {
			__le64 cir;
			__le32 cbs;
		} __packed sr_tcm; /* make sure always 12 bytes size */
		__le32 reserved[6];
	};
	u8 mode;
	u8 type;
};

struct prestera_msg_policer_resp {
	struct prestera_msg_ret ret;
	__le32 id;
};

#endif /* PRESTERA_HW_CMD_H_ */
