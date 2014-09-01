# coding: utf-8

# ryu -> mld
CON_MAIN_DISPATCHER = 11
CON_PACKET_IN = 12

# mld -> ryu
CON_FLOW_MOD = 21
CON_PACKET_OUT = 22

# MLD処理部でのReport受信後の動作(Flowmodの動作)
CON_REPLY_NOTHING = 30
CON_REPLY_ADD_MC_GROUP = 31
CON_REPLY_ADD_SWITCH = 32
CON_REPLY_ADD_PORT = 33
CON_REPLY_DEL_MC_GROUP = 34
CON_REPLY_DEL_SWITCH = 35
CON_REPLY_DEL_PORT = 36

# =============================================================================
# ログファイルの定義
# =============================================================================
MLD_LOG_CONF = "logconf_mld.ini"
RYU_LOG_CONF = "logconf_ryu.ini"

# =============================================================================
# config.jsonの定義
# =============================================================================
# 設定ファイル
CONF_FILE = "config.json"
# Socketタイプ用定数
CHECK_ZMQ_TYPE_IPC = "ipc"
CHECK_ZMQ_TYPE_TCP = "tcp"
# ZMQ用定数
URL_DELIMIT = "://"
PORT_DELIMIT = ":"
SEND_IP = "0.0.0.0"
# 設定ファイルの定義名
SETTING = "settings"
ZMQ_TYPE = "zmq_type"
ZMQ_IPC = "zmq_ipc"
ZMQ_TCP = "zmq_tcp"
OFC_ZMQ = "ofc_zmq"
MLD_ZMQ = "mld_zmq"
OFC_SERVER_IP = "ofc_server_ip"
MLD_SERVER_IP = "mld_server_ip"
MLD_ESW_IFNAME = "mld_esw_ifname"
REGURALY_QUERY_INTERVAL = "reguraly_query_interval"
REGURALY_QUERY_TYPE = "reguraly_query_type"
MC_QUERY_INTERVAL = "mc_query_interval"
USER_TIME_OUT = "user_time_out"
C_TAG_ID = "c_tag_id"
DB_CONNECT_STR = "db_connect_str"

# =============================================================================
# multicast_info.jsonの定義
# =============================================================================
# マルチキャスト情報ファイル
MULTICAST_INFO = "multicast_info.json"
MC_TAG_MC_INFO = "mc_info"
MC_TAG_SERV_IP = "serv_ip"
MC_TAG_MC_ADDR = "mc_addr"
MC_TAG_MC_IVID = "ivid"
MC_TAG_MC_TYPE = "type"
MC_TAG_MC_PBB_ISID = "pbb_isid"

# =============================================================================
# bvid_variation.jsonの定義
# =============================================================================
# bvidのバリエーション定義ファイル
BVID_VARIATION = "bvid_variation.json"
BV_TAG_BV_INFO = "bvid_variation"
BV_TAG_KEY = "key"
BV_TAG_BVID = "bvid"

# =============================================================================
# switch_info.jsonの定義
# =============================================================================
# スイッチ情報ファイル
SWITCH_INFO = "switch_info.json"
# switch_mld_info
SW_TAG_MLD_INFO = "switch_mld_info"
SW_TAG_MLD_INFO_PBB_ISID = "pbb_isid"
SW_TAG_MLD_INFO_BVID = "bvid"
SW_TAG_MLD_INFO_IVID = "ivid"
# switch_mc_info
SW_TAG_MC_INFO = "switch_mc_info"
SW_TAG_MC_INFO_IVID = "ivid"
# switch_info common
SW_TAG_SWITCHES = "switches"
SW_TAG_DATAPATHID = "datapathid"
SW_TAG_TYPE = "sw_type"
SW_TYPE_12K = 12000
SW_TYPE_26K = 26000
SW_TAG_NAME = "sw_name"
SW_NAME_ESW = "esw"
SW_TAG_BMAC = "sw_bmac"
# switch_info edge
# common
SW_TAG_EDGE_ROUTER_PORT = "edge_router_port"
# Apresia12000k
SW_TAG_CONTEINER_PORTS = "container_sw_ports"
# Apresia26000k
SW_TAG_CONTEINER_PORT = "container_sw_port"
SW_TAG_FCRP_PORT = "fcrp_port"
SW_TAG_LAG = "lag"
SW_TAG_FCRP = "fcrp"
SW_TAG_PHYSICAL = "physical"
# switch_info container
SW_TAG_EDGE_SWITCH_PORT = "edge_switch_port"
SW_TAG_OLT_PORTS = "olt_ports"
