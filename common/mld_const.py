# coding: utf-8

# ryu -> mld
CON_SWITCH_FEATURE = 11
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

# ログファイル用定数
LOG_CONF = "logconf.ini"
# 設定ファイル用定数
CONF_FILE = "config.json"
