#!/usr/bin/python
# coding:utf-8

# import cPickle
import bisect
import logging
import logging.config
import sys
import time
from functools import total_ordering
sys.path.append('../../common')
import mld_const
# from pymongo import MongoClient

logging.config.fileConfig("../../common/logconf.ini")
logger = logging.getLogger(__name__)


class base_info(object):
    # {(マルチキャストアドレス, サーバのIP): {データパスID: channel_switch_info}
    channel_info = {}
    # [channel_user_info]
    user_info_list = []

#    def dump_self(self):
#        return cPickle.dumps(self)

    def exists_user(self, mc_addr, serv_ip, datapathid, port_no, cid):
        logger.debug("")
        logger.debug(
            "mc_addr, serv_ip, datapathid, port_no, cid : %s, %s, %s, %s, %s",
            mc_addr, serv_ip, datapathid, port_no, cid)
        """
            channel_infoから指定されたcidまでを持つchannel_user_infoを返却
            存在しない場合はNoneを返却
        """
        if (mc_addr, serv_ip) in self.channel_info:
            sw_info = self.channel_info[(mc_addr, serv_ip)]
            if datapathid in sw_info:
                port_info = sw_info[datapathid]
                if port_no in port_info.port_info:
                    user_list = port_info[port_no]
                    for user in user_list:
                        if cid == user.cid:
                            logger.debug("found user")
                            return user

        logger.debug("user not found")
        return None

    def find(self, array, value, index_find=False):
        """
            ソート済み配列からキー値を探索(arrayはソート済みであること)
            index_find == True  の場合は挿入するべきインデックスを返却する
            index_find == False の場合は対象が存在するインデックスを返却する（存在しない場合は-1）
        """
        logger.debug("")
        idx = bisect.bisect_left(array, value)
        logger.debug("idx : %d", idx)
        if index_find:
            return idx
        if idx != len(array) and array[idx] == value:
            logger.debug("found. idx : %d", idx)
            return idx
        logger.debug("not found. return -1")
        return -1


class channel_info(base_info):
    def __init__(self):
        logger.debug("")
#        self.accessor = DatabaseAccessor()

    def __getitem__(self, key):
        return self.channel_info[key]

    def add_ch_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        logger.debug("")
        logger.debug(
            "mc_addr, serv_ip, datapathid, port_no, cid : %s, %s, %s, %s, %s",
            mc_addr, serv_ip, str(datapathid), str(port_no), str(cid))
        logger.debug("self.channel_info : %s", self.get_channel_info())
        """
          視聴端末を追加。さらに、
            1. ch視聴ユーザが当該swにおける最初の視聴ユーザだった場合、エッジルータへ
               report(ADD_NEW_RESOURCESおよびCHANGE_TO_INCLUDE)を投げる。
               また、エッジSWおよび収容SWへFlowMod
            2. ch視聴ユーザが当該swの当該ポートにおける最初の視聴ユーザだった場合
               (他ポートには既存ユーザがいる)、収容SWへFlowMod
        """

        # 既に対象ユーザが存在する場合
        if self.exists_user(mc_addr, serv_ip, datapathid, port_no, cid):
            logger.debug("the user already exists.")
            return mld_const.CON_REPLY_NOTHING

        # チャンネル存在チェック
        if (mc_addr, serv_ip) not in self.channel_info:
            # 当該チャンネルが存在しない場合
            sw_info = channel_switch_info()
            sw_info.add_sw_info(mc_addr, serv_ip, datapathid, port_no, cid)
            self.channel_info[(mc_addr, serv_ip)] = {datapathid: sw_info}
            logger.debug("added self.channel_info : %s",
                         self.get_channel_info())
            self.user_info_list.append(sw_info.port_info[port_no][-1])
            # エッジSW、収容SW両方へのFlowMod、およびエッジルータへのReport
            return mld_const.CON_REPLY_ADD_MC_GROUP

        # 当該チャンネルが既に存在する場合
        # DataPath存在チェック
        sw_info = self.channel_info[(mc_addr, serv_ip)]
        if datapathid not in sw_info:
            new_sw_info = channel_switch_info()
            new_sw_info.add_sw_info(
                mc_addr, serv_ip, datapathid, port_no, cid)
            sw_info[datapathid] = new_sw_info
            logger.debug("added self.channel_info : %s",
                         self.get_channel_info())
            self.user_info_list.append(
                sw_info[datapathid].port_info[port_no][-1])
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_SWITCH

        # 当該チャンネルにこの収容SWの情報がある場合
        ch_sw_info = sw_info[datapathid]
        ret = ch_sw_info.add_sw_info(
            mc_addr, serv_ip, datapathid, port_no, cid)
        self.user_info_list.append(ch_sw_info.port_info[port_no][-1])
        logger.debug("added self.channel_info : \n%s",
                     self.get_channel_info())
        return ret

    def remove_ch_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        logger.debug("")
        """
          視聴端末を削除。さらに、
            1. 当該sw、当該ポートの視聴ユーザが0になった場合、
               収容SWにFlowMod
            2. 当該swの視聴ユーザが0になった場合
               エッジSW、収容SWへFlowMod
               エッジルータへReport(BLOCK_OLD_SOURCES)を投げる
        """

        # チャンネルおよびDataPath存在チェック
        if (mc_addr, serv_ip) not in self.channel_info \
                or datapathid not in self.channel_info[(mc_addr, serv_ip)]:
            # 存在しなければ何もしない
            logger.debug("remove target is nothing.")
            # FlowModの必要なし
            return mld_const.CON_REPLY_NOTHING

        # 存在する場合
        ch_sw_info = self.channel_info[(mc_addr, serv_ip)][datapathid]
        # ポート以下の情報を削除
        ret = ch_sw_info.remove_sw_info(
            mc_addr, serv_ip, datapathid, port_no, cid)
        if ret == mld_const.CON_REPLY_DEL_PORT \
                and len(ch_sw_info.port_info.keys()) == 0:

            # 当該SWの視聴ユーザが0の場合、DataPathに対応する情報を削除する
            self.channel_info[(mc_addr, serv_ip)].pop(datapathid)
            logger.debug("removed datapath : %s",  datapathid)
            ret = mld_const.CON_REPLY_DEL_SWITCH

            # 当該mcグループの視聴ユーザが0になった場合、mcグループに対応する情報を削除する
            if len(self.channel_info[(mc_addr, serv_ip)]) == 0:
                self.channel_info.pop((mc_addr, serv_ip))
                ret = mld_const.CON_REPLY_DEL_MC_GROUP

        logger.debug("removed self.channel_info : %s",
                     self.get_channel_info())
        return ret

    def update_user_info_list(
            self, mc_addr, serv_ip, datapathid, port_no, cid):
        logger.debug("")
        """
            引数のcidまでを持つchannel_user_infoを取得し、
            存在する場合、対象のtimeを更新し、user_info_listに入れ直す
        """
        user = self.exists_user(
            mc_addr, serv_ip, datapathid, port_no, cid)
        if user:
            # user_info_listから一度削除し、更新後に最後尾に追加
            self.user_info_list.pop(
                self.user_info_list.index(user))
            user.update_time(
                mc_addr, serv_ip, datapathid, port_no, cid, time.time())
            self.user_info_list.append(user)

    def get_channel_info(self):
        """
            channel_infoの内容をStringで返却。（DEBUG用）
        """
        info = "{\n"
        for key in self.channel_info.keys():
            info += "  multicast address : (%s, %s)\n" % (key[0], key[1])
            info += "  switches : [\n"
            switch_info = self.channel_info[key]
            for datapath in switch_info.keys():
                info += "    datapath : %s\n" % datapath
                info += "    ports : [\n"
                sw_info = switch_info[datapath]
                info += sw_info.get_switch_info()
            info += "  ]\n"
        info += "}"
        return info

    def get_user_info_list(self):
        """
            user_info_listの内容をStringで返却。（DEBUG用）
        """
        info = "\n"
        for user in self.user_info_list:
            for user_keys in user.user_info.keys():
                info += "        {\n"
                info += "          keys : %s\n" % str(user_keys)
                info += "          time : %f\n" % user[user_keys]
                info += "        }\n"
        return info


class channel_switch_info(base_info):
    def __init__(self):
        logger.debug("")
        self.port_info = {}

    def __getitem__(self, key):
        return self.port_info[key]

    def add_sw_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        logger.debug("port_no, cid : %s, %s", str(port_no), str(cid))

        # port_infoにユーザ情報を追加
        if port_no not in self.port_info:
            # 当該ポートに視聴ユーザが存在しない場合
            self.port_info[port_no] = [channel_user_info(
                mc_addr, serv_ip, datapathid, port_no, cid, time.time())]
            logger.debug("added self.port_info : \n%s",
                         self.get_switch_info())
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_PORT
        else:
            # 当該ポートに視聴ユーザが存在する場合
            # 当該CIDが存在しない場合はCIDを追加
            # ソートを維持して挿入しておく
            user = self.exists_user(
                mc_addr, serv_ip, datapathid, port_no, cid)
            if not user:
                # CIDの追加
                bisect.insort(self.port_info[port_no], channel_user_info(
                    mc_addr, serv_ip, datapathid, port_no, cid, time.time()))
            else:
                # 既にCIDが存在する場合はtimeを更新
                # user_info_listから一度削除し、更新後に最後尾に追加
                self.user_info_list.pop(
                    self.user_info_list.index(user))
                user.update_time(
                    mc_addr, serv_ip, datapathid, port_no, cid, time.time())
                self.user_info_list.append(user)

                # FlowMod必要なし
                return mld_const.CON_REPLY_NOTHING

    def remove_sw_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        logger.debug("port_no, cid : %s, %s", str(port_no), str(cid))
        logger.debug("self.port_info : \n%s", self.get_switch_info())
        # port_infoから当該ユーザ情報を検索し削除
        # ch_infoを更新
        #   当該chを視聴しているユーザがいなくなった場合
        if port_no not in self.port_info:
            # 当該ポートにユーザがそもそも存在しない場合
            # 何もせず抜ける
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

        # 当該ポートにユーザが存在する場合
        # cidを探索し、存在すれば削除
        # ユーザが0になればポート情報も削除
        user_list = self.port_info[port_no]
        user = self.exists_user(mc_addr, serv_ip, datapathid, port_no, cid)
        if not user:
            # 指定されたCIDが存在しなければ何もせず抜ける
            logger.debug("remove target is nothing.")
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

        # ユーザ情報の削除
        idx = self.find(self.user_info_list, user)
        if not idx == -1:
            self.user_info_list.pop(idx)
            logger.debug("removed user_info_list[cid : %s]", cid)
        user_list.pop(user_list.index(user))
        logger.debug("removed user[cid : %s]", cid)
        if len(user_list) == 0:
            # ポート情報の削除
            self.port_info.pop(port_no)
            logger.debug("removed self.port_info : \n%s",
                         self.get_switch_info())
            # 収容SWへのFlowModが必要
            return mld_const.CON_REPLY_DEL_PORT
        else:
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

    def get_switch_info(self):
        info = ""
        for port in self.port_info.keys():
            info += "      port : %s\n" % port
            info += "      users : [\n"
            user_info = self.port_info[port]
            for ch_user_info in user_info:
                info += ch_user_info.get_user_info_list()
        info += "    ]\n"
        return info


@total_ordering
class channel_user_info(base_info):
    def __init__(self, mc_addr, serv_ip, datapathid, port_no, cid, time):
        logger.debug("")
        self.user_info = {}
        self.user_info[(mc_addr, serv_ip, datapathid, port_no, cid)] = time
        self.cid = cid
        self.time = time

    def __getitem__(self, key):
        return self.user_info[key]

    def update_time(self, mc_addr, serv_ip, datapathid, port_no, cid, time):
        logger.debug("")
        self.user_info[mc_addr, serv_ip, datapathid, port_no, cid] = time
        self.time = time

    def get_user_info_list(self):
        info = ""
        for user_keys in self.user_info.keys():
            info += "        {\n"
            info += "          keys : %s\n" % str(user_keys)
            info += "          time : %f\n" % self.user_info[user_keys]
            info += "        }\n"
        return info

    def __eq__(self, other):
        return (self.user_info.values() == other.user_info.values())

    def __lt__(self, other):
        return (self.user_info.values() < other.user_info.values())


# DEBUG
if __name__ == "__main__":
    ch_info = channel_info()
#    print "**** init"
#
#    # add
#    print "**** <1>"
#    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    print
#    print "**** <1> add cid 100"
#    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 1, 1, 100)
#    print ch_info.get_user_info_list()
#    print
#    print "**** <1> add port 2"
#    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 1, 2, 120)
#    print
#    print "**** <1> add datapath 2"
#    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 2, 1, 210)
#    print
#    print "**** <2>"
#    ch_info.add_ch_info("ff38::1:2", "2001::1:20", 1, 1, 1110)
#    print ch_info.get_user_info_list()
#    print
#
#    # update
#    print "**** <1> update cid 111"
#    ch_info.update_user_info_list("ff38::1:1", "2001::1:20", 1, 1, 111)
#    print
#    print ch_info.get_channel_info()
#    print ch_info.get_user_info_list()
#    print
#
#    # remove
#    print "**** remove <1> cid 111"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    print
#    print "**** remove <1> cid 100"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 1, 100)
#    print
#    print "**** remove <1> datapath 2"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 2, 1, 210)
#    print
#    print "**** remove <1> port 2"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 2, 120)
#    print
#    print "**** remove <2>"
#    ch_info.remove_ch_info("ff38::1:2", "2001::1:20", 1, 1, 1110)
#    print ch_info.get_user_info_list()

"""
class DatabaseAccessor:
    def __init__(self, connect_str):
        self.client = MongoClient(connect_str)
        # TODO: DB名、コレクション名は別途検討
        self.db = self.client.viewerdb
        self.col = self.db.serialized_data

    def insert(self, key, inserted_obj):
        # TODO: DB上のデータ形式は別途検討
        dump = inserted_obj.dump_self(inserted_obj)
        self.col.update({key: dump})

    def query(self, key):
        result = self.col.find_one()
        dump = result[key]
        return cPickle.loads(dump)
"""

"""
class UserInfo:
    def __init__(self, port_no=-1):
        self.port_no = port_no
        self.float = float
        self.array = [1, 2, "123"]
        self.dict = {"key1": page(), "key2": page(str="test")}

if '__main__' == __name__:
    a = hoge(int=5)
    b = hoge()
    b.int = 2
    logger.debug a.int
    logger.debug b.int

    # open mongodb
    client = MongoClient("mongodb://localhost:27017")
    db = client.testdb
    col = db.posts

    # serialize
    dump_a = cpickle.dumps(a)
    dump_b = cpickle.dumps(b)

    c = cpickle.loads(dump_a)

    # insert
    for i in range(0, 10000):
        dict_a = {"switch_name": "s1", "data": dump_a}
        col.update({"switch_name": "s1"}, \
                   {"$set": {"data": dump_a}}, \
                   upsert=True)

    # query
    result = col.find_one({"switch_name": "s1"})
    dump_result = result["data"]
    load_result = cpickle.loads(dump_result)

    # check
    logger.debug load_result.int
    logger.debug load_result.float
    logger.debug load_result.dict["key1"].str
    logger.debug load_result.dict["key2"].str
"""
