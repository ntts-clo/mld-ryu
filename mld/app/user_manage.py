#!/usr/bin/python
# coding:utf-8

import cPickle
import bisect
import logging
import logging.config
import sys
import time
sys.path.append('../../common')
import mld_const
# from pymongo import MongoClient

logging.config.fileConfig("../../common/logconf.ini")
# logger = logging.getLogger("channel_info")
logger = logging.getLogger(__name__)


class base_info():
    def dump_self(self):
        return cPickle.dumps(self)


class channel_info(base_info):
    def __init__(self):
        logger.debug("")
        # {["FF38::1:1", "2001:1::20"]: {"datapath1":channel_switch_infoのインスタンス, ... } という形
        self.channel_info = {}
#        self.accessor = DatabaseAccessor()

    def add_ch_info(self, mc_addr, serv_ip, detapathid, port_no, cid):
        logger.debug(
            "mc_addr, serv_ip, detapathid, port_no, cid : %s, %s, %s, %s, %s",
             mc_addr, serv_ip, str(detapathid), str(port_no), str(cid))
        logger.debug("self.channel_info : %s", self.get_channel_info())
        """
          視聴端末を追加。さらに、
            1. ch視聴ユーザが当該swにおける最初の視聴ユーザだった場合、エッジルータへ
               report(ADD_NEW_RESOURCESおよびCHANGE_TO_INCLUDE)を投げる。
               また、エッジSWおよび収容SWへFlowMod
            2. ch視聴ユーザが当該swの当該ポートにおける最初の視聴ユーザだった場合
               (他ポートには既存ユーザがいる)、収容SWへFlowMod
        """

        # チャンネル存在チェック
        if (mc_addr, serv_ip) not in self.channel_info:
            # 当該チャンネルが存在しない場合
            sw_info = channel_switch_info(port_no, cid)
            self.channel_info[(mc_addr, serv_ip)] = {detapathid: sw_info}
            logger.debug("added self.channel_info : %s",
                         self.get_channel_info())
            user_info = sw_info[detapathid][port_no][0]
            # エッジSW、収容SW両方へのFlowMod、およびエッジルータへのReport
            return mld_const.CON_REPLY_ADD_MC_GROUP

        # 当該チャンネルが既に存在する場合
        # DataPath存在チェック
        sw_info = self.channel_info[(mc_addr, serv_ip)]
        if detapathid not in sw_info:
            new_sw_info = channel_switch_info(port_no, cid)
            sw_info[detapathid] = new_sw_info
            logger.debug("added self.channel_info : %s",
                         self.get_channel_info())
            user_info = new_sw_info[detapathid][port_no][0]
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_SWITCH

        # 当該チャンネルにこの収容SWの情報がある場合
        ch_sw_info = sw_info[detapathid]  # channel_switch_infoクラスのインスタンス
        ret = ch_sw_info.add_sw_info(port_no, cid)
        logger.debug("added self.channel_info : %s",
                     self.get_channel_info())
        user_info_list = ch_sw_info[port_no]
        for user_info in user_info_list:
            if cid == user_info.cid:
        return ret

    def remove_ch_info(self, mc_addr, serv_ip, detapathid, port_no, cid):
        logger.debug(
            "mc_addr, serv_ip, detapathid, port_no, cid : %s, %s, %s, %s, %s",
             mc_addr, serv_ip, str(detapathid), str(port_no), str(cid))
        logger.debug("self.channel_info : %s", self.get_channel_info())
        """
          視聴端末を削除。さらに、
            1. 当該sw、当該ポートの視聴ユーザが0になった場合、
               収容SWにFlowMod
            2. 当該swの視聴ユーザが0になった場合
               エッジSW、収容SWへFlowMod
               エッジルータへReport(BLOCK_OLD_SOURCES)を投げる
        """

        # チャンネルおよびDataPath存在チェック
        # 存在しなければ何もしない
        if (mc_addr, serv_ip) not in self.channel_info \
                or detapathid not in self.channel_info[(mc_addr, serv_ip)]:
            logger.debug("remove target is nothing.")
            # FlowModの必要なし
            return mld_const.CON_REPLY_NOTHING

        # 存在する場合
        ch_sw_info = self.channel_info[(mc_addr, serv_ip)][detapathid]
        ret = ch_sw_info.remove_sw_info(port_no, cid)
        if ret == mld_const.CON_REPLY_DEL_PORT \
                and len(ch_sw_info.port_info.keys()) == 0:

            # 当該SWの視聴ユーザが0の場合、DataPathに対応する情報を削除する
            self.channel_info[(mc_addr, serv_ip)].pop(detapathid)
            logger.debug("removed datapath : %s",  detapathid)
            ret = mld_const.CON_DEL_SWITCH

            if len(self.channel_info[(mc_addr, serv_ip)]) == 0:
                # 当該mcグループの視聴ユーザが0の場合、mcグループに対応する情報を削除する
                self.channel_info.pop((mc_addr, serv_ip))
                ret = mld_const.CON_REPLY_DEL_MC_GROUP

        logger.debug("removed self.channel_info : %s",
                     self.get_channel_info())
        return ret

    def exsits_user(self, mc_addr, serv_ip, detapathid, port_no, cid):
        logger.debug("")
        if (mc_addr, serv_ip) in self.channel_info:
            sw_info = self.channel_info[(mc_addr, serv_ip)]
            if detapathid in sw_info:
                port_info = sw_info[detapathid]
                if port_no in port_info:
                    user_list = port_info[port_no]
                    if cid in [user.cid for user in user_list]:
                        return True
        return False

    def get_channel_info(self):
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
#        logger.debug(info)
        return info


class channel_switch_info(base_info):
    def __init__(self, port_no=None, cid=None):
        logger.debug("")
        self.port_info = {}
        if not port_no == None and not cid == None:
            self.port_info[port_no] = [channel_user_info(cid, time.time())]

    def add_sw_info(self, port_no, cid):
        logger.debug("port_no, cid : %s, %s", str(port_no), str(cid))
        logger.debug("self.port_info : %s", self.get_switch_info())
        # port_infoにユーザ情報を追加
        if port_no not in self.port_info:
            # 当該ポートに視聴ユーザが存在しない場合
            self.port_info[port_no] = [channel_user_info(cid, time.time())]
            logger.debug("added self.port_info : %s", self.get_switch_info())
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_PORT
        else:
            # 当該ポートに視聴ユーザが存在する場合
            # 当該CIDが存在しない場合はCIDを追加
            # ソートを維持して挿入しておく(探索時にbinary searchを使いたい)
            user_list = self.port_info[port_no]
            cid_list = [user.cid for user in user_list]
            if self.find(cid_list, cid) == -1:
                # CIDの追加
                self.port_info[port_no].append(
                    channel_user_info(cid, time.time()))
                # TODO オブジェクトに対し使用できるか確認
                """
                pos = bisect.bisect(cid_list, cid)
                bisect.insort(cid_list, cid)
                """
            # TODO: 既にCIDが存在する場合に無視する処理でよいか精査
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

    def remove_sw_info(self, port_no, cid):
        logger.debug("%s, %s", str(port_no), str(cid))
        logger.debug("self.port_info : %s", self.get_switch_info())
        # port_infoから当該ユーザ情報を検索し削除
        # ch_infoを更新
        #   当該chを視聴しているユーザがいなくなった場合
        if port_no not in self.port_info:
            # 当該ポートにユーザがそもそも存在しない場合
            # 何もせず抜ける TODO: 本当にそれでよいか精査
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

        # 当該ポートにユーザが存在する場合
        # cidを探索し、存在すれば削除
        # ユーザが0になればポート情報も削除
        user_list = self.port_info[port_no]
        cid_list = [user.cid for user in user_list]
        logger.debug("cid_list : %s", str(cid_list))
        idx = self.find(cid_list, cid)
        if idx == -1:
            # 指定されたCIDが存在しなければ何もせず抜ける TODO: 本当にそれでよいか精査
            logger.debug("remove target is nothing.")
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

        user_list.pop(idx)
        if len(user_list) == 0:
            self.port_info.pop(port_no)
            logger.debug("removed self.port_info : %s",
                         self.get_switch_info())
            logger.debug("removed cid_list : %s, return 1", cid_list)
            # 収容SWへのFlowModが必要
            return mld_const.CON_REPLY_DEL_PORT
        else:
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

    """
    ソート済み配列からキー値を探索
    arrayはソート済みであること
    TODO: 共通クラスに移動すべきか検討
    """
    def find(self, array, value):
        logger.debug("")
        idx = bisect.bisect_left(array, value)
        if idx != len(array) and array[idx] == value:
            return idx
        return -1

    def get_switch_info(self):
        info = ""
        for port in self.port_info.keys():
            info += "      port : %s\n" % port
            info += "      users : [\n"
            user_info = self.port_info[port]
            for ch_user_info in user_info:
                info += ch_user_info.get_user_info()
        info += "    ]\n"
        return info

class channel_user_info(base_info):
    def __init__(self, cid, time):
        logger.debug("")
        self.cid = cid
        self.time = time
        logger.debug("created user_info : cid:%s, time:%d", cid, time)

    def get_user_info(self):
        info = ""
        info += "        cid  : %s\n" % self.cid
        info += "        time : %f\n" % self.time
        return info


if __name__ == "__main__":
    print "**** init"
    ch_info = channel_info()
    print "**** <1>"
    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 1, 1, 110)
    print
    print "**** <1> add cid"
    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    print
#    print "**** <1> add port"
#    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 1, 2, 120)
#    print
#    print "**** <1> add datapath"
#    ch_info.add_ch_info("ff38::1:1", "2001::1:20", 2, 1, 210)
#    print
#    print "**** <2>"
#    ch_info.add_ch_info("ff38::1:2", "2001::1:20", 1, 1, 1110)
#    ch_info.get_channel_info()
#    print
#    print "**** remove <1> cid 111"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    print
#    print "**** remove <1> datapath 2"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 2, 1, 210)
#    print
#    print "**** remove <1> port 1"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 1, 110)
#    print
#    print "**** remove <1> port 2"
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 2, 120)
#    print
#    print "**** remove <2>"
#    ch_info.remove_ch_info("ff38::1:2", "2001::1:20", 1, 1, 1110)

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
