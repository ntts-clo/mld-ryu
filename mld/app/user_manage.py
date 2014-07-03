#!/usr/bin/python
# coding:utf-8

import cPickle
import bisect
import sys
sys.path.append('../../common')
import mld_const
#from pymongo import MongoClient


class BaseInfo():
    def dump_self(self):
        return cPickle.dumps(self)


class ChannelInfo(BaseInfo):
    def __init__(self):
        print("ChannelInfo : __init__")
        # {["FF38::1:1", "2001:1::20"]: {"datapath1":ChannelSwitchInfoのインスタンス, ... } という形
        self.channel_info = {}
#        self.accessor = DatabaseAccessor()

    def add_info(self, mc_addr, serv_ip, data_path, port_no, cid):
        print("ChannelInfo : add_info(%s, %s, %s, %s, %s)" % 
               (mc_addr, serv_ip, str(data_path), str(port_no), str(cid)))
        print("self.channel_info : %s" % self.channel_info)
        """
          視聴端末を追加。さらに、
            1. ch視聴ユーザが当該swにおける最初の視聴ユーザだった場合、エッジルータへ
               report(ADD_NEW_RESOURCESおよびCHANGE_TO_INCLUDE)を投げる。
               また、エッジSWおよび収容SWへFlowMod
            2. ch視聴ユーザが当該swの当該ポートにおける最初の視聴ユーザだった場合
               (他ポートには既存ユーザがいる)、収容SWへFlowMod
          FlowModは本関数の戻り値で返す？本関数内で送信までやりたくない。もっといえば
          FlowModの組み立ても本関数外でやりたい。BEサービスか品質保証かの判定も外で。
        """

        # チャンネル存在チェック
        if (mc_addr, serv_ip) not in self.channel_info:
            # 当該チャンネルが存在しない場合
            sw_info = ChannelSwitchInfo(data_path, port_no, cid)
            self.channel_info[(mc_addr, serv_ip)] = {data_path: sw_info}
            print("added self.channel_info : %s" % self.channel_info) 
            # エッジSW、収容SW両方へのFlowMod、およびエッジルータへのReport
            return mld_const.CON_REPLY_ADD_FLOW_MOD_AND_PACKET_OUT

        # 当該チャンネルが既に存在する場合
        # DataPath存在チェック
        sw_info = self.channel_info[(mc_addr, serv_ip)]
        if data_path not in sw_info:
            new_sw_info = ChannelSwitchInfo(data_path, port_no, cid)
            sw_info[data_path] = new_sw_info
            print("added self.channel_info : %s" % self.channel_info) 
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_FLOW_MOD

        # 当該チャンネルにこの収容SWの情報がある場合
        ch_sw_info = sw_info[data_path]  # ChannelSwitchInfoクラスのインスタンス
        print("added self.channel_info : %s" % self.channel_info) 
        return ch_sw_info.add_info(port_no, cid)

    def remove_info(self, mc_addr, serv_ip, data_path, port_no, cid):
        print("ChannelInfo : remove_info(%s, %s, %s, %s, %s)" % 
               (mc_addr, serv_ip, str(data_path), str(port_no), str(cid)))
        print("self.channel_info : %s" % self.channel_info)
        """
          視聴端末を削除。さらに、
            1. 当該sw、当該ポートの視聴ユーザが0になった場合、
               収容SWにFlowMod
            2. 当該swの視聴ユーザが0になった場合
               エッジSW、収容SWへFlowMod
               エッジルータへReport(BLOCK_OLD_SOURCES)を投げる
          FlowModは本関数の戻り値で返す？本関数内で送信までやりたくない。もっといえば
          FlowModの組み立ても本関数外でやりたい。BEサービスか品質保証かの判定も外で。
        """

        # チャンネルおよびDataPath存在チェック
        # 存在しなければ何もしない
        if (mc_addr, serv_ip) not in self.channel_info \
            or data_path not in self.channel_info[(mc_addr, serv_ip)]:
                print "remove target is nothing."
                # FlowModの必要なし
                return mld_const.CON_REPLY_NOTHING

        # 存在する場合
        ch_sw_info = self.channel_info[(mc_addr, serv_ip)][data_path]
        ret = ch_sw_info.remove_info(port_no, cid)
        if ret == mld_const.CON_REPLY_DEL_FLOW_MOD \
            and len(ch_sw_info.port_info.keys()) == 0:

            # 当該SWの視聴ユーザが0の場合、DataPathに対応する情報を削除する
            self.channel_info[(mc_addr, serv_ip)].pop(data_path)
            print("removed datapath : %s" % data_path) 
            print("removed self.channel_info[(mc_addr, serv_ip)] : %s" 
                   % self.channel_info[(mc_addr, serv_ip)]) 
            
            if len(self.channel_info[(mc_addr, serv_ip)]) == 0:
                # 当該mcグループの視聴ユーザが0の場合、mcグループに対応する情報を削除する
                self.channel_info.pop((mc_addr, serv_ip))
                ret = mld_const.CON_REPLY_DEL_FLOW_MOD_AND_PACKET_OUT

        print("removed self.channel_info : %s" % self.channel_info) 
        return ret


class ChannelSwitchInfo(BaseInfo):
    def __init__(self, data_path, port_no=-1, cid=-1):
        print("ChannelSwitchInfo : __init__")
        self.data_path = data_path
        self.port_info = {}
        if cid != -1:
            self.port_info[port_no] = [cid]

    def add_info(self, port_no, cid):
        print("ChannelSwitchInfo : add_info(%s, %s)" % (str(port_no), str(cid)))
        print("self.port_info : %s" % self.port_info)
        # port_infoにユーザ情報を追加
        if port_no in self.port_info:
            # 当該ポートに視聴ユーザが存在する場合
            # 当該CIDが存在しない場合はCIDを追加
            # ソートを維持して挿入しておく(探索時にbinary searchを使いたい)
            cid_list = self.port_info[port_no]
            if self.find(cid_list, cid) == -1:
                pos = bisect.bisect(cid_list, cid)
                bisect.insort(cid_list, cid)
            # Todo: 既にCIDが存在する場合に無視する処理でよいか精査
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING
        else:
            # 当該ポートに視聴ユーザが存在しない場合
            self.port_info[port_no] = [cid]
            print("added self.port_info : %s" % self.port_info)
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_FLOW_MOD

    def remove_info(self, port_no, cid):
        print("ChannelSwitchInfo : remove_info(%s, %s)" % (str(port_no), str(cid)))
        print("self.port_info : %s" % self.port_info)
        # port_infoから当該ユーザ情報を検索し削除
        # ch_infoを更新
        #   当該chを視聴しているユーザがいなくなった場合
        if port_no not in self.port_info:
            # 当該ポートにユーザがそもそも存在しない場合
            # 何もせず抜ける Todo: 本当にそれでよいか精査
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

        # 当該ポートにユーザが存在する場合
        # cidを探索し、存在すれば削除
        # ユーザが0になればポート情報も削除
        cid_list = self.port_info[port_no]
        idx = self.find(cid_list, cid)
        if idx == -1:
            # 指定されたCIDが存在しなければ何もせず抜ける Todo: 本当にそれでよいか精査
            print "remove target is nothing."
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

        cid_list.pop(idx)
        if len(cid_list) == 0:
            self.port_info.pop(port_no)
            print("removed self.port_info : %s" % self.port_info)
            print("removed cid_list : %s, return 1" % cid_list)
            # 収容SWへのFlowModが必要
            return mld_const.CON_REPLY_DEL_FLOW_MOD

    """
    ソート済み配列からキー値を探索
    arrayはソート済みであること
    Todo: 共通クラスに移動すべきか検討
    """
    def find(self, array, value):
        idx = bisect.bisect_left(array, value)
        if idx != len(array) and array[idx] == value:
            return idx
        return -1

"""
class DatabaseAccessor:
    def __init__(self, connect_str):
        self.client = MongoClient(connect_str)
        # Todo: DB名、コレクション名は別途検討
        self.db = self.client.viewerdb
        self.col = self.db.serialized_data

    def insert(self, key, inserted_obj):
        # Todo: DB上のデータ形式は別途検討
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
    print a.int
    print b.int

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
    print load_result.int
    print load_result.float
    print load_result.dict["key1"].str
    print load_result.dict["key2"].str
"""
