#!/usr/bin/python
# coding:utf-8

import user_manage
from pymongo import MongoClient

"""
class base_info():
    pass


class channel_info(base_info):
    def __init__(self, config=None):
        logger.debug("")
        # ch視聴情報を保存する
        #   key  : (マルチキャストアドレス, サーバのIP)
        #   value: {データパスID: channel_switch_info}
        self.channel_info = {}

        # channel_user_infoをtimeの昇順に保持するタイムアウト判定用リスト
        self.user_info_list = []

        # DBアクセサクラスのインスタンス生成
        connect_str = config.get(DB_CONNECT_STR)
        self.accessor = DatabaseAccessor(connect_str)

    def dump_self(self):
        return cPickle.dumps(self.channel_info)

    def update_ch_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        # 対象ユーザーが存在しない場合は追加、存在する場合は更新処理を呼び出す
        logger.debug("")

        user = self.exists_user(mc_addr, serv_ip, datapathid, port_no, cid)
        ret = None
        if not user:
            # 追加処理
            ret = self.add_ch_info(
                mc_addr, serv_ip, datapathid, port_no, cid)
        else:
            # 更新処理
            self.update_user_info(user)
            ret = mld_const.CON_REPLY_NOTHING
        # DBへ投入
        self.accessor.upsert("viewerdata", self)
        return ret

    def add_ch_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        # 視聴端末情報を追加
        logger.debug("")

        # チャンネル存在チェック
        if (mc_addr, serv_ip) not in self.channel_info:
            # 当該チャンネルが存在しない場合
            sw_info = channel_switch_info()
            sw_info.add_sw_info(mc_addr, serv_ip, datapathid, port_no, cid)
            self.channel_info[(mc_addr, serv_ip)] = {datapathid: sw_info}
            self.user_info_list.append(sw_info.port_info[port_no][cid])
            # エッジSW、収容SW両方へのFlowMod、およびエッジルータへのReport
            return mld_const.CON_REPLY_ADD_MC_GROUP

        # 収容SW(detapathid)存在チェック
        sw_info = self.channel_info[(mc_addr, serv_ip)]
        if datapathid not in sw_info:
            # 存在しない場合、既存チャンネル配下に新規収容SWの追加
            new_sw_info = channel_switch_info()
            new_sw_info.add_sw_info(
                mc_addr, serv_ip, datapathid, port_no, cid)
            sw_info[datapathid] = new_sw_info
            self.user_info_list.append(
                sw_info[datapathid].port_info[port_no][cid])
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_SWITCH

        # 当該チャンネルにこの収容SWの情報がある場合
        #   ポート情報及びユーザー情報を追加
        ch_sw_info = sw_info[datapathid]
        ret = ch_sw_info.add_sw_info(
            mc_addr, serv_ip, datapathid, port_no, cid)
        self.user_info_list.append(ch_sw_info.port_info[port_no][cid])
        return ret

    def update_user_info(self, ch_user_info):
        # 引数のchannel_user_infoのtimeを更新し、user_info_listに入れ直す
        logger.debug("")

        self.user_info_list.pop(self.user_info_list.index(ch_user_info))
        ch_user_info.time = time.time()
        self.user_info_list.append(ch_user_info)
        logger.debug("updated user_info")

    def remove_ch_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        # 視聴端末を削除
        logger.debug("")

        # 削除対象の存在チェック
        user = self.exists_user(mc_addr, serv_ip, datapathid, port_no, cid)
        if not user:
            # 存在しなければ何もしない
            logger.debug("remove target is nothing.")
            return None

        # ポート以下の情報を削除
        ch_sw_info = self.channel_info[(mc_addr, serv_ip)][datapathid]
        ret = ch_sw_info.remove_sw_info(port_no, cid)

        # ポートの削除を行い、ポート配下の視聴ユーザが0になった場合
        if ret == mld_const.CON_REPLY_DEL_PORT \
                and len(ch_sw_info.port_info) == 0:

            # 収容SW(datapathid)に対応する情報を削除する
            self.channel_info[(mc_addr, serv_ip)].pop(datapathid)
            logger.debug("removed datapath : %s",  datapathid)
            ret = mld_const.CON_REPLY_DEL_SWITCH

            # 当該mcグループの視聴ユーザが0になった場合、mcグループに対応する情報を削除する
            if len(self.channel_info[(mc_addr, serv_ip)]) == 0:
                self.channel_info.pop((mc_addr, serv_ip))
                ret = mld_const.CON_REPLY_DEL_MC_GROUP

        # user_info_listから対象ユーザーを削除する
        self.user_info_list.pop(self.user_info_list.index(user))
        # DBへ投入
        self.accessor.upsert("viewerdata", self)
        return ret

    def exists_user(self, mc_addr, serv_ip, datapathid, port_no, cid):
        # channel_infoから指定されたcidまでを持つchannel_user_infoを返却
        # 存在しない場合はNoneを返却
        logger.debug("")

        if (mc_addr, serv_ip) in self.channel_info:
            logger.debug("hit mc_addr, serv_ip : %s, %s", mc_addr, serv_ip)
            sw_info = self.channel_info[(mc_addr, serv_ip)]
            if datapathid in sw_info:
                logger.debug("hit datapathid : %s", datapathid)
                sw_info = sw_info[datapathid]
                if port_no in sw_info.port_info:
                    logger.debug("hit port_no : %s", port_no)
                    user_info = sw_info.port_info[port_no]
                    if cid in user_info:
                        logger.debug("hit cid : %s", cid)
                        logger.debug("user exists")
                        return user_info[cid]

        logger.debug("user does not exist")
        return None

    def find_insert_point(self, target_user):
        # timeでソート済みのユーザーリストから対象ユーザーを挿入すべき場所を返却
        logger.debug("")

        idx = bisect.bisect_left(self.user_info_list, target_user)
        logger.debug("idx : %d", idx)
        return idx

    def get_channel_info(self):
        # channel_infoの内容をStringで返却。（DEBUG用）

        info = "{\n"
        for key in self.channel_info.keys():
            info += "  multicast address : (%s, %s)\n" % (key[0], key[1])
            info += "  switches : [\n"
            switch_info = self.channel_info[key]
            for datapath in switch_info.keys():
                info += "    datapathid : %s\n" % datapath
                info += "    ports : [\n"
                sw_info = switch_info[datapath]
                info += sw_info.get_switch_info()
            info += "  ]\n"
        info += "}"
        return info

    def get_user_info_list(self):
        # user_info_listの内容をStringで返却。（DEBUG用）

        info = "\n"
        for user in self.user_info_list:
            info += user.get_user_info()
        return info


class channel_switch_info(base_info):
    def __init__(self):
        logger.debug("")
        # SW配下のポートの視聴情報を保存する
        #   key  : port_no
        #   value: {cid: channel_user_info}
        self.port_info = {}

    def add_sw_info(self, mc_addr, serv_ip, datapathid, port_no, cid):
        # port_infoにユーザ情報を追加
        logger.debug("")
        logger.debug("port_no, cid : %s, %s", str(port_no), str(cid))

        if port_no not in self.port_info:
            # 当該ポートに視聴ユーザが存在しない場合
            ch_user_info = channel_user_info(
                mc_addr, serv_ip, datapathid, port_no, cid, time.time())
            self.port_info[port_no] = {cid: ch_user_info}
            # 収容SWへのFlowMod
            return mld_const.CON_REPLY_ADD_PORT
        else:
            # 当該ポートに視聴ユーザが存在する場合
            # 当該CIDが存在しない場合はCIDを追加
            new_user_info = channel_user_info(
                mc_addr, serv_ip, datapathid, port_no, cid, time.time())
            self.port_info[port_no][cid] = new_user_info

            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

    def remove_sw_info(self, port_no, cid):
        # port_infoからユーザ情報を削除
        logger.debug("")

        # port_infoから当該ユーザ情報を検索し削除
        self.port_info[port_no].pop(cid)
        logger.debug("removed user[cid : %s]", cid)
        if len(self.port_info[port_no]) == 0:
            # ポート配下のユーザが0になればポート情報も削除
            self.port_info.pop(port_no)
            # 収容SWへのFlowModが必要
            return mld_const.CON_REPLY_DEL_PORT
        else:
            # FlowMod必要なし
            return mld_const.CON_REPLY_NOTHING

    def get_switch_info(self):
        # port_infoの内容をStringで返却。（DEBUG用）

        info = ""
        for port in self.port_info.keys():
            info += "      port : %s\n" % port
            info += "      users : [\n"
            user_info = self.port_info[port]
            for cid in user_info.keys():
                ch_user_info = user_info[cid]
                info += ch_user_info.get_user_info()
        info += "    ]\n"
        return info


@total_ordering
class channel_user_info(base_info):
    def __init__(self, mc_addr, serv_ip, datapathid, port_no, cid, time):
        logger.debug("")
        self.mc_addr = mc_addr
        self.serv_ip = serv_ip
        self.datapathid = datapathid
        self.port_no = port_no
        self.cid = cid
        self.time = time

    def get_user_info(self):
        # user_infoの内容をStringで返却。（DEBUG用）
        info = ""
        info += "        {\n"
#        info += "          mc_addr : %s\n" % self.mc_addr
#        info += "          serv_ip : %s\n" % self.serv_ip
#        info += "          datapathid : %s\n" % self.datapathid
#        info += "          port_no : %s\n" % self.port_no
        info += "          cid : %s\n" % self.cid
        info += "          time : %f\n" % self.time
        info += "        }\n"
        return info

    def __eq__(self, other):
        return (self.time == other.time)

    def __lt__(self, other):
        return (self.time < other.time)


# 動作確認用
# if __name__ == "__main__":
#    ch_info = channel_info()
#
#    # add
#    logger.debug("**** <1>")
#    ch_info.update_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    logger.debug("")
#    logger.debug("**** <1> add cid 100")
#    ch_info.update_ch_info("ff38::1:1", "2001::1:20", 1, 1, 100)
#    logger.debug("")
#    logger.debug("**** <1> add port 2")
#    ch_info.update_ch_info("ff38::1:1", "2001::1:20", 1, 2, 120)
#    logger.debug("")
#    logger.debug("**** <1> add datapath 2")
#    ch_info.update_ch_info("ff38::1:1", "2001::1:20", 2, 1, 210)
#    logger.debug("")
#    logger.debug("**** <2>")
#    ch_info.update_ch_info("ff38::1:2", "2001::1:20", 1, 1, 111)
#    logger.debug(ch_info.get_channel_info())
#    logger.debug(ch_info.get_user_info_list())
#
#    # update
#    logger.debug("")
#    logger.debug("**** <1> update cid 111")
#    ch_info.update_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    logger.debug("")
#    logger.debug(ch_info.get_channel_info())
#    logger.debug(ch_info.get_user_info_list())
#
#    # remove
#    logger.debug("")
#    logger.debug("**** remove <1> cid 111")
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 1, 111)
#    logger.debug("")
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 1, 100)
#    logger.debug("")
#    logger.debug("**** remove <1> datapath 2")
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 2, 1, 210)
#    logger.debug("")
#    logger.debug("**** remove <1> port 2")
#    ch_info.remove_ch_info("ff38::1:1", "2001::1:20", 1, 2, 120)
#    logger.debug("")
#    logger.debug("**** remove <2>")
#    ch_info.remove_ch_info("ff38::1:2", "2001::1:20", 1, 1, 111)
#    logger.debug(ch_info.get_channel_info())
#    logger.debug(ch_info.get_user_info_list())

class DatabaseAccessor:
    def __init__(self, connect_str):
        self.client = None
        if not connect_str:
            return
        self.client = MongoClient(connect_str)
        # DB名:viewerdb、コレクション名:serialized_data
        self.db = self.client.viewerdb
        self.col = self.db.serialized_data

    def upsert(self, key, inserted_obj):
        if not self.client:
            return
        # 投入対象オブジェクトをdumpしてそのまま投入
        dump = inserted_obj.dump_self()
        self.col.update({"ch": "all"}, {"$set": {key: dump}}, upsert=True)

    def query(self, key):
        if not self.client:
            return None
        result = self.col.find_one()
        dump = result[key]
        return cPickle.loads(dump)

"""

if '__main__' == __name__:
    # open mongodb
    client = MongoClient("mongodb://localhost:27017")
    db = client.viewerdb
    col = db.serialized_data

    # query
    result = col.find_one({"ch": "all"})
    dump_result = result["viewerdata"]
    load_result = cpickle.loads(dump_result)

    # check
    logger.debug(load_result)
