# coding: utf-8
# zmq install
#  >sudo apt-get install libzmq-dev
#  >sudo apt-get install python-zmq

from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan, packet
from ryu.lib import hub
from scapy import sendrecv
from scapy import packet as scapy_packet
from eventlet import patcher
from icmpv6_extend import icmpv6_extend
from user_manage import ChannelInfo
import os
import logging
import logging.config
import cPickle
import zmq
import sys
sys.path.append('../../common')
from zmq_dispatch import dispatch
from read_json import read_json
import mld_const
hub.patch()


# ======================================================================
# mld_process
# ======================================================================
class mld_process():

    IPC = "ipc://"
    SEND_PATH = "/tmp/feeds/mld-ryu"
    RECV_PATH = "/tmp/feeds/ryu-mld"
    IPC_PATH_SEND = IPC + SEND_PATH
    IPC_PATH_RECV = IPC + RECV_PATH

    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    addressinfo = []

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    def __init__(self):
        logging.config.fileConfig("../../common/logconf.ini")
        self.logger = logging.getLogger(__name__)
        self.logger.debug("")

        self.ch_info = ChannelInfo()

        # 設定情報読み込み
        config = read_json("../../common/config.json")
        self.logger.info("config_info : %s", str(config.data))
        self.config = config.data["settings"]
        self.WAIT_TIME = self.config["reguraly_query_interval"]

        for line in open(self.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    self.addressinfo.append(column)

        self.logger.info("addressinfo : %s", str(self.addressinfo))

        # スイッチ情報読み込み
        switches = read_json("../../common/switch_info.json")
        self.logger.info("switch_info : %s", str(switches.data))
        self.switches = switches.data["switches"]
        self.edge_switch = self.switches[0]
        self.switch1 = self.switches[1]
        self.switch2 = self.switches[2]

        # CHECK TMP FILE(SEND)
        self.check_exists_tmp(self.SEND_PATH)

        # CHECK TMP FILE(RECV)
        self.check_exists_tmp(self.RECV_PATH)
        
        ctx = zmq.Context()
        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(self.IPC_PATH_SEND)

        self.recv_sock = ctx.socket(zmq.SUB)
        self.recv_sock.connect(self.IPC_PATH_RECV)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")

    # ==================================================================
    # check_exists_tmp
    # ==================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug("")

        if os.path.exists(filename):
            return

        else:
            dirpath = os.path.dirname(filename)
            if os.path.isdir(dirpath):
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create file[%s]", filename)
            else:
                os.makedirs(dirpath)
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create dir[%s], file[%s]",
                                 dirpath, filename)

    # ==================================================================
    # send_mldquey_regularly
    # ==================================================================
    def send_mldquey_regularly(self):
        self.logger.debug("")

        if self.config["reguraly_query_type"] == "GQ":
            while True:
                mld = self.create_mldquery(("::", None))
                sendpkt = self.create_packet(self.addressinfo, mld)
                self.send_packet_to_sw(sendpkt)
                hub.sleep(self.WAIT_TIME)
        elif self.config["reguraly_query_type"] == "SQ":
            mc_service_info_list = []
            for line in open(self.MULTICAST_SERVICE_INFO, "r"):
                if line[0] == "#":
                    continue
                else:
                    # multicast_addr, srcip_addr
                    column = list(line[:-1].split(","))
                    mc_service_info_list.append(column)
            self.logger.debug(
                "send address(multicast_addr, srcip_addr) : %s",
                str(mc_service_info_list))

            while True:
                for mc_info in mc_service_info_list:
                    mld = self.create_mldquery(mc_info[0], mc_info[1])
                    sendpkt = self.create_packet(self.addressinfo, mld)
                    self.send_packet_to_sw(sendpkt)
                    hub.sleep(self.WAIT_TIME)

    # ==================================================================
    # create_mldquery
    # ==================================================================
    def create_mldquery(self, mc_address, mc_serv_ip):
        self.logger.debug("")

        return icmpv6.mldv2_query(
            address=mc_address,
            srcs=[mc_serv_ip] if mc_serv_ip else None,
            maxresp=10000, qqic=self.WAIT_TIME)

    # ==================================================================
    # create_mldreport
    # ==================================================================
    def create_mldreport(self, mc_address, mc_serv_ip, report_types):
        self.logger.debug("")

        record_list = []
        for report_type in report_types:
            record_list.append(
                icmpv6.mldv2_report_group(
                    type_=report_type, address=mc_address, 
                    srcs=[mc_serv_ip]))

        return icmpv6.mldv2_report(records=record_list)

    # ==================================================================
    # create_packet
    # ==================================================================
    def create_packet(self, addressinfo, mld):
        self.logger.debug("")

        # ETHER
        eth = ethernet.ethernet(
#            ethertype=ether.ETH_TYPE_8021Q,
            ethertype=ether.ETH_TYPE_IPV6, 
            src=addressinfo[0], dst=addressinfo[1])

# TODO
        """
        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        """
        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
            data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=addressinfo[2], dst=addressinfo[3],
            hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
#        sendpkt = eth / vln / ip6 / icmp6
        sendpkt = eth / ip6 / icmp6
        sendpkt.serialize()
        self.logger.debug("created packet(ryu) : %s", str(sendpkt))

        return sendpkt

    # ==================================================================
    # send_packet_to_sw
    # ==================================================================
    def send_packet_to_sw(self, ryu_packet):
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of scapy
        sendrecv.sendp(sendpkt)
        self.logger.debug("sent 1 packet to switch.")

    # ==================================================================
    # send_packet_to_ryu
    # ==================================================================
    def send_packet_to_ryu(self, packet):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(packet, protocol=0))
        self.logger.debug("sent 1 packet to ryu.")# [data] = %s"),
#                          str(packet["data"]))

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")
        dispatch = recvpkt.dispatch
        self.logger.debug("received [type_]: %s",
                          str(dispatch["type_"]))
        self.logger.debug("received [data]: %s",
                          str(dispatch["data"]))
        receive_type = dispatch["type_"]

        if receive_type == mld_const.CON_SWITCH_FEATURE:
            self.set_switch_config(dispatch)

        elif receive_type == mld_const.CON_PACKET_IN:
            pkt_icmpv6 = dispatch["data"]
            self.logger.debug("pkt_icmpv6 : " + str(pkt_icmpv6))

            # MLDv2 Query
            if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
                self.logger.debug("MLDv2 Query : %s",
                                  str(pkt_icmpv6.data))
                self.send_reply()

            # MLDv2 Report
            if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
                self.logger.debug("MLDv2 Report : %s",
                                  str(pkt_icmpv6.data))
                self.manage_user(dispatch)

        else:
            self.logger.debug("received type : %s", dispatch["type_"])

    # ==================================================================
    # set_switch_config
    # ==================================================================
    def set_switch_config(self, dispatch_):
        self.logger.debug("")

        # ファイルから読み込んだSWの情報から接続元SWがエッジか収容か判定し、
        # 初期設定をFlowModする
        target_switch = dispatch_["datapathid"]
        for switch in self.switches:
            if target_switch == switch["datapathid"]:
                sw_name = switch["sw_name"]
                ports = switch["ports"]
                flowlist = []
                if sw_name == "esw":
                    # エッジSWのFlowMod
                    self.logger.debug("sw_name : %s", sw_name)
                    # TODO ルータからのQueryをp-inする
                    flowlist.append(self.create_flowmod(
                        datapathid=target_switch,
                        in_port=ports[0], out_port="p-in", type_=130))
                    # MLDからのQueryを収容SWへ
                    flowlist.append(self.create_flowmod(
                        datapathid=target_switch,
                        in_port=ports[3], out_port=ports[1:3], type_=130))
                    # ベストエフォートの場合のみ
                    if self.config["service_type"] == "BE":
                        # TODO p-out(Report)をルータへ
                        flowlist.append(self.create_flowmod(
                            datapathid=target_switch,
                            in_port="p-out", out_port=ports[0], type_=143))
                        # TODO それ以外のパケットはブリッジとして動作
                        flowlist.append(self.create_flowmod(
                            datapathid=target_switch,
                            in_port="", out_port="", type_=0))
                        flowmod = dispatch(
                            type_=mld_const.CON_FLOW_MOD,
                            datapathid=1, data=flowlist)
                        self.logger.debug("flowmod[data] : %s",
                                          str(flowmod["data"]))

                        self.send_packet_to_ryu(flowmod)

                if sw_name == "sw1" or sw_name == "sw2":
                    # 収容SWのFlowMod
                    self.logger.debug("sw_name : %s", sw_name)
                    # TODO ホストからReportがきたらp-in
                    flowlist.append(self.create_flowmod(
                        datapathid=target_switch,
                        in_port=ports[0], out_port="p-in", type_=0))
                    # TODO それ以外のパケットはブリッジとして動作
                    flowlist.append(self.create_flowmod(
                        datapathid=target_switch,
                        in_port="", out_port="", type_=0))
                    flowmod = dispatch(
                        type_=mld_const.CON_FLOW_MOD,
                        datapathid=1, data=flowlist)
                    self.logger.debug("flowmod[data] : %s",
                                      str(flowmod["data"]))

                    self.send_packet_to_ryu(flowmod)

    # ==================================================================
    # create_flowmod
    # ==================================================================
    def create_flowmod(self, datapathid, in_port, out_port, type_):
        self.logger.debug("")
        # TODO 引数を元にFlowmodを生成し、返却する

        return parser.OFPFlowMod(datapath=datapathid)

    # ==================================================================
    # create_packetout
    # ==================================================================
    def create_packetout(self, datapathid, packet):
        self.logger.debug("")
        actions = [
            parser.OFPActionOutput(port=self.edge_switch["ports"][0])]
        pout = parser.OFPPacketOut(
            datapathid=datapathid, in_port=ofproto_v1_3.OFPP_CONTROLLER,
            buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
            actions=actions, data=packet)
        return pout

    # ==================================================================
    # send_reply
    # ==================================================================
    def send_reply(self):
        self.logger.debug("")
        
        if not self.ch_info.channel_info:
            # 未視聴状態の場合は何もしない
            self.logger.info("No one shows any channels.")

        else:
            # 視聴中のMCグループ毎にレポートを作成
            for mc_info in self.ch_info.channel_info.keys():
                report_type = [icmpv6.MODE_IS_INCLUDE]
                mld = self.create_mldreport(
                    mc_info[0], mc_info[1], report_type)
                # packetのsrcはMLD処理部のものを使用する
                sendpkt = self.create_packet(self.addressinfo, mld)
                # エッジスイッチにp-out
                pout = self.create_packetout(
                    datapathid=self.edge_switch["datapathid"],
                    packet=sendpkt)
                packetout = dispatch(
                    type_=mld_const.CON_PACKET_OUT,
                    datapathid=1, data=pout)
                self.logger.debug("packetout: %s", str(packetout))
                self.send_packet_to_ryu(packetout)

    # ==================================================================
    # manage_user
    # ==================================================================
    def manage_user(self, dispatch):
        self.logger.debug("")

        mldv2_report = dispatch["data"].data
        target_switch = dispatch["datapathid"]
        in_port = dispatch["in_port"]
        cid = dispatch["cid"]

        for report in mldv2_report.records:
            self.logger.debug("report : %s", str(report))
            # ALLOW_NEW_SOURCES：視聴情報に追加
            if report.type_ == icmpv6.ALLOW_NEW_SOURCES:
                reply_type = self.ch_info.add_info(
                    mc_addr=report.address, serv_ip=report.srcs[0],
                    data_path=target_switch, port_no=in_port, cid=cid)

            # BLOCK_OLD_SOURCES：視聴情報から削除
            elif report.type_ == icmpv6.BLOCK_OLD_SOURCES:
                reply_type = self.ch_info.remove_info(
                    mc_addr=report.address, serv_ip=report.srcs[0],
                    data_path=target_switch, port_no=in_port, cid=cid)

            else:
                self.logger.debug("report.type : %s", report.type_)
                reply_type = mld_const.CON_REPLY_NOTHING

            self.logger.debug("channel_info : %s", self.ch_info.channel_info)

            flowlist = []
            if reply_type == mld_const.CON_REPLY_ADD_FLOW_MOD:
                self.logger.debug("reply_type : %d", reply_type)
                # packet-inしてきた収容スイッチへFlowMod
                flowlist.append(self.create_flowmod(
                    datapathid=target_switch, in_port="esw",
                    out_port=in_port, type_=0))
                flowmod = dispatch(
                    type_=mld_const.CON_FLOW_MOD,
                    datapathid=1, data=flowlist)
                self.logger.debug("flowmod[data] : %s",
                                  str(flowmod["data"]))
                self.send_packet_to_ryu(flowmod)

            elif reply_type == \
                mld_const.CON_REPLY_ADD_FLOW_MOD_AND_PACKET_OUT:
                self.logger.debug("reply_type : %d", reply_type)
                # エッジスイッチとpacket-inしてきた収容スイッチへFlowMod
                flowlist.append(self.create_flowmod(
                    datapathid=self.edge_switch["datapathid"],
                    in_port=self.edge_switch["ports"][0],
                    out_port="接続元sw", type_=0))
                flowlist.append(self.create_flowmod(
                    datapathid=target_switch, in_port="esw",
                    out_port=in_port, type_=0))
                flowmod = dispatch(
                    type_=mld_const.CON_FLOW_MOD,
                    datapathid=1, data=flowlist)
                self.logger.debug("flowmod[data] : %s",
                                  str(flowmod["data"]))
                self.send_packet_to_ryu(flowmod)

                # ベストエフォートの場合のみ
                if self.config["service_type"] == "BE":
                    # エッジスイッチへ投げるReportを作成
                    report_types = [icmpv6.ALLOW_NEW_SOURCES,
                                    icmpv6.CHANGE_TO_INCLUDE_MODE]
                    mld_report = self.create_mldreport(
                        mc_address=report.address,
                        mc_serv_ip=report.srcs[0], 
                        report_types=report_types)
                    packet = self.create_packet(
                        self.addressinfo, mld_report)
                    pout = self.create_packetout(
                        datapathid=self.edge_switch["datapathid"],
                        packet=packet)
                    packetout = dispatch(
                        type_=mld_const.CON_PACKET_OUT,
                        datapathid=1, data=pout)
#                    self.logger.debug("packetout[data] : %s",
#                                      packetout["data"])
                    self.send_packet_to_ryu(packetout)

            elif reply_type == mld_const.CON_REPLY_DEL_FLOW_MOD:
                self.logger.debug("reply_type : %d", reply_type)
                # packet-inしてきた収容スイッチへFlowMod
                flowlist.append(self.create_flowmod(
                    datapathid=target_switch, in_port="esw",
                    out_port=in_port, type_=0))
                flowmod = dispatch(
                    type_=mld_const.CON_FLOW_MOD,
                    datapathid=1, data=flowlist)
                self.logger.debug("flowmod[data] : %s",
                                  str(flowmod["data"]))
                self.send_packet_to_ryu(flowmod)

            elif reply_type == \
                mld_const.CON_REPLY_DEL_FLOW_MOD_AND_PACKET_OUT:
                self.logger.debug("reply_type : %d", reply_type)
                # エッジスイッチとpacket-inしてきた収容スイッチへFlowMod
                flowlist.append(self.create_flowmod(
                    datapathid=self.edge_switch["datapathid"],
                    in_port=self.edge_switch["ports"][0],
                    out_port="接続元sw", type_=0))
                flowlist.append(self.create_flowmod(
                    datapathid=target_switch, in_port="esw",
                    out_port=in_port, type_=0))
                flowmod = dispatch(
                    type_=mld_const.CON_FLOW_MOD,
                    datapathid=1, data=flowlist)
                self.logger.debug("flowmod[data] : %s",
                                  str(flowmod["data"]))
                self.send_packet_to_ryu(flowmod)

                # ベストエフォートの場合のみ
                if self.config["service_type"] == "BE":
                    # エッジスイッチへ投げるReportを作成
                    report_types = [icmpv6.BLOCK_OLD_SOURCES]
                    mld_report = self.create_mldreport(
                        mc_address=report.address,
                        mc_serv_ip=report.srcs[0], 
                        report_types=report_types)
                    packet = self.create_packet(
                        self.addressinfo, mld_report)
                    pout = self.create_packetout(
                        datapathid=self.edge_switch["datapathid"],
                        packet=packet)
                    packetout = dispatch(
                        type_=mld_const.CON_PACKET_OUT,
                        datapathid=1, data=pout)
#                    self.logger.debug("packetout[data] : %s",
#                                      str(packetout["data"]))
                    self.send_packet_to_ryu(packetout)
            else:
                # 何もしない
                self.logger.debug("reply_type : %d", reply_type)

        # TODO タイムアウト処理

    # ==================================================================
    # receive_from_ryu
    # ==================================================================
    def receive_from_ryu(self):
        self.logger.debug("")
        while True:
            self.logger.debug("waiting packet...")
            # receive of zeromq
            recvpkt = self.recv_sock.recv()
            packet = cPickle.loads(recvpkt)
            self.analyse_receive_packet(packet)

            self.org_thread_time.sleep(1)

if __name__ == "__main__":
    mld_proc = mld_process()
#    hub.spawn(mld_proc.send_mldquey_regularly)
    recv_thre = mld_proc.org_thread.Thread(
                                target=mld_proc.receive_from_ryu,
                                name="ReceiveThread")
    recv_thre.start()
    while True:
        hub.sleep(1)
