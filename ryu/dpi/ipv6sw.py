# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import logging
import json
import webob

from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub, ofctl_v1_3
from ryu.lib.packet import packet
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.app.wsgi import route


LOG = logging.getLogger(__name__)

# Tuning
BARRIER_REPLY_TIMER = 2.0  # sec
FLOW_PKT_IN = {
    "actions": [{"type": "OUTPUT", "port": 0xfffffffd, "max_len": 65535}]}

# Static
DPI_FLOWLIST = {"default": "standard", "dpi": "primary"}
JSONFILE = DPI_FLOWLIST.values()
JSONDIR = "dpiflows"
JSONPATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), JSONDIR)


def to_match(dp, attrs):
    try:
        match = dp.ofproto_parser.OFPMatch(**attrs)
    except Exception as e:
        match = dp.ofproto_parser.OFPMatch()
        LOG.error("### Match-ERR: %s", e)
        LOG.debug("  --> attrs=%s", attrs)
        LOG.debug("  --> match=%s", match.to_jsondict())

    return match


def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get("cookie", 0))
    cookie_mask = int(flow.get("cookie_mask", 0))
    table_id = int(flow.get("table_id", 0))
    idle_timeout = int(flow.get("idle_timeout", 0))
    hard_timeout = int(flow.get("hard_timeout", 0))
    priority = int(flow.get("priority", 0))
    buffer_id = int(flow.get("buffer_id", dp.ofproto.OFP_NO_BUFFER))
    out_port = int(flow.get("out_port", dp.ofproto.OFPP_ANY))
    out_group = int(flow.get("out_group", dp.ofproto.OFPG_ANY))
    flags = int(flow.get("flags", 0))
    match = to_match(dp, flow.get("match", {}))
    inst = ofctl_v1_3.to_actions(dp, flow.get("actions", []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        flags, match, inst)

    dp.send_msg(flow_mod)


def add_flows(dp, flows):
    cmd = dp.ofproto.OFPFC_ADD
    for flow in flows:
        mod_flow_entry(dp, flow, cmd)


def del_flows(dp, flows):
    cmd = dp.ofproto.OFPFC_DELETE
    for flow in flows:
        mod_flow_entry(dp, flow, cmd)


def del_cookies(dp, cookies):
    cmd = dp.ofproto.OFPFC_DELETE
    for cookie in cookies:
        flow = {"cookie": cookie, "cookie_mask": 65535}
        mod_flow_entry(dp, flow, cmd)


class Flowdict(dict):
    """
    flowdict = {<dpid>: [flow, ...], ...}
    flow = {"cookie": cookie,
            "priority": priority,
            "flags": 0,
            "idle_timeout": 0,
            "hard_timeout": 0,
            "match": match,
            "actions": actions}
    """

    def __init__(self):
        super(Flowdict, self).__init__()

    def from_file(self, file, encoding='utf-8'):
        with open(file, 'r') as f:
            self.update(json.load(f, encoding))

    def from_json(self, j):
        self.update(json.loads(j))
        return self

    def to_json(self, indent=False):
        if indent:
            return json.dumps(self, sort_keys=True, indent=4)
        else:
            return json.dumps(self)

    def get_dpids(self):
        return [int(x) for x in self.keys()]

    def get_items(self):
        return [(int(x), y) for x, y in self.items()]

    def get_flows(self, dpid):
        if str(dpid) in self:
            return self[str(dpid)]
        else:
            return []

    def check_dp(self, dpset):
        for dpid in self.get_dpids():
            if dpset.get(dpid) is None:
                return dpid


class DpiStatsController(StatsController):
    DPI_REST_LIST = {"dpi": ["on", "off"]}

    def __init__(self, req, link, data, **config):
        super(DpiStatsController, self).__init__(req, link, data, **config)
        self.dpiflow = data["dpiflow"]

    def _wait_barrier(self, dp):
        barrier = dp.ofproto_parser.OFPBarrierRequest(dp)
        dp.set_xid(barrier)
        waiters_per_dp = self.waiters.setdefault(dp.id, {})
        event = hub.Event()
        waiters_per_dp[barrier.xid] = event
        LOG.info("<----------------- Barrier Request")
        LOG.debug("dpid=%s xid=%s", dp.id, barrier.xid)
        LOG.debug("----------------------------------")
        dp.send_msg(barrier)

        ret = event.wait(timeout=BARRIER_REPLY_TIMER)
        if not ret:
            del waiters_per_dp[barrier.xid]

        return ret

    def _dpi_flows_cmd(self, dp, flows, cmd):
        if cmd == "on":
            LOG.info("<------------------- Flow-Mod(ADD)")
            add_flows(dp, flows)
        elif cmd == "off":
            LOG.info("<---------------- Flow-Mod(DELETE)")
            del_flows(dp, flows)

        LOG.debug("dpid=%s flows=%s", dp.id, len(flows))
        LOG.debug("----------------------------------")
        return self._wait_barrier(dp)

    def _dpi_response(self, status, body, err_msg=None):
        if err_msg:
            _dpi_body = {"err_msg": err_msg, "body": body}
            LOG.info("### REST-ERR: %s: %s", err_msg, str(body))
        else:
            _dpi_body = body
        return webob.Response(content_type="application/json",
                              status=status, body=json.dumps(_dpi_body))

    @route("dpi", "/dpi/flow", methods=["PUT"])
    def dpi_received(self, req, **_kwargs):
        body = req.body
        LOG.info("================ Received REST DPI")
        LOG.info("Request_body=%s", body)
        LOG.debug("dpset_dpids=%s", self.dpset.dps.keys())
        LOG.debug("==================================")

        # REST Parameter check
        try:
            dpi_cmd = eval(body)["dpi"]
        except:
            err_msg = "invalid syntax at body"
            return self._dpi_response(400, body, err_msg)

        if dpi_cmd not in self.DPI_REST_LIST["dpi"]:
            err_msg = "invalid value at dpi"
            return self._dpi_response(400, body, err_msg)

        # Datapath check
        flow_tag = DPI_FLOWLIST["dpi"]
        flow_list = self.dpiflow[flow_tag]
        dpid = flow_list.check_dp(self.dpset)
        if dpid is not None:
            err_msg = "Datapath[dpid=%s] is None" % dpid
            return self._dpi_response(500, body, err_msg)

        # FlowMod & BariierRequest
        for dpid, flows in flow_list.get_items():
            dp = self.dpset.get(dpid)
            LOG.debug("FlowMod dpid=%s flows=%s", dp.id, flow_tag)
            if not self._dpi_flows_cmd(dp, flows, dpi_cmd):
                err_msg = "BarrierRequest Timeout. [dpid=%s]" % dp.id
                LOG.error(err_msg)
                return self._dpi_response(500, body, err_msg)

        return self._dpi_response(200, body)


class DpiRestApi(RestStatsApi):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DpiRestApi, self).__init__(*args, **kwargs)
        self.dpiflow = {}

        LOG.info("=================== REST-API(init)")
        LOG.info("BarrierReplyTimer=%s", BARRIER_REPLY_TIMER)
        LOG.debug("args=%s, kwargs=%s", args, kwargs)

        for f in JSONFILE:
            fname = os.path.join(JSONPATH, f)
            if os.path.isfile(fname):
                self.dpiflow[f] = Flowdict()
                self.dpiflow[f].from_file(fname)
                LOG.info("FlowFile=[%s]: %s", f, fname)
                LOG.debug("flows: %s\n", self.dpiflow[f].to_json())
            else:
                LOG.error("### Init-ERR: cannot access [%s]", fname)
                exit(1)

        self.data["dpiflow"] = self.dpiflow
        wsgi = kwargs["wsgi"]
        wsgi.register(DpiStatsController, self.data)
        LOG.debug("==================================")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        LOG.info("==================> SwitchFeatures")
        LOG.info("dpid=%s, dpset=%s", dp.id, self.dpset.get_all())

        if dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flows = [FLOW_PKT_IN]
            LOG.debug("FlowMod dpid=%s flows=PacketIn", dp.id)
            add_flows(dp, flows)

        LOG.debug("==================================")

    @set_ev_cls(dpset.EventDP)
    def _handler_datapath(self, ev):
        if ev.enter:
            dp = ev.dp
            LOG.info("===================> dpset EventDP")
            LOG.info("dpid=%s, xid=%s, dpset=%s",
                      dp.id, dp.xid, self.dpset.dps.keys())

            flow_tag = DPI_FLOWLIST["default"]
            flows = self.dpiflow[flow_tag].get_flows(dp.id)
            LOG.debug("FlowMod dpid=%s flows=%s", dp.id, flow_tag)
            add_flows(dp, flows)
            LOG.debug("==================================")

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        LOG.info("-------------------> Barrier Reply")
        LOG.debug("dpid=%s, msg=%s", dp.id, msg)
        LOG.debug("----------------------------------")

        if (dp.id not in self.waiters
                or msg.xid not in self.waiters[dp.id]):
            return

        event = self.waiters[dp.id][msg.xid]
        del self.waiters[dp.id][msg.xid]
        event.set()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        LOG.info("=======================> Packet-in")
        LOG.info("dpid=%s, in_port=%s", dp.id, in_port)
        LOG.debug("packet=%s", str(pkt))
        LOG.debug("==================================")
