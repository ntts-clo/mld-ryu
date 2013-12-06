# vim: tabstop=4 shiftwidth=4 softtabstop=4

import os
import unittest
import logging
import itertools
import webob
import json
from nose.tools import *
from mock import patch

from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.dpi import ipv6sw
from ryu.controller.dpset import EventDP

LOG = logging.getLogger(__name__)

TEST_FLOW_STD = {"actions":[{"type":"OUTPUT", "port":1}]}
TEST_FLOW_PRI = {"actions":[{"type":"OUTPUT", "port":2}]}

class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self, id=1):
        self.msgs = []
        self.id = id
        self.xid = 1

    def set_xid(self, msg):
        self.xid += 1
        self.xid &= self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg):
        self.msgs.append(msg)


class _DPSet(object):
    def __init__(self):
        self.dps = {}

    def register(self, dp):
        self.dps[dp.id] = dp
        self.ev = EventDP(dp, True)

    def get(self, dp_id):
        return self.dps.get(dp_id)

    def get_all(self):
        return self.dps.items()


class Test_ipv6sw(unittest.TestCase):
    """ Test case for ipv6sw functions
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_to_match(self, attrs):
        dp = _Datapath()
        return ipv6sw.to_match(dp, attrs)

    def test_to_match_ok(self):
        attrs = {}
        attrs['in_port'] = 1
        attrs['eth_type'] = 0x86dd
        attrs['ipv6_src'] = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        attrs['ipv6_dst'] = '2001:db8:bd05:1d2:288a:1fc0:1:10ef'

        match = self._get_to_match(attrs)

        for key in attrs.keys():
            eq_(match[key], attrs[key])

    def test_to_match_invalid(self):
        attrs = {'dummy': 1}
        match = self._get_to_match(attrs)
        ok_('dummy' not in match)

    def test_add_flows(self):
        dp = _Datapath()
        flows = [ipv6sw.FLOW_PKT_IN]
        ipv6sw.add_flows(dp, flows)

        for msg in dp.msgs:
            ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
            eq_(msg.command, dp.ofproto.OFPFC_ADD)

    def test_del_flows(self):
        dp = _Datapath()
        flows = [ipv6sw.FLOW_PKT_IN]
        ipv6sw.del_flows(dp, flows)

        for msg in dp.msgs:
            ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
            eq_(msg.command, dp.ofproto.OFPFC_DELETE)

    def test_del_cookies(self):
        dp = _Datapath()
        cookies = [1, 2, 3]
        ipv6sw.del_cookies(dp, cookies)

        for i, msg in enumerate(dp.msgs):
            ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
            eq_(msg.command, dp.ofproto.OFPFC_DELETE)
            eq_(msg.cookie, cookies[i])

    def test_wait_barrier(self):
        ipv6sw.BARRIER_REPLY_TIMER = 0
        ok_(not ipv6sw.wait_barrier(_Datapath(), {}))


class TestFlowdict(unittest.TestCase):
    """ Test case for Flowdict
    """

    def setUp(self):
        self.flow = TEST_FLOW_STD
        self.dict = {"1":[self.flow]}
        self.json = json.dumps(self.dict)
        self.flowdict = ipv6sw.Flowdict()
        self.flowdict["1"] = [self.flow]

    def tearDown(self):
        pass

    def test_from_file(self):
        flowdict = ipv6sw.Flowdict()
        file = "/tmp/_test_json"
        with open(file, 'w') as f:
            json.dump(self.dict, f)
        flowdict.from_file(file)
        eq_(json.dumps(flowdict), self.json)
        os.remove(file)

    def test_from_json(self):
        flowdict = ipv6sw.Flowdict()
        dict = {"1":[self.flow, self.flow, self.flow], "2":[self.flow], "3":[]}
        j = json.dumps(dict)
        flowdict.from_json(j)
        eq_(json.dumps(flowdict), j)

    def test_to_json_indentFalse(self):
        eq_(self.flowdict.to_json(), self.json)

    def test_to_json_indentTrue(self):
        eq_(self.flowdict.to_json(True),
            json.dumps(self.dict, sort_keys=True, indent=4))

    def test_get_dpids(self):
        eq_(self.flowdict.get_dpids(), [1])

    def test_get_items(self):
        eq_(self.flowdict.get_items(), [(1, [self.flow])])

    def test_get_flows_dpid_in_dict(self):
        eq_(self.flowdict.get_flows(1), [self.flow])

    def test_get_flows_dpid_not_in_dict(self):
        eq_(self.flowdict.get_flows(2), [])

    def test_check_dp_dpid_in_dpset(self):
        dpset = _DPSet()
        dpset.register(_Datapath())
        ok_(self.flowdict.check_dp(dpset) is None)

    def test_check_dp_dpid_not_in_dpset(self):
        dpset = _DPSet()
        eq_(self.flowdict.check_dp(dpset), 1)


class TestDpiStatsController(unittest.TestCase):
    """ Test case for StatsController
    """

    def setUp(self):
        self.dpiflow = {"standard": ipv6sw.Flowdict(),
                        "primary": ipv6sw.Flowdict()}
        self.dpiflow["standard"]["1"] = [TEST_FLOW_STD]
        self.dpiflow["primary"]["1"] = [TEST_FLOW_PRI]
        self.data = {
            'waiters': {},
            'dpset': _DPSet(),
            'dpiflow': self.dpiflow
        }
        self.wsgi = WSGIApplication()
        self.wsgi.register(ipv6sw.DpiStatsController, self.data)

    def tearDown(self):
        pass

    def _test_request_dpi(self, wsgi, uri, code=200, method='GET', body=''):
        req = webob.Request.blank(uri)
        req.method = method
        req.body = body

        res = req.get_response(wsgi)
        eq_(res.charset, 'UTF-8')
        eq_(res.status_code, code)

        return res

    @patch('ryu.dpi.ipv6sw.wait_barrier', return_value=True)
    def _test_dpi_received_200(self, body, m):
        dp = _Datapath()
        data = self.data
        self.data["dpset"].register(dp)
        _cmddict = {"on": dp.ofproto.OFPFC_ADD,
                    "off": dp.ofproto.OFPFC_DELETE}
        cmd = _cmddict[json.loads(body)["dpi"]]

        wsgi = WSGIApplication()
        wsgi.register(ipv6sw.DpiStatsController, self.data)

        res = self._test_request_dpi(wsgi, '/dpi/flow', 200, 'PUT', body)
        eq_(res.json, body)

        msgs = self.data["dpset"].dps[1].msgs
        eq_(len(msgs), 1)
        ok_(isinstance(msgs[0], dp.ofproto_parser.OFPFlowMod))
        eq_(msgs[0].command, cmd)

    def test_dpi_received_200_dpi_on(self):
        body = '{"dpi": "on"}'
        self._test_dpi_received_200(body)

    def test_dpi_received_200_dpi_off(self):
        body = '{"dpi": "off"}'
        self._test_dpi_received_200(body)

    def test_dpi_received_404_notfound_uri(self):
        self._test_request_dpi(self.wsgi, '/dpi', 404)

    def test_dpi_received_404_unreserved_method(self):
        self._test_request_dpi(self.wsgi, '/dpi/flow', 404)

    def test_dpi_received_400_body_is_none(self):
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT')
        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], '')

    def test_dpi_received_400_body_is_not_json(self):
        body = 'test'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT', body)
        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_400_body_has_not_dpi(self):
        body = '{"test": 0}'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT', body)
        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_400_dpi_value_is_invalid(self):
        body = '{"dpi": 0}'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT', body)
        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_500_dpid_not_in_dpset(self):
        body = '{"dpi": "on"}'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 500, 'PUT', body)
        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_500_BarrierRequest_timeout(self):
        ipv6sw.BARRIER_REPLY_TIMER = 0.1
        data = self.data
        self.data["dpset"].register(_Datapath())
        LOG.debug(("self.data", self.data["dpset"].get_all()))

        wsgi = WSGIApplication()
        wsgi.register(ipv6sw.DpiStatsController, self.data)

        body = '{"dpi": "on"}'
        res = self._test_request_dpi(wsgi, '/dpi/flow', 500, 'PUT', body)
