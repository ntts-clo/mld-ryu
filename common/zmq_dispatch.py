# coding: utf-8
import os
import logging
import logging.config
from ryu.ofproto import ofproto_v1_3

logging.config.fileConfig(
    os.path.abspath(os.path.dirname(__file__)) + "/logconf.ini")
logger = logging.getLogger(__name__)


class dispatch():
    def __init__(self, type_, datapathid, in_port=-1, cid=0, data=None):
        logger.debug("")

        self.dispatch = {}
        self.dispatch["type_"] = type_
        self.dispatch["datapathid"] = datapathid
        self.dispatch["in_port"] = in_port
        self.dispatch["cid"] = cid
        self.dispatch["data"] = data
        logger.debug("dispatch : %s \n", self.dispatch)

    def __getitem__(self, key):
        return self.dispatch[key]

    def __getstate__(self):
        logger.debug("")
        return self.dispatch.copy()

    def __setstate__(self, data):
        logger.debug("")
        self.dispatch = data
        logger.debug("set self.dispatch : %s \n", str(self.dispatch))


'''
FlowModの転送用データクラス
'''
class FlowModData(object):

    def __init__(self, datapathid, command=ofproto_v1_3.OFPFC_ADD, table_id, priority, match, instructions):
        logger.debug("")

        self.datapathid = datapathid
        self.command = command
        self.table_id = table_id
        self.priority = priority
        self.match = match
        self.instructions = instructions

