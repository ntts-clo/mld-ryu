#!/usr/bin/python
# coding:utf-8

import user_manage
import argparse
import cPickle
import time
import sys
from pymongo import MongoClient
from pymongo.errors import (ConnectionFailure, ConfigurationError)


if '__main__' == __name__:
    # get connect_str
    parser = argparse.ArgumentParser(description="Show user database.")
    parser.add_argument("-i", "--ip", default="localhost",
                        metavar="address",
                        help="MongoDB server address (default=localhost).")
    parser.add_argument("-p", "--port", default="27017",
                        metavar="port_no",
                        help="MongoDB server port (default=27017).")
    args = parser.parse_args()
    connect_str = "mongodb://" + args.ip + ":" + args.port

    # open mongodb
    try:
        client = MongoClient(connect_str)
    except (ConfigurationError, ConnectionFailure) as e:
        print "%s (ip = %s, port = %s)" % (e.message, args.ip, args.port)
        sys.exit(1)

    db = client.viewerdb
    col = db.serialized_data

    # query
    result = col.find_one({"ch": "all"})

    if not result:
        print "no entry found."
        sys.exit()

    dump_result = result["viewerdata"]
    load_result = cPickle.loads(str(dump_result))

    # display
    for (key, switch_dict) in load_result.items():
        print key
        for (datapath_id, sw_obj) in switch_dict.items():
            print "\tSwitch:", datapath_id
            for (port_no, usr_dict) in sw_obj.port_info.items():
                print "\t\tPort_No:", port_no
                for (cid, usr_obj) in usr_dict.items():
                    time_str = time.strftime("%Y/%m/%d %H:%M:%S",
                                             time.localtime(usr_obj.time))
                    print "\t\t\tcid: ", cid, " Update time: ", time_str
