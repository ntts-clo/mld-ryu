# coding: utf-8
import json


class read_json():
    def __init__(self, filename):
        jsonfile = open(filename)
        self.data = json.load(jsonfile)

    def __getitem__(self, key):
        return self.data[key]
