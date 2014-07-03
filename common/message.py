class message():
    def __init__(self, type_, datapath, in_port=-1, cid=0, data=None):
        print("message __init__")
        self.message = {}

        self.message["type_"] = type_
        self.message["datapath"] = datapath
        self.message["in_port"] = in_port
        self.message["cid"] = cid
        self.message["data"] = data
        print("message : %s", self.message)

    def __getitem__(self, key):
        return self.message[key]

    def __getstate__(self):
        print("message __getstate__")
#        print("get self.message : %s" , str(self.message))
        return self.message.copy()

    def __setstate__(self, data):
        print("message __setstate__")
        self.message = data
        print("set self.message : %s" , str(self.message))
