class dispatch():
    def __init__(self, type_, datapathid, in_port=-1, cid=0, data=None):
        print("dispatch __init__")
        self.dispatch = {}

        self.dispatch["type_"] = type_
        self.dispatch["datapathid"] = datapathid
        self.dispatch["in_port"] = in_port
        self.dispatch["cid"] = cid
        self.dispatch["data"] = data
        print("dispatch : %s \n", self.dispatch)

    def __getitem__(self, key):
        print("dispatch __getitem__")
        return self.dispatch[key]

    def __getstate__(self):
        print("dispatch __getstate__")
#        print("get self.dispatch : %s", str(self.dispatch))
        return self.dispatch.copy()

    def __setstate__(self, data):
        print("dispatch __setstate__")
        self.dispatch = data
        print("set self.dispatch : %s \n", str(self.dispatch))
