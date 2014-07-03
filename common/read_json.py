import json

class read_json():
    def __init__(self, filename):
        jsonfile = open(filename)
        self.data = json.load(jsonfile)

    def __getitem__(self, key):
        return self.data[key]


if __name__ == "__main__":
    test = read_json("./config.json")
    print str(test.data)
