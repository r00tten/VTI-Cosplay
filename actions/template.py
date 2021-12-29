class trigger:
    hList = []
    meta = []
    apikey = ""
    yara = ""

    def __init__(self, param):
        self.hList = param.get('res', [])
        self.meta = param.get('meta', {})
        self.apikey = param.get('key', "")
        self.yara = param.get('yara', "")