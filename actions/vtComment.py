import json
import datetime
import requests

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

        for i in range(len(self.hList)):
            self.commentOut(self.hList['hash'])


    def commentOut(self, hash):
        cTime = str(datetime.datetime.now())
        text = ""
        
        postData = {
                        "data": {
                            "type": "comment",
                            "attributes": {
                                "text": text
                            }
                        }
                    }
                    
        try:
            response = requests.post(
            'https://www.virustotal.com/api/v3/files/{}/comments'.format(hash),
            headers={'x-apikey': self.apikey},
            data= json.dumps(postData),)
        except Exception as e:
            print(e)