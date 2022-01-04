import re
import json
import time
import requests
import threading
import subprocess

from typing import Dict, List

class doublecheck:
    sArr = []
    yRes = []
    mRes = []
    yFile = None
    apikey = ""
    url = None
    s_printer = None

    def __init__(self, 
                 arr: List, 
                 path: str, 
                 apikey: str, 
                 yFile: str, 
                 s_printer: object) -> None:

        self.sArr = arr
        self.path = path
        if not self.path.endswith('/'):
            self.path += '/'
            
        self.apikey = apikey
        self.yFile = yFile
        self.s_printer = s_printer


    def yaraScan(self) -> None:

        try:
            stdout, strerr = subprocess.Popen(['yara', 
                                               self.yFile, 
                                               self.path], 
                                               stdout=subprocess.PIPE, 
                                               stderr=subprocess.PIPE).communicate()
            
            res = stdout.decode("utf-8")
        except FileNotFoundError:
            print('[-] YARA must be installed. \
                I don\' trust you scan is aborted.\n')
        except NameError:
            print('NameError')
        
        res = res.split('\n')
        rPattern = re.compile("(?<=(" + self.path + "))[a-zA-Z0-9]{64}(?=\.img)")

        for i in range(len(res)):
            if res[i] != "" or len(res[i]) > 0:
                res[i] = re.sub(r'[/]+', '/', res[i])
                self.yRes.append(rPattern.search(res[i]).group())


    def sampleDownload(self, 
                       hash: str) -> None:

        response = requests.get(
            'https://www.virustotal.com/api/v3/files/{}/download'.format(hash),
            headers={'x-apikey': self.apikey},
            stream= True)

        with open("{}/{}.img".format(self.path, hash), 'wb') as file:
            for chunk in response.iter_content(chunk_size=128):
                file.write(chunk)


    def mergeR(self) -> None:

        if self.yRes == [] or len(self.yRes) <= 0:
            self.mRes = []
            return
        
        for i in range(len(self.yRes)):
            for j in range(len(self.sArr)):
                if self.yRes[i] == self.sArr[j]['hash']:
                    self.sArr[j]['doubleCheck'] = True
                    self.mRes.append(self.sArr[j])
                    break
        

    def orchestrator(self) -> List:

        if self.sArr != [] and len(self.sArr) > 0:
            thread1 = threading.Thread(target=self.s_printer.downloadStatus,
                                       args=(), 
                                       daemon=True)

            thread1.start()
            self.s_printer.dTot = len(self.sArr)
            for i in range(len(self.sArr)):
                self.sampleDownload(self.sArr[i]['hash'])
                self.s_printer.dCur = i + 1
                time.sleep(0.1)
            self.s_printer.finished = True
            thread1.join()
        
            self.yaraScan()
            self.mergeR()

        return self.mRes