import os
import yaml
import hashlib
import datetime

from pathlib import Path
from typing import Dict, List

class logger:
    plat = None
    s_printer = None
    l_handle = None
    md5 = None
    yml = None
    unique = None
    fRead = None
    path = {
        'Linux':'/.vti-cosplay/',
        'Darwin':'/.vti-cosplay/',
        'Java':None,
        'Windows':'%appdata%\\vti-cosplay\\'}
    dirPath = ''
    base = ''

    def __init__(self, 
                 plat: str, 
                 s_printer: object, 
                 path: str) -> None:

        self.plat = plat
        if self.plat == 'Linux' or self.plat == 'Darwin':
            self.dirPath = self.getEnv() + self.path[self.plat]
        else:
            self.dirPath = self.path[self.plat]

        self.s_printer = s_printer

        try:
            Path(f"{self.dirPath}").mkdir(parents=False, exist_ok=True)
        except PermissionError as pe:
            print(f"[-] Permission denied while creating \
                the folder {self.path[self.plat]}")

        try:
            with open("{}".format(path), 'r') as file:
                md5 = self.calculateMD5(file.read().encode('utf-8', 'ignore'))
            self.md5 = md5

            self.base = os.path.basename(path)
        except Exception as e:
            print(e)


    def getEnv(self) -> str:
        return os.environ.get('HOME', '/tmp')


    def calculateMD5(self, 
                     data: bytes) -> str:

        if data == None:
            return False

        md5 = hashlib.md5(data).hexdigest()

        return md5
    

    def yamlParser(self, 
                   data: str) -> List:

        if len(data) == 0:
            return []
        
        yml = yaml.safe_load(data)

        if yml is None:
            return []
        
        res = []

        for i in range(len(yml)):
            res.append({'hash': yml[i]['matched']['hash']})

        return res


    def yamlCreate(self, 
                   data: List) -> List:

        res = []
        cTime = str(datetime.datetime.now())

        for i in range(len(data)):
            res.append({
                'matched':{'hash': data[i]['hash'],
                'date': cTime,
                'size': data[i].get('size', '-'),
                'first_submission_date': data[i].get('first_submission_date', '-'),
                'doubleCheck': data[i].get('doubleCheck', '-')
            }})
        
        return res


    def uniqueList(self, 
                   data: List) -> List:

        res = []
        if self.fRead == None:
            try:
                with open(
                    f"{self.dirPath}vti-cosplay_{self.md5}_{self.base}.log",
                    'r') as file:
                    fRead = self.yamlParser(file.read())
                    self.fRead = fRead
            except FileNotFoundError:
                res = data
                self.fRead = []

        if len(self.fRead) == 0 or self.fRead == [] or res != []:
            res = data
        else:
            for i in range(len(data)):
                for j in range(len(self.fRead)):
                    if data[i]['hash'] == self.fRead[j]['hash']:
                        break
                    elif j == len(self.fRead) - 1:
                        res.append(data[i])

        self.unique = res

        return res
        

    def logResults(self, 
                   data: List) -> bool:

        print(f'[+] The samples\'s details are going to be logged to the file: '
              + f'{self.dirPath}vti-cosplay_{self.md5}_{self.base}.log')
        try:
            with open(
                f"{self.dirPath}vti-cosplay_{self.md5}_{self.base}.log",
                'a') as file:
                yaml.dump(self.yamlCreate(data), file)
        except FileNotFoundError:
            print('[-] Error on writing to the file, FileNotFoundError.')
        except PermissionError:
            print('[-] Error on writing to the file, PermissionError.')

        return True