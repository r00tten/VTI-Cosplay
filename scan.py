import re
import copy
import json
import requests
import threading

from typing import Dict, List

class VTscan:
    apiArray = []
    apikey = ""
    result = []
    limit = 0
    cursor = []
    s_printer = None
    r_logger = None
    verbose = False
    fast = False
    livehunt = False
    nodeCount = 0
    cursorEnd = 0

    def __init__(self, 
                 arr: List, 
                 param: Dict) -> None:

        self.apiArray = arr
        self.apikey = param.get('key', '')
        self.limit = int(param.get('limit', 0))
        self.s_printer = param.get('printer', None)
        self.r_logger = param.get('logger', None)
        self.verbose = param.get('verbose', False)
        self.fast = param.get('fast', False)
        self.livehunt = param.get('livehunt', False)

    def evaluate(self) -> List:
        thread1 = threading.Thread(target=self.s_printer.status, 
                                   args=("Normalizing", "Normalized", "the queries",),
                                   daemon=True)
        thread1.start()
        normalized = self.normalize(self.apiArray)
        self.s_printer.finished = True
        thread1.join()
        
        if self.verbose == True:
            self.s_printer.prettyPrint(normalized)

        thread2 = threading.Thread(target=self.s_printer.status, 
                                   args=("Optimizing", "Optimized", "the queries",),
                                   daemon=True)
        thread2.start()
        optimized = self.optimize(normalized)
        self.s_printer.finished = True
        thread2.join()
        
        if self.verbose == True:
            self.s_printer.prettyPrint(optimized)

        preResult = []
        tmpSetup = self.setup(optimized, preResult)
        self.cursor = tmpSetup['res']
        preResult = tmpSetup['pre']
        
        result = []
        thread3 = threading.Thread(target=self.s_printer.searchStatus,
                                   args=("Total matched samples",),
                                   daemon=True)
        thread3.start()
        while True:
            tmpSearch = self.search(optimized, self.cursor, preResult)
            preResult = tmpSearch['arr']
            
            self.cursor = tmpSearch['cursor']
            
            if self.verbose == True:
                self.s_printer.prettyPrint(preResult)

            result = self.binOperation(copy.deepcopy(preResult))
            result = self.cleanDub(result)
            uRes = self.r_logger.uniqueList(result) if self.livehunt == True else result

            self.s_printer.search = len(uRes)
            if len(uRes) >= self.limit and self.limit != 0:
                break
            elif self.nodeCount == self.cursorEnd:
                break
            
        self.s_printer.finished = True
        thread3.join()
        
        if not self.fast and not len(uRes) <= 0:
            result = self.sorting(uRes)
        else:
            result = uRes
            
        return result

    def normalize(self, 
                  arr: List) -> List:

        if arr == None:
            return False

        i = 0
        res = []

        if len(arr) == 1 or not isinstance(arr[0], list):
            res.append(arr)
            arr = res
        else:
            while i < len(arr):
                if arr[i] == '&':
                    tmp = []
                    count = -1
                    if (re.search('^size', str(arr[i-1][0])) 
                            or re.search('^size', str(arr[i+1][0])) 
                            or isinstance(arr[i-1][0], list) 
                            or isinstance(arr[i+1][0], list)):
                        count = -1
                    elif (isinstance(arr[i-1][0], (int, float, complex)) 
                          and isinstance(arr[i+1][0], (int, float, complex))):
                        if (len(arr[i-1][1]) == arr[i-1][0] 
                                and len(arr[i+1][1]) == arr[i+1][0]):

                            count = arr[i-1][0]
                            count += arr[i+1][0]

                            tmp.extend(self.normalize(arr[i-1][1]))
                            tmp.extend(self.normalize(arr[i+1][1]))
                    elif (isinstance(arr[i-1][0], (int, float, complex)) 
                          and not isinstance(arr[i+1][0], (int, float, complex))):
                        if len(arr[i-1][1]) == arr[i-1][0]:
                            count = arr[i-1][0]
                            count += 1

                            tmp.extend(self.normalize(arr[i-1][1]))
                            tmp.extend(self.normalize(arr[i+1]))

                    elif (not isinstance(arr[i-1][0], (int, float, complex)) 
                          and isinstance(arr[i+1][0], (int, float, complex))):
                        if len(arr[i+1][1]) == arr[i+1][0]:
                            count = arr[i+1][0]
                            count += 1

                            tmp.extend(self.normalize(arr[i-1]))
                            tmp.extend(self.normalize(arr[i+1][1]))
                    else:
                        count = 2 if arr[i] == '&' else 1

                        tmp.extend(self.normalize(arr[i-1]))
                        tmp.extend(self.normalize(arr[i+1]))

                    if count > 0:
                        arr.insert(i-1, [count, tmp])
                        del arr[i:i+3]
                        i = 0
                    else:
                        i += 1
                else:
                    i += 1

        return arr

    def optimize(self,
                 arr: List) -> List:
                 
        if arr == None:
            return False       
        
        i = 0
        while i < len(arr):
            if isinstance(arr[i], list):
                arr[i] = self.optimize(arr[i])
            elif (isinstance(arr[i], (int, float, complex)) and
                  arr[i] == len(arr[i+1])):
                tmp = ''
                for j in arr[i+1]:
                    if re.search('^content:', j[0]):
                        tmp += j[0] + ' '
                arr = [tmp]
            i += 1
            

        i = 0
        while i < len(arr):
            if (arr[i] == '&' 
                    and not isinstance(arr[i-1][0], list)
                    and not isinstance(arr[i+1][0], list)):

                tmp = ''
                if (re.search('^content', str(arr[i-1][0])) and 
                        re.search('^content', str(arr[i+1][0]))):
                    tmp = arr[i-1][0] + ' ' + arr[i+1][0]
                    arr.insert(i-1, [tmp])
                    del arr[i:i+3]
                    i = 0
                else:
                    i += 1
            else:
                i += 1

        i = 0
        while i < len(arr):
            if (arr[i] == '|' 
                    and not isinstance(arr[i-1][0], list) 
                    and not isinstance(arr[i+1][0], list)):

                tmp = ''
                if (re.search('^content', str(arr[i-1][0])) and 
                        re.search('^content', str(arr[i+1][0]))):

                    tmp = arr[i-1][0] + ' OR ' + arr[i+1][0]
                    arr.insert(i-1, [tmp])
                    del arr[i:i+3]
                    i = 0
                else:
                    i += 1
            else:
                i += 1

        return arr

            
    def setup(self, 
              arr: List, 
              pre: List) -> Dict:

        res = []
        for i in range(len(arr)):
            if arr[i] == '&' or arr[i] == '|':
                res.append(arr[i])
                pre.append(arr[i])
                continue
            elif isinstance(arr[i], (int, float, complex)):
                tmp = self.setup(arr[i+1], [])
                res = [arr[i], tmp['res']]
                pre = [arr[i], tmp['pre']]
                break
            elif isinstance(arr[i], list):
                tmp = self.setup(arr[i], [])
                res.append(tmp['res'])
                pre.append(tmp['pre'])
            elif re.search('^size', arr[i]):
                res.append("")
                pre.append(arr[i])
            else:
                res.append("")
                self.nodeCount += 1
        return {'res': res, 'pre': pre}

    def search(self, 
               arr: List, 
               cursor: List,
               res: List) -> Dict:

        tmp = []
        for i in range(len(arr)):
            if arr[i] == '&' or arr[i] == '|':
                continue
            elif isinstance(arr[i], (int, float, complex)):
                tmp = self.search(arr[i+1], cursor[i+1], res[i+1])
                res[i+1] = tmp['arr']
                cursor[i+1] = tmp['cursor']
                break
            elif isinstance(arr[i], list):
                tmp = self.search(arr[i], cursor[i], res[i])
                res[i] = tmp['arr']
                cursor[i] = tmp['cursor']
            else:
                if not re.search('^size', str(arr[i])):
                    if not cursor[i] == 'end':
                        tmp = self.connect(arr[i], cursor[i], res)
                        cursor[i] = tmp['cursor']
                        
        return {'arr': res, 'cursor': cursor}


    def connect(self, 
                apiStr: str, 
                cursor: str, 
                res: List) -> Dict:

        if apiStr == None or apiStr == "":
            return False
            
        if self.verbose == True:
            self.s_printer.prettyPrint(apiStr)
        
        tmp = []
        param_limit = 10

        response = requests.get(
            'https://www.virustotal.com/api/v3/intelligence/search',
            params={'query': apiStr, 'limit': param_limit, 'cursor': cursor,
            'descriptors_only': self.fast}, headers={'x-apikey': self.apikey})

        resJson = json.loads(response.text)

        data = resJson['data']
        meta = resJson['meta']
        if data != None:
            tmp.extend(data)
        if 'cursor' in meta:
            cursor = meta['cursor']
        else:
            cursor = "end"
            self.cursorEnd += 1
            
        data = tmp
        for i in range(len(data)):
            if not self.fast:
                res.append({
                    'hash': data[i]['attributes']['sha256'], 
                    'size': data[i]['attributes']['size'], 
                    'first_submission_date': data[i]['attributes'].get('first_submission_date', -1),
                    'detection': '{}/{}'.format(
                        data[i]['attributes']['last_analysis_stats']['malicious'],
                        int(data[i]['attributes']['last_analysis_stats']['malicious']) 
                        + (data[i]['attributes']['last_analysis_stats']['undetected']))})
            else:
                res.append({'hash':data[i]['id']})

        return {'arr': res, 'cursor': cursor}


    def binOperation(self, 
                     arr: List) -> List:

        if arr == None:
            return False
            
        res = []
        i = 0

        if arr == []:
            res = arr
        elif len(arr) == 1 or not isinstance(arr[0], list):
            if isinstance(arr[0], (int, float, complex)):
                tmp = []
                for j in arr[1]:
                    for k in self.binOperation(j):
                        tmp.append(k)
                        
                res.extend(self.compare(tmp, arr[0], []))
            elif isinstance(arr[0], list):
                tmp = self.binOperation(arr[0])
                
                if tmp != []:
                    res = tmp
            else:
                res = arr
        else:
            while i < len(arr):
                tmp = []

                if arr[i] == '&' or arr[i] == '|':
                    count = 2 if arr[i] == '&' else 1
                    op1 = self.binOperation(arr[i-1])
                    op2 = self.binOperation(arr[i+1])
                    
                    if (op1 == []):
                        arr.insert(i-1, op2)
                        del arr[i:i+3]
                        i = 0
                    elif (op2 == []):
                        arr.insert(i-1, op1)
                        del arr[i:i+3]
                        i = 0
                    elif (re.search('^size', str(op1[0])) 
                          and re.search('^size', str(op2[0]))
                          and len(arr) > 3):
                        i += 1
                    else:
                        tmp = self.compare(op1, count, op2)
                        if tmp == [] and len(arr) == 3:
                            del arr[i-1:i+2]
                            i = 0
                        else:
                            arr.insert(i-1, tmp)
                            del arr[i:i+3]
                            i = 0
                else:
                    i += 1
            res = arr
            res = self.binOperation(res)
            
        return res


    def compare(self, 
                op1, 
                count, 
                op2) -> None:

        if count == None or op1 == None or op2 == None:
            return False
        
        size = 0
        less = -1
        res = []
        tmp = []

        if not op1 == []:
            if re.search('^size', str(op1[0])):
                size = op1[0].split(':')[1]
                tmp = op2

        if not op2 == []:
            if re.search('^size', str(op2[0])) and size == 0:
                size = op2[0].split(':')[1]
                tmp = op1

        if size != 0 and self.fast:
            return tmp
        
        if size != 0:
            if re.search('\+|\-', str(size)):
                if re.search('\+', str(size)):
                    less = True
                else:
                    less = False
                
                size = size[:len(size)-1]

            if re.search('KB', str(size)):
                size = int(size.split('KB')[0]) * 1024
            elif re.search('MB', str(size)):
                size = int(size.split('MB')[0]) * 1024 * 1024
            else:
                size = int(size)

            if less == -1:
                for i in range(len(tmp)):
                    if tmp[i]['size'] == size:
                        res.append(tmp[i])
            elif less == False:
                for i in range(len(tmp)):
                    if tmp[i]['size'] < size:
                        res.append(tmp[i])
            else:
                for i in range(len(tmp)):
                    if tmp[i]['size'] > size:
                        res.append(tmp[i])
        else:
            if count == 1:
                res.extend(op1)
                res.extend(op2)
            else:
                k = 0

                for i in range(len(op1)):
                    for j in range(len(op2)):
                        if op1[i]['hash'] == op2[j]['hash']:
                            k += 1

                        if k >= count:
                            if tmp[i] not in res:
                                res.append(tmp[i])
                            break
                    k = 0
                
        return res
    

    def cleanDub(self, 
                 arr: List) -> List:

        res = []
        if len(arr) > 0:
            for i in range(len(arr)):
                if arr[i] not in res:
                    res.append(arr[i])
            
        return res
                    
        
    def sorting(self, 
                arr: List) -> List:

        if arr == [] or arr == None:
            return False

        tmp = []
        i = 0
        small = -1

        while True:
            if len(arr) == 1:
                tmp.append(arr[0])
                del arr[0]
                break
            elif i == 0:
                small = i
            elif arr[i]['first_submission_date'] < arr[small]['first_submission_date']:
                small = i
            
            if i == len(arr) - 1:
                tmp.append(arr[small])
                del arr[small]
                i = 0
            else: 
                i += 1
                
        return tmp
