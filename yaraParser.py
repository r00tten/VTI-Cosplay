import re
import struct
import threading

from typing import Dict, List


class parser:
    file = ''
    meta = {}
    strings = []
    condition = []
    rules = []
    s_printer = None
    r_logger = None
    verbose = False

    def __init__(self, 
                 param: Dict) -> None:

        self.file = param.get('file', '')
        self.s_printer = param.get('printer', None)
        self.r_logger = param.get('logger', None)
        self.verbose = param.get('verbose', None)

    def clean(self, 
              data: List) -> List:
        if data is None:
            return False

        cleanedData = []
        multi = False
        line = ''

        for i in data:
            if (multi and re.search(r'([^\'\"])(.*)\*/(.*)([^\'\"])', i)):
                multi = False
                line = i.split('*/')[1]
                if (re.search(r'[^ \t\n]', line)):
                    cleanedData.append('{}'.format(line))
            elif (not multi and re.search(
                    r'([^\'\"])(.*)/\*(.*)([^\'\"])',
                    i)):
                line = i.split('/*')[0]
                if re.search(r'[^ \t\n]', line):
                    cleanedData.append('{}\n'.format(line))
                multi = True
            elif (not multi and re.search(
                    r'\/\/(?=([^\"\']*\"[^\"\']*\")*[^\"\']*$)',
                    i)):
                line = i.split('//')[0]
                if (re.search(r'[^ \t\n]', line)):
                    cleanedData.append('{}\n'.format(line))
            elif (not multi and i.replace(' ', '').find('\n') != -1 and
                    len(i.replace(' ', '')) <= 1):
                pass
            else:
                cleanedData.append(i)

        return cleanedData

    def stringParser(self) -> None:
        if (len(self.strings) <= 0):
            return False

        line = ''
        switch = -1
        start = -1
        end = -1
        context = ''
        modifier = ''
        mod = 0
        content = []

        for i in self.strings:
            if (i.find('$') != -1):
                line = i.split('=', 1)
                content.append(line[0].replace(' ', ''))
                context = line[1]

                for j in range(len(context)):
                    if (context[j] == '\"'):
                        switch = 1
                        start = j
                        break
                    elif (context[j] == '\''):
                        switch = 2
                        start = j
                        break
                    elif (context[j] == '{'):
                        switch = 3
                        start = j
                        break

                if (switch == 1):
                    for j in range(len(context) - 1, start, -1):
                        if (context[j] == '\"'):
                            end = j
                            break
                elif (switch == 2):
                    for j in range(len(context) - 1, start, -1):
                        if context[j] == '\'':
                            end = j
                            break
                elif (switch == 3):
                    for j in range(len(context) - 1, start, -1):
                        if (context[j] == '}'):
                            end = j
                            break

                content.append(context[start:end+1])

                if (switch != 3):
                    modifier = context[end+1:]

                    if (modifier.find('fullword') != -1):
                        mod += 1000
                    if (modifier.find('nocase') != -1):
                        mod += 0
                    if (modifier.find('wide') != -1):
                        mod += 10
                    if (modifier.find('ascii') != -1):
                        mod += 1
                else:
                    mod = 0

                content.append(mod)
                self.rules.append(content)

            mod = 0
            start = -1
            end = -1
            switch = -1
            content = []

    def conditionNormalizer(self, 
                            data: str) -> List:

        conStr = data
        temp = ''
        stack = []
        conStr = conStr.replace('\n', '')
        conStr = re.sub(r'[ ]+', ' ', conStr)
        conStr = conStr.replace(' & ', ' \n&\n')
        conStr = conStr.replace(' | ', ' \n|\n')
        for i in range(len(conStr)):
            if conStr[i] == '(':
                stack.append(i)
            elif conStr[i] == ')':
                stack.pop()

            if len(stack) > 0 and conStr[i] == '\n':
                temp += ' '
            else:
                temp += conStr[i]

        conStr = temp
        conStr = re.sub(r'^[ ]|[ ]$', '', conStr)
        conSpl = conStr.split('\n')

        for i in range(len(conSpl)):
            if re.search(r'^[(]', conSpl[i]) is not None:
                conSpl[i] = self.conditionNormalizer(conSpl[i][re.search(
                    r'\(',
                    conSpl[i]).span()[1]:re.search(
                        r'(?s:.*)[)]',
                        conSpl[i]).span()[1]-1])

        return conSpl

    def stringExpand(self, 
                     arr: List) -> List:

        if arr is None:
            return False
        exArr = []
        cond = int(arr[2])
        if cond == 0:
            exArr.append('content: ' + arr[1])
        elif cond % 1000 < 100:
            if cond % 10 == 1:
                exArr.append('content: ' + arr[1])
            if cond % 100 >= 10:
                tmp = 'content: {'
                for i in arr[1][1:len(arr[1])-1].encode():
                    tmp += hex(i).split('x')[1] + '00'
                tmp += '}'

                exArr.append(tmp)
        elif cond % 1000 >= 100:
            if cond % 10 == 1:
                tmp = 'content: {'
                for i in arr[1][1:len(arr[1])-1].encode():
                    if (i >= 65 and i <= 90):
                        tmp += '(' + hex(i).split('x')[1] + \
                                '|' + hex(i + 32).split('x')[1] + ')'
                    elif (i >= 97 and i <= 122):
                        tmp += '(' + hex(i).split('x')[1] + \
                                '|' + hex(i - 32).split('x')[1] + ')'
                    else:
                        tmp += hex(i).split('x')[1]
                tmp += '}'
                exArr.append(tmp)
            if (cond % 100 >= 10):
                tmp = 'content: {'
                tmp += hex(i).split('x')[1] + '00'
                tmp += '}'
                exArr.append(tmp)

        return exArr

    def conditionConverter(self, 
                           arr: List) -> List:

        if arr is None:
            return False

        for i in range(len(arr)):
            if (isinstance(arr[i], list)):
                arr[i] = self.conditionConverter(arr[i])
            elif (re.search(r'(^").+?(" $)', arr[i])):
                arr[i] = [re.search(r'(?<=(^")).+?(?=(" $))', arr[i]).group()]
            elif (re.search(r'uint[0-9]{1,2}\([0-9x]\)', arr[i])):
                tmp = arr[i].split(' ')
                content = tmp[2].split('x')[1]
                content = [
                    content[z:z+2]
                    for z in range(0, len(content), 2)][::-1]
                content = ''.join(content)
                arr[i] = ["content:{" + str(content) + "}@" + re.search(
                    r'(?<=\()[^\]\[\r\n]*(?=\))',
                    tmp[0]).group(0)]
            elif (re.search(r'filesize [=><]', arr[i])):
                tmp = arr[i].split(' ')
                if (re.search(r'<', tmp[1])):
                    arr[i] = ["size:" + tmp[2] + "-"]
                elif (re.search(r'>', tmp[1])):
                    arr[i] = ["size:" + tmp[2] + "+"]
                else:
                    arr[i] = ["size:" + tmp[2]]
            elif (re.search(r'for.*?in.?', arr[i])):
                print('for with in' + ' ' + str(arr[i]))
            elif (re.search(r'for.*?of.?', arr[i])):
                print('for with of' + ' ' + str(arr[i]))
            elif (re.search(r' at ', arr[i])):
                tmp = arr[i].split(' ')
                if (tmp[2].find('@') != -1):
                    continue

                atArr = []
                for j in self.rules:
                    if (tmp[0] == j[0]):
                        exStr = self.stringExpand(j)
                tmp[2] = re.sub(
                            r'^\(|\)$',
                            '',
                            tmp[2])

                for k in exStr:
                    atArr.append(k + '@' + tmp[2])

                arr[i] = atArr
            elif (re.search(r' in ', arr[i])):
                arr[i] = re.sub(r' (?=[^\(\)]*\))', '', arr[i])
                tmp = arr[i].split(' ')
                if (tmp[2].find('@') != -1):
                    if (re.search(
                            r"\((\@[a-zA-Z_]+)\.{2}\1+\+[0-9]+\)",
                            tmp[2])):
                        tmp[2] = re.search(
                            r'(?<=\().+?(?=\))',
                            tmp[2]).group()
                        addrStr = tmp[2].split('..')[0]
                        addrStr = re.sub('\@', '$', addrStr)
                        tmpStr = []
                        tmpStr2 = []
                        for j in self.rules:
                            if j[0] == addrStr:
                                tmpStr = j
                        j = 0
                        for j in self.rules:
                            if j[0] == tmp[0]:
                                tmpStr2 = j
                        if (re.search(r'^\".+?\"$', tmpStr[1])):
                            temp = 'content: { '
                            for k in tmpStr[1][1:len(tmpStr[1])-1].encode():
                                temp += hex(k).split('x')[1] + ' '
                            temp += '}'
                            tmpStr[1] = temp
                        if (re.search(r'^\".+?\"$', tmpStr2[1])):
                            temp = 'content: { '
                            for k in tmpStr2[1][1:len(tmpStr2[1])-1].encode():
                                temp += hex(k).split('x')[1] + ' '
                            temp += '}'
                            tmpStr2[1] = temp
                        arr[i] = [
                            'content: {' +
                            re.search(
                                r'(?<=\{).+?(?=\})',
                                tmpStr[1]).group() +
                            '[0-' +
                            tmp[2].split('..')[1].split('+')[1] + ']' +
                            re.search(
                                r'(?<=\{).+?(?=\})',
                                tmpStr2[1]).group() +
                            '}']
                    elif (re.search(
                            r"\((\@[a-zA-Z_]+)\+[0-9]+\.{2}\1+\+[0-9]+\)",
                            tmp[2])):
                        tmp[2] = re.search(
                            r'(?<=\().+?(?=\))',
                            tmp[2]).group()
                        addrStr = tmp[2].split('..')[0]
                        count = addrStr.split('+')[1]
                        addrStr = re.sub(r'\@', '$', addrStr.split('+')[0])
                        tmpStr = []
                        tmpStr2 = []
                        for j in self.rules:
                            if j[0] == addrStr:
                                tmpStr = j
                        j = 0
                        for j in self.rules:
                            if j[0] == tmp[0]:
                                tmpStr2 = j
                        if (re.search(r'^\".+?\"$', tmpStr[1])):
                            temp = 'content: { '
                            for k in tmpStr[1][1:len(tmpStr[1])-1].encode():
                                temp += hex(k).split('x')[1] + ' '
                            temp += '}'
                            tmpStr[1] = temp
                        if (re.search(r'^\".+?\"$', tmpStr2[1])):
                            temp = 'content: { '
                            for k in tmpStr2[1][1:len(tmpStr2[1])-1].encode():
                                temp += hex(k).split('x')[1] + ' '
                            temp += '}'
                            tmpStr2[1] = temp
                        arr[i] = [
                                'content: {' +
                                re.search(
                                    r'(?<=\{).+?(?=\})',
                                    tmpStr[1]).group() +
                                '[' + count + '-' +
                                tmp[2].split('..')[1].split('+')[1] +
                                ']' +
                                re.search(
                                    r'(?<=\{).+?(?=\})',
                                    tmpStr2[1]).group() +
                                '}']
                elif (re.search(r"\([0-9]+[\.]{2}[0-9]+\)", tmp[2])):
                    inArr = []
                    for j in self.rules:
                        if (tmp[0] == j[0]):
                            exStr = self.stringExpand(j)
                    tmp[2] = re.sub(r'^\(|\)$', '', tmp[2])
                    tmp[2] = re.sub(r'\.\.', '-', tmp[2])

                    for k in range(len(exStr)):
                        inArr.append([exStr[k] + '@' + tmp[2]])
                        if (k < len(exStr) - 1):
                            inArr.append('|')

                    arr[i] = inArr
            elif (re.search(r' of ', arr[i])):
                tmp = arr[i].split(' ')
                ofArr = []
                tmp[2] = re.sub(r'^\(|\)$', '', tmp[2])

                if (tmp[0] == 'all'):
                    for j in tmp[2].split(','):
                        j = re.sub('\$', '\\$', j)
                        if j.find('*') != -1:
                            j = re.sub('\*', '\\\w+', j)
                            for k in self.rules:
                                if (re.search(j, k[0])):
                                    ofArr.append(self.stringExpand(k))
                        elif (j == 'them'):
                            for k in self.rules:
                                ofArr.append(self.stringExpand(k))
                        else:
                            ofArr.append(self.stringExpand(k))
                    arr[i] = [len(ofArr), ofArr]
                elif (tmp[0] == 'any'):
                    for j in tmp[2].split(','):
                        j = re.sub('\$', '\\$', j)
                        if (j.find('*') != -1):
                            j = re.sub('\*', '\\\w+', j)
                            for k in self.rules:
                                if (re.search(j, k[0])):
                                    ofArr.append(self.stringExpand(k))
                        elif (j == 'them'):
                            for k in self.rules:
                                ofArr.append(self.stringExpand(k))
                        else:
                            ofArr.append(self.stringExpand(k))
                    arr[i] = [1, ofArr]
                elif (int(tmp[0])):
                    for j in tmp[2].split(','):
                        j = re.sub('\$', '\\$', j)
                        if (j.find('*') != -1):
                            j = re.sub('\*', '\\\w+', j)
                            for k in self.rules:
                                if (re.search(j, k[0])):
                                    ofArr.append(self.stringExpand(k))
                        elif (j == 'them'):
                            for k in self.rules:
                                ofArr.append(self.stringExpand(k))
                        else:
                            ofArr.append(self.stringExpand(k))
                    arr[i] = [int(tmp[0]), ofArr]
            elif (re.search(r'\$\w+', arr[i])):
                for j in self.rules:
                    if (arr[i].strip() == j[0].strip()):
                        arr[i] = self.stringExpand(j)
                        break

        return arr

    def conditionParser(self) -> List:
        if (self.condition is None):
            return ''

        conStr = ''

        for i in self.condition:
            conStr += i

        conStr = conStr.replace('\n', '')
        conStr = re.sub(r'[ ]+', ' ', conStr)
        conStr = conStr.replace(' and ', ' & ')
        conStr = conStr.replace(' or ', ' | ')

        conArr = []
        conArr = self.conditionNormalizer(conStr)
        conArr = self.conditionConverter(conArr)

        return conArr

    def parse(self) -> Dict:
        if (self.file is None):
            return False

        switch = 0

        try:
            with open(self.file, 'r') as yara:
                data = self.clean(yara)
                for i in data:
                    if (switch == 3 and not i.find('}') != -1):
                        self.condition.append(i)
                    elif (switch == 2 and
                            i.find('condition:') == -1 and
                            i.find('$') != -1):
                        self.strings.append(i)
                    elif (switch == 0 and
                            i.find('meta:') == -1):
                        if (re.search(
                                r'^([ \\t]?)rule([ ]?)',
                                i)):
                            self.meta['ruleName'] = re.search(
                                r'(?<=(rule )).+?(?=([ :{\n]+))',
                                i).group()
                    elif (switch == 1 and not re.search(
                            r'([ \t]*[^\'\"])strings:([ \t\n]*[^\'\"])',
                            i)):
                        if (re.search(r'[ \t]*author[ ]?=', i)):
                            self.meta['author'] = re.search(
                                r'(?<=(\'|\")).+?(?=(\1))',
                                i.split('=')[1]).group()
                        elif (re.search(r'[ \t]*description[ ]?=', i)):
                            self.meta['description'] = re.search(
                                r'(?<=(\'|\")).+?(?=(\1))',
                                i.split('=')[1]).group()
                        elif (re.search(r'[ \t]*reference[ ]?=', i)):
                            self.meta['reference'] = re.search(
                                r'(?<=(\'|\")).+?(?=(\1))',
                                i.split('=')[1]).group()

                    if (switch == 2 and i.find('condition:') != -1 and
                            i.find('$', 0, i.find('condition:')) == -1):
                        switch = 3
                    if (switch == 1 and i.find('strings:') != -1 and
                            (i.find('\'', 0, i.find('strings:')) == -1 or
                                i.find('\"', 0, i.find('strings:')) == -1)):
                        switch = 2
                    if switch == 0 and i.find('meta:') != -1:
                        switch = 1
        except FileNotFoundError:
            print('[-] Please provide a YARA file.\n')
            exit(0)

        thread1 = threading.Thread(
            target=self.s_printer.status,
            args=("Parsing", "Parsed", "the strings",),
            daemon=True)
        thread1.start()
        self.stringParser()
        self.s_printer.finished = True
        thread1.join()

        thread2 = threading.Thread(
            target=self.s_printer.status,
            args=("Parsing", "Parsed", "the condition",),
            daemon=True)
        thread2.start()
        conditionParsed = self.conditionParser()
        self.s_printer.finished = True
        thread2.join()

        if (self.verbose is True):
            self.s_printer.prettyPrint(conditionParsed)

        return {'arr': conditionParsed, 'meta': self.meta}
