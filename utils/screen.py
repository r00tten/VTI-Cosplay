import os
import json
import time
import pprint

from typing import Dict, List

class printer:
    finished = False
    rows = -1
    columns = -1
    search = 0
    dTot = 0
    dCur = 0
    plat = None

    def __init__(self, 
                 plat: str) -> None:

        try:
            self.rows, self.columns = os.popen('stty size', 'r').read().split()
        except:
            self.columns = 80
            
        self.plat = plat
        sign = []
        sign.append("")
        sign.append("                                      ,(#*                                                   ")
        sign.append("                                      ,(#*.                                                  ")
        sign.append("                             *********(##*          ,**********.                             ")
        sign.append("                            .%%#////////*,         .,///////(%#,                             ")
        sign.append("                            .%%*                            *%#,                             ")
        sign.append("                            .%%*                            *%#,                             ")
        sign.append("                            .%%*                            *%#/,,,,,,                       ")
        sign.append("                                           ,(%%/.           ,(((((((((.                      ")
        sign.append("                                        ./#%%%%%%#*                                          ")
        sign.append("                                          *#%%%%(,                                           ")
        sign.append("                     /((((((((*.           ,(*.                                              ")
        sign.append("                      ,,*,*,*#%/.                          .*(*.                             ")
        sign.append("                            .(%/.                          ./%/.                             ")
        sign.append("                            .(%/.                          ./%/.                             ")
        sign.append("                            .(%#///////*.        .*/////////#%/.                             ")
        sign.append("                             **////////*.        .#%#/////////,.                             ")
        sign.append("                                                 .##/                                        ")
        sign.append("                                                 .##/                                        ")
        sign.append("                                                 ,,.                                         ")
        sign.append("")
        sign.append("██╗   ██╗████████╗██╗               ██████╗ ██████╗ ███████╗██████╗ ██╗      █████╗ ██╗   ██╗")
        sign.append("██║   ██║╚══██╔══╝██║              ██╔════╝██╔═══██╗██╔════╝██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝")
        sign.append("██║   ██║   ██║   ██║    █████╗    ██║     ██║   ██║███████╗██████╔╝██║     ███████║ ╚████╔╝ ")
        sign.append("╚██╗ ██╔╝   ██║   ██║    ╚════╝    ██║     ██║   ██║╚════██║██╔═══╝ ██║     ██╔══██║  ╚██╔╝  ")
        sign.append(" ╚████╔╝    ██║   ██║              ╚██████╗╚██████╔╝███████║██║     ███████╗██║  ██║   ██║   ")
        sign.append("  ╚═══╝     ╚═╝   ╚═╝               ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ")
        sign.append("")
        sign.append("")

        print('\n\r'.join(sign))

    def status(self, 
               finishedFalseStr: str, 
               finishedTrueStr: str, 
               statstaticStr: str) -> None:

        while not self.finished:
            print(f"[|] {finishedFalseStr} {statstaticStr}", end='\r')
            time.sleep(0.1)
            print(f"[/] {finishedFalseStr} {statstaticStr}", end='\r')
            time.sleep(0.1)
            print(f"[-] {finishedFalseStr} {statstaticStr}", end='\r')
            time.sleep(0.1)
            print(f"[\\] {finishedFalseStr} {statstaticStr}", end='\r')
            time.sleep(0.1)
            print(f"[|] {finishedFalseStr} {statstaticStr}", end='\r')
            time.sleep(0.1)
        print(f"[+] {finishedTrueStr} {statstaticStr}.   ")
        self.finished = False

    def searchStatus(self, 
                     statstaticStr: str) -> None:

        while not self.finished:
            print(f"[|] {statstaticStr}: {str(self.search)}", end='\r')
            time.sleep(0.1)
            print(f"[/] {statstaticStr}: {str(self.search)}", end='\r')
            time.sleep(0.1)
            print(f"[-] {statstaticStr}: {str(self.search)}", end='\r')
            time.sleep(0.1)
            print(f"[\\] {statstaticStr}: {str(self.search)}", end='\r')
            time.sleep(0.1)
            print(f"[|] {statstaticStr}: {str(self.search)}", end='\r')
            time.sleep(0.1)
        print(f"[+] {statstaticStr}: {str(self.search)}")
        self.search = 0
        self.finished = False

    def downloadStatus(self) -> None:

        print("[+] The samples is going to be downloaded.")
        while not self.finished:
            if self.dCur == 0:
                print("{}{:>90} {}/{}".format('[ ',
                                              ' ]', 
                                              self.dCur, 
                                              self.dTot), end='\r')
                time.sleep(0.1)
            else:
                print("{}{}{:>{}} {}/{}".format('[ ', 
                                                int(89 * self.dCur / self.dTot) * "█",
                                                ' ]',
                                                90 - int(89 * self.dCur / self.dTot), 
                                                self.dCur, 
                                                self.dTot), end='\r')
                time.sleep(0.1)
        print("{}{}{:>{}} {}/{}".format('[ ', 
                                        89 * "█", 
                                        ' ]', 
                                        1, 
                                        self.dCur, 
                                        self.dTot))
        self.download = 0
        self.finished = False

    def prettyPrint(self, 
                    data: List) -> bool:

        if data == None or data == []:
            return False

        try:
            pp = pprint.PrettyPrinter(indent=2,
                                      width=self.columns, 
                                      sort_dicts=False)
        except TypeError:
            pp = pprint.PrettyPrinter(indent=2, 
                                      width=self.columns)

        pp.pprint(data)