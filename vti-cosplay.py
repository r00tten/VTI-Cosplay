#!/usr/bin/env python3

import os
import platform
import argparse
import importlib
import threading
import subprocess

from utils.scan import VTscan
from utils.record import logger
from utils.screen import printer
from utils.yaraParser import parser
from utils.download import doublecheck

from typing import Dict, List

def takeAction(
        mName: str, iDic: Dict) -> None:
    if (mName == "" or mName is None):
        return False

    aModule = importlib.import_module('actions.{}'.format(mName))
    mTrigget = aModule.trigger(iDic)


def main() -> None:
    plat = platform.system()
    s_printer = printer(plat)

    argumentParser = argparse.ArgumentParser("VTI-Cosplay")
    argumentParser.add_argument(
        '-y', '--yara-file',
        nargs=1,
        required=True,
        help='YARA file'
    )
    argumentParser.add_argument(
        '-k', '--api-key',
        nargs=1,
        required=False,
        help='Virustotal API key'
    )
    argumentParser.add_argument(
        '-l', '--limit',
        nargs=1,
        required=False,
        help='Limit total matched sample count')
    argumentParser.add_argument(
        '-a', '--action',
        nargs=1,
        required=False,
        help='Action module to trigger for matched samples')
    argumentParser.add_argument(
        '--livehunt',
        action='store_true',
        required=False,
        help='Create scheduled task for the YARA file provided.\
              When a new sample is out there it prints and stores')
    argumentParser.add_argument(
        '-f', '--fast',
        action='store_true',
        required=False,
        help='Fast scan by reducing the data that is transferred')
    argumentParser.add_argument(
        '-v', '--verbose',
        action='store_true',
        required=False,
        help='Verbose output')
    argumentParser.add_argument(
        '-i', '--i-dont-trust-you',
        nargs=1,
        required=False,
        help='At the end, it downloads matched files\
              and does YARA scan against them')
    args = argumentParser.parse_args()

    try:
        api_key = args.api_key[0]
    except TypeError as e:
        api_key = os.environ.get('VT_API_KEY')
    except Exception as e:
        print(e)
        exit()

    r_logger = logger(
        plat,
        s_printer,
        args.yara_file[0])
    livehunt = args.livehunt
    verbose = args.verbose
    fast = args.fast
    if (args.limit is not None):
        limit = args.limit[0]
    else:
        limit = 0

    if (args.i_dont_trust_you is not None):
        path = args.i_dont_trust_you[0]
    else:
        path = ""
        
    param = {
        'file': args.yara_file[0],
        'key': api_key,
        'limit': limit,
        'printer': s_printer,
        'logger': r_logger,
        'verbose': verbose,
        'fast': fast,
        'livehunt': livehunt}

    yara = parser(param)
    pDic = yara.parse()
    arr = pDic.get('arr', [])
    meta = pDic.get('meta', {})
    scan = VTscan(arr, param)
    res = scan.evaluate()

    if (args.i_dont_trust_you is not None):
        try:
            stdout, strerr = subprocess.Popen(
                ['yara', '-v'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()

            d_doublecheck = doublecheck(
                res, path,
                api_key, args.yara_file[0],
                s_printer)
            yRes = d_doublecheck.orchestrator()
        except FileNotFoundError as e:
            print(e)
            print("[-] YARA must be installed. \
                   I don't trust you scan is aborted.\n")
            d_doublecheck = None
            yRes = res
        finally:
            hList = yRes
    else:
        hList = res
        d_doublecheck = None

    if (args.action is not None and
            hList != [] and len(hList) > 0):
        try:
            thread1 = threading.Thread(
                target=s_printer.status,
                args=("Taking", "Took", "the actions",),
                daemon=True)
            thread1.start()
            paramA = {
                'res': hList,
                'meta': meta,
                'yara': args.yara_file[0],
                'key': api_key,
                'path': path
            }
            takeAction(args.action[0], paramA)
            s_printer.finished = True
            thread1.join()
        except Exception as e:
            print(e)

    if (hList != [] and len(hList) > 0):
        if (d_doublecheck is not None):
            r_logger.logResults(d_doublecheck.sArr)
        else:
            r_logger.logResults(hList)
        print()
        s_printer.prettyPrint(hList)

if (__name__ == "__main__"):
    main()
