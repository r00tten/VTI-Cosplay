# VTI-Cosplay
vti-cosplay is a solution to the problem due to the lack of a Virustotal Enterprise license. First, it parses the YARA rule, maps each atomic entry to Virustotal API endpoints, and merges individual results. Subsequently, it mimics the YARA scan on the Virustotal platform.

~~~
r00tten@vti-cosplay VTI-Cosplay % python3 vti-cosplay.py -h

                                      ,(#*                                                   
                                      ,(#*.                                                  
                             *********(##*          ,**********.                             
                            .%%#////////*,         .,///////(%#,                             
                            .%%*                            *%#,                             
                            .%%*                            *%#,                             
                            .%%*                            *%#/,,,,,,                       
                                           ,(%%/.           ,(((((((((.                      
                                        ./#%%%%%%#*                                          
                                          *#%%%%(,                                           
                     /((((((((*.           ,(*.                                              
                      ,,*,*,*#%/.                          .*(*.                             
                            .(%/.                          ./%/.                             
                            .(%/.                          ./%/.                             
                            .(%#///////*.        .*/////////#%/.                             
                             **////////*.        .#%#/////////,.                             
                                                 .##/                                        
                                                 .##/                                        
                                                 ,,.                                         

██╗   ██╗████████╗██╗               ██████╗ ██████╗ ███████╗██████╗ ██╗      █████╗ ██╗   ██╗
██║   ██║╚══██╔══╝██║              ██╔════╝██╔═══██╗██╔════╝██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝
██║   ██║   ██║   ██║    █████╗    ██║     ██║   ██║███████╗██████╔╝██║     ███████║ ╚████╔╝ 
╚██╗ ██╔╝   ██║   ██║    ╚════╝    ██║     ██║   ██║╚════██║██╔═══╝ ██║     ██╔══██║  ╚██╔╝  
 ╚████╔╝    ██║   ██║              ╚██████╗╚██████╔╝███████║██║     ███████╗██║  ██║   ██║   
  ╚═══╝     ╚═╝   ╚═╝               ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   


usage: VTI-Cosplay [-h] -y YARA_FILE [-k API_KEY] [-l LIMIT] [-a ACTION]
                   [--livehunt] [-f] [-v] [-i I_DONT_TRUST_YOU]

optional arguments:
  -h, --help            show this help message and exit
  -y YARA_FILE, --yara-file YARA_FILE
                        YARA file
  -k API_KEY, --api-key API_KEY
                        Virustotal API key
  -l LIMIT, --limit LIMIT
                        Limit total matched sample count
  -a ACTION, --action ACTION
                        Action module to trigger for matched samples
  --livehunt            Create scheduled task for the YARA file provided. When
                        a new sample is out there it prints and stores
  -f, --fast            Fast scan by reducing the data that is transferred
  -v, --verbose         Verbose output
  -i I_DONT_TRUST_YOU, --i-dont-trust-you I_DONT_TRUST_YOU
                        At the end, it downloads matched files and does YARA
                        scan against them
~~~

VirusTotal's Content Search(VTGrep) capability provides pattern search in its database. On the other hand, a YARA rule is a combination of the patterns and their conditions. Therefore, a YARA rule can be mapped to a couple of Content Search queries to a certain extent. vti-cosplay interprets a rule and then evaluates different results to combine them with respect to the rule.

[![asciicast](https://asciinema.org/a/AAX1qkDVnFiDa5CFVO0y8NFXd.svg)](https://asciinema.org/a/AAX1qkDVnFiDa5CFVO0y8NFXd)

## Additional Features
At the end of the interpretation, the VirusTotal queries are searched. This provides to create hybrid rules, rules that contain plain VT queries in its condition part. In this way hunting process's range can be broadened.
~~~
rule Stuxnet_Malware_4 
{

    meta:
        description = "Stuxnet Sample - file 0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        hash2 = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
   
    strings:
        $x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
        $x2 = "MRxCls.sys" fullword wide
        $x3 = "MRXNET.Sys" fullword wide
    condition:
        "similar-to:0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198" 
        or 
        (filesize < 80KB and 1 of them ) 
        or 
        ( all of them )
}
~~~

In this example, VirusTotal's _similar-to_ capability is used to hunt more.

[![asciicast](https://asciinema.org/a/0zF6JGASnooaYIWjVGJ4Iez3Q.svg)](https://asciinema.org/a/0zF6JGASnooaYIWjVGJ4Iez3Q)

---
vti-cosplay's capability can be extended with action modules; further procedures can apply to the result. The goal can vary from sending a Slack message or adding a VT comment to downloading and running complex algorithms against the samples.

~~~
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
~~~
---
For the blog post of the project: https://r00tten.com/vti-cosplay/
