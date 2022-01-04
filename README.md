# VTI-Cosplay
This project is designed to be a solution for the lack of the VirusTotal Hunting license(_YARA search capability_). It uses VirusTotal's _Content Search_ feature to simulate YARA scanning. 

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

Content Search is really helpful when someone would like to deepen its search across VirusTotal's vast database. It is very similar to YARA. Certain byte patterns at a certain location can be easily searched. A YARA rule is contracted by a combination of patterns and conditions of them. So technically they are almost interchangeable. 

This project is a YARA interpreter for the VirusTotal. The working principle:
* Parsing the YARA rule 
* Creating queries for it
* Optimizing them to use less quota
* Making VirusTotal API requests
* Merging the results according to the rule's condition.

[![asciicast](https://asciinema.org/a/BMVqET0qPJ6didxzBMmMnAIgC.svg)](https://asciinema.org/a/BMVqET0qPJ6didxzBMmMnAIgC)

## Additional Features
Because at the end of the pipeline the VirusTotal API is used, it is completely possible to create a YARA rule that contains VirusTotal specific queries at the _condition_ part of the rule:
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
        "similar-to:0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198" or (filesize < 80KB and 1 of them ) or ( all of them )
}
~~~

In this example, VirusTotal's _similar-to_ capability is used to hunt more.

[![asciicast](https://asciinema.org/a/TfOveVMAj6BSH5rMe5dTv7bEw.svg)](https://asciinema.org/a/TfOveVMAj6BSH5rMe5dTv7bEw)

---
The other useful feature of the VTI-Cosplay is __action modules__. It gives an opportunity to take action against matched samples. In this way, one can send a Slack message or leave a comment for the sample on the VirusTotal without any hassle.

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
