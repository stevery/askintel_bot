import re
import os
import sys
import json
from pprint import pprint
import random
import requests
import optparse
import shodan
import hashlib
import base64
import platform as pf

mypf = pf.platform()
dir_path = os.path.dirname(os.path.abspath(__file__))
seperator = ""
if re.search(r'^windows', mypf, re.I):
    seperator = "\\"
elif re.search(r'^(linux|Darwin)', mypf, re.I):
    seperator = "/"
else:
    print("Not supported platform")
    print("your os is: {}".format(mypf))
    sys.exit(0)

lib_path = seperator.join(dir_path.split(seperator)[:-3])
sys.path.append(lib_path)

class EasyIntell:
    def __init__(self):
        try:
            json_data=open("{}{}api.json".format(dir_path,seperator)).read()
        except:
            print("If you run easyintell You need set api.json first")
            sys.exit(0)
        self.apis = json.loads(json_data)
        self.teletoken = self.apis["telegram"]
        self.result = {"virustotal":"",
                       "shodan":"",
                       "xfe":""}


    def ask_ip(self, query, itype, option=False):
        self.vt_get_report(query, itype)
        self.shodan_ip(query, option)
        self.xfe_get_report(query, itype)


    def ask_hash(self, query, itype, option=False):
        self.vt_get_report(query, itype)
        self.xfe_get_report(query, itype)

    
    def ask_domain(self, query, itype, option=False):
        self.vt_get_report(query, itype)
        self.xfe_get_report(query, itype)


    def ask_url(self, query, itype, option=False):
        self.vt_get_report(query, itype)
        self.xfe_get_report(query, itype)


    def get_vt_key(self):
        secure_random = random.SystemRandom()
        return secure_random.choice(self.apis["virustotal"]["key"])


    def vt_parser(self, vt):
        tmp = {}
        # for hash parse
        hash_filters = ["md5","sha1","sha256","positives","total","scan_date","permalink"]
        av_filters = ["ALYac","AhnLab-V3","Kaspersky","MAX","Malwarebytes","Microsoft","Symantec","ViRobot"]

        # for domain parse
        domain_filters = ["detected_communicating_samples", "detected_downloaded_samples", "detected_referrer_samples", 
                          "detected_urls", "resolutions"]
        # positive: malware ample is in vt
        if vt["response_code"] == 1 and 'md5' in vt:
            if 'md5' in vt:
                for key in hash_filters:
                    tmp[key] = vt[key]
                for key in av_filters:
                    tmp[key] = vt["scans"][key]
        else:
            print("Sample is not in vt")
            tmp = vt
        print(len(str(tmp)))
        return tmp



    def vt_get_report(self, query, type):
        try:
            print('Virustotal query start')
            vt_result = ""
            if type == 'ip':
                vt_sub = "/vtapi/v2/ip-address/report"
                payloads = {"ip": query, "apikey": self.get_vt_key()}
            elif type == 'hash':
                vt_sub = "/vtapi/v2/file/report"
                payloads = {"resource": query, "apikey": self.get_vt_key()}
            elif type == 'domain':
                vt_sub = '/vtapi/v2/domain/report'
                payloads = {"domain": query, "apikey": self.get_vt_key()}
            elif type == 'url':
                vt_sub = '/vtapi/v2/url/report'
                payloads = {"url": query, "apikey": self.get_vt_key()}
                
            vt_url = "{}{}".format(self.apis["virustotal"]["url"], vt_sub)
            
            r = requests.get(vt_url, params=payloads)
            print(r.url)
            pprint(json.loads(r.text))
            vt_result = json.loads(r.text)
            # self.vt_parser(vt_result)
            # self.result["virustotal"] = vt_result
            self.result["virustotal"] = self.vt_parser(vt_result)


        except Exception as e:
            print("Error: {}".format(e))
            self.result["virustotal"] = None
            pass


    def shodan_ip(self, query, full):
        try:
            print('Shodan query started')
            SHODAN_API_KEY = self.apis["shodan"]["key"]
            api = shodan.Shodan(SHODAN_API_KEY)
            # Lookup the host
            host = api.host(query)

            # Print general info
            if full is False:
                self.result['shodan'] = "IP: {}\nOrganization: {}\nOperating System: {}\n".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')).strip()
                print("IP: {}\nOrganization: {}\nOperating System: {}\n".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                # Print all banners
                for item in host['data']:
                    self.result['shodan'] += "Port: {}\nBanner: {}".format(item['port'], item['data']).strip()
                    print("Port: {}\nBanner: {}".format(item['port'], item['data']))
            else:
                pprint(host)
            
            #self.result["shodan"] = host

        except Exception as e:
            print("Error: {}".format(e))
            self.result["shodan"] = None
            pass


    def send_request(self, apiurl, scanurl, headers):
        fullurl = apiurl +  scanurl
        response = requests.get(fullurl, params='', headers=headers, timeout=20)
        all_json = response.json()
        print(json.dumps(all_json, indent=4, sort_keys=True)) 
        return all_json


    def xfe_get_report(self, query, itype):
        try:
            print('XFE query started')
            XFORCE_API_KEY = self.apis["xforce"]["key"]
            XFORCE_API_PW = self.apis["xforce"]["pw"]
            url = self.apis["xforce"]["url"]
            keys = XFORCE_API_KEY + ":" + XFORCE_API_PW
            token = base64.b64encode(keys.encode('utf-8')).decode("utf-8") 
            headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}

            if itype == 'ip':
                apiurl = url + "/ipr/malware/"
            elif itype == 'hash':
                apiurl = url + "/malware/"
            elif itype == 'domain' or itype == 'url':
                apiurl = url + "/url/malware/"
            
            self.result["xfe"] = self.send_request(apiurl, query, headers)
            
            '''if full is not False:
                apiurl = url + "/ipr/history/"
                self.send_request(apiurl, query, headers)
                apiurl = url + "/ipr/malware/"
                self.send_request(apiurl, query, headers)'''

        except Exception as e:
            print("Error: {}".format(e))
            self.result["xfe"] = None
            pass


    def output_json(self, input):
        print("my turn")
        with open("{}.json".format(input), "w") as fw:
            json.dump(self.result, fw, sort_keys=True, indent=4)

    def output_html(self, input):
        pass

        

def main():
    parser = optparse.OptionParser(usage="%prog [options] <arg1>")
    parser.add_option("--ip", dest="ip", type="string", help="input your [ip]")
    parser.add_option("-f", action="store_true", dest="full", default=False, help="this is an optional option to show extra info" )
    parser.add_option("--output", dest="output", type="string", default=None, help="input output type, json or html")
    (options, args) = parser.parse_args()
    ip = options.ip
    full = options.full
    output = options.output

    ei = EasyIntell()

    if ip is not None:
        itype = 'ip'    
        ei.vt_get_report(ip, itype)
        ei.shodan_ip(ip, full)
        ei.xfe_get_report(ip, itype)
    else:
        print(parser.usage)
        exit(0)
        
    
    if output is None:
        pass
    elif output == "json":
        ei.output_json(ip)
    elif output == "html":
        ei.output_html(ip)
    else:
        print("{} is Wrong output type".format(output))
        

if __name__ == "__main__":
    main()
