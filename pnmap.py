import nmap
import re
from datetime import datetime

def input_validation(ip, port):
    ip_valid = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    port_valid = re.compile(r'^(\d{1,5}|\d{1,5}\-\d{1,5})$')
    if ip_valid.search(ip) is None or port_valid.search(port) is None:
        return False
    else:
        return True

# https://xael.org/norman/python/python-nmap/
def simple_scan(ip, port):
    result = ""
    if input_validation(ip, port) is False:
        result = "ip or port is invalid"
        return False
    #print("Scan stated at {:%Y-%m-%d %H:%M:%S}".format(datetime.now()))
    nm = nmap.PortScanner()
    nm.scan(ip, port)
    #print("Scan finished at {:%Y-%m-%d %H:%M:%S}".format(datetime.now()))
    lists = nm.csv().split('\n')
    head = lists[0].split(';')
    for i in lists[1:]:
        for j,k in enumerate(i.split(';')):
            result += "{}: {}\n".format(head[j],k)
    return result


def main():
    print(simple_scan("54.213.199.92","2375"))



if __name__ == "__main__":
    main()