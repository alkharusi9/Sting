#!/usr/bin/python3

import shodan
import requests
import sys
import datetime

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'




api_key = "{Your_API_Key_Here}"
api = shodan.Shodan(api_key)
target = sys.argv[1]

def banner():
    print(bcolors.FAIL + """%s     
    
                                                                 
           $$$$$$$$$$                                             
          $$             %%      $$                    $$$$$$$$$$$$$ v1.2
          $$           %%%%%%         $$              $$
            $$$$$$       %%      $$   $$ $$$$$$      $$
                 $$$     %%      $$   $$$$    $$     $$ 
                  $$$    %%      $$   $$      $$     $$           $$$$$      
                  $$     %%      $$   $$      $$      $$          $$$ %
           $$$$$$$$       %%%%%  $$   $$      $$        $$$$$$$$$$$$$ %     
                                                                
                                                      
                                              
                        
                        |%s%s                                                          
                        # Coded By Alsalt Alkharosi - @0x_pwner
            """ + bcolors.ENDC)


def Scanner():
    try:

        time = datetime.datetime.now()
        print(bcolors.OKBLUE+'Time:', time,bcolors.ENDC)
        if len(sys.argv) < 2:
            print(bcolors.FAIL + '[!] Usage: python3 sting.py <target>' + bcolors.ENDC)
            sys.exit(1)

        dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + api_key
        resolved = requests.get(dnsResolve)
        hostIP= resolved.json()[target]

        host = api.host(hostIP)

        print(bcolors.OKGREEN+'[*] IP: %s'%host['ip_str']+bcolors.ENDC)
        print(bcolors.OKGREEN+'[*] Organization: %s'% host.get('org')+bcolors.ENDC)
        print(bcolors.OKGREEN+'[*] Operating System: %s'% host.get('os')+bcolors.ENDC)

        for item in host['data']:
            print(bcolors.OKGREEN+'[*] Port %s'% item['port']+bcolors.ENDC)
            print(bcolors.OKGREEN+'[*] Banner: %s'%item['data']+bcolors.ENDC)

        for item in host['vulns']:
            Exploit = item.replace('!','')
            print(bcolors.WARNING+'[!] Vulnerability: %s'%item+bcolors.ENDC)
            exploits = api.exploits.search(Exploit)
            for item in exploits['matches']:
                if item.get('cve')[0] == Exploit:
                    print(item.get('description'))
    except Exception as e:
        print(e)
def dir_check():
    url = 'https://'+target+'/robots.txt'
    r = requests.get(url)
    if r.status_code == 200:
        print(bcolors.FAIL+'[!] robots.txt directory is found!'+bcolors.ENDC)
    else:
        pass
def X_XSS_Protection():
    try:
        url = 'https://'+target
        r = requests.get(url)
        if "X-XSS-Protection" in r.headers:
            print(bcolors.OKGREEN+'[*] X-XSS-Protection header exists!'+bcolors.ENDC)
        else:
            print(bcolors.WARNING+'[!] X-XSS-Protection header was not found!')
    except Exception as e:
        print(e)


def main():

    banner()
    Scanner()
    dir_check()
    X_XSS_Protection()


if __name__=='__main__':
   main()




        
