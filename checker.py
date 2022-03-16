#!/usr/bin/python3

import subprocess
import sys
import argparse
import datetime
import os

### ============================
class scaner:
    def __init__(self):
        self.port = 443
        self.ciphers = ['ECDHE-ECDSA-AES256-SHA',
'ECDHE-RSA-AES256-SHA',
'DHE-RSA-AES256-SHA',
'ECDHE-ECDSA-AES128-SHA',
'ECDHE-RSA-AES128-SHA',
'DHE-RSA-AES128-SHA',
'ECDHE-PSK-AES256-CBC-SHA',
'SRP-RSA-AES-256-CBC-SHA',
'SRP-AES-256-CBC-SHA',
'RSA-PSK-AES256-CBC-SHA',
'DHE-PSK-AES256-CBC-SHA',
'AES256-SHA',
'PSK-AES256-CBC-SHA',
'ECDHE-PSK-AES128-CBC-SHA',
'SRP-RSA-AES-128-CBC-SHA',
'SRP-AES-128-CBC-SHA',
'RSA-PSK-AES128-CBC-SHA',
'DHE-PSK-AES128-CBC-SHA',
'AES128-SHA',
'PSK-AES128-CBC-SHA']
        self.verbose = False
        self.output = './'

    def show_details(self):
        try:
            print('[*] Target IPs:')
            for item in self.targets:
                print('- {}'.format(item))
            print('[*] Target port:', self.port)
            print('[*] Target path:', self.output)
            print('[*] Target ciphers:')
            for item in self.ciphers:
                print('- {}'.format(item))
        except Exception as error:
            print('[!] Showing details error:', error)

    def start_scan(self):
        try:
            for ip_item in self.targets:
                print('[*] Checking {}'.format(ip_item))
                for cip_item in self.ciphers:
                    if self.verbose: print('> {}'.format(cip_item), end='')
                    try:
                        answ = self.__check_cipher(ip_item, cip_item)
                        if answ == 0:
                            if self.verbose: print(' [+]')
                            with open(os.path.join(self.output, 'success.txt'), 'a') as f_obj:
                                f_obj.write('[+] ' + datetime.datetime.utcnow().strftime('%y.%m.%d.%H:%M:%S') + ' | ' + '{} accepted {}\n'.format(ip_item, cip_item))
                        elif answ == 1:
                            if self.verbose: print(' [-]')
                            with open(os.path.join(self.output, 'rejects.txt'), 'a') as f_obj:
                                f_obj.write('[-] ' + datetime.datetime.utcnow().strftime('%y.%m.%d.%H:%M:%S') + ' | ' + '{} rejected {}\n'.format(ip_item, cip_item))
                        elif answ == 2:
                            if self.verbose: print(' [?]')
                            with open(os.path.join(self.output, 'no_answ.txt'), 'a') as f_obj:
                                f_obj.write('[-] ' + datetime.datetime.utcnow().strftime('%y.%m.%d.%H:%M:%S') + ' | ' + '{} didn\'t answered\n'.format(ip_item, cip_item))
                    except Exception as error:
                        print('[-] Error: {}'.format(error))
        except Exception as error:
            print('[!] Scan process error:', error)
            exit()
    
    def __check_cipher(self, ip, cip):
        try:
            cmd = ['timeout','1','openssl', 's_client', '-connect', '{}:{}'.format(ip, self.port), '-cipher', cip]
            all_data = subprocess.run(cmd, capture_output=True)
            data = all_data.stdout.decode().strip() + all_data.stderr.decode().strip()
            with open(os.path.join(self.output, 'log.txt'),'a') as f_obj:
                f_obj.write('='*32+'\n[*] ' + datetime.datetime.utcnow().strftime('%y.%m.%d.%H:%M:%S') + ' | ' + '{}\n'.format(data))
            if data == '':
                return 2
            if 'Secure Renegotiation IS supported' in data:
                return 0
            return 1
        except Exception as error:
            print('[!] Request error:', error)
            return 2

### ============================
def args():
    try:
        scan_obj = scaner()
        parser = argparse.ArgumentParser(description='Small script to check SSL ciphersuits.', formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('--clear', dest='clear', action='store_true', help='Clear all log files before run.')
        parser.add_argument('--scope', dest='scope_file', action='store', type=argparse.FileType('r'), help='File with IP scope.')
        parser.add_argument('--ip', dest='scope_ip', action='store', help='Single IP to check.')
        parser.add_argument('--port', dest='target_port', action='store', help='Port to check. Default: 443')
        parser.add_argument('--ciphers', dest='ciph_file', action='store', type=argparse.FileType('r'), help='File with Ciphers. Default: SHA1')
        parser.add_argument('--output', dest='output', action='store', help='Output dir. Default: ./')
        parser.add_argument('--verbose', dest='verbose', action='store_true', help='Print all results.')
        if len(sys.argv)==1:
            parser.print_help(sys.stderr)
            exit()
    
        parser = parser.parse_args()
        if parser.clear:
            clear_files()
        if parser.scope_file and parser.scope_ip:
            print('[-] Either scope list or 1 IP. I\'m lazy ;)')
            exit()
        if parser.scope_file:
            scan_obj.targets = strip_targets(parser.scope_file)
        elif parser.scope_ip:
            scan_obj.targets = [parser.scope_ip]
        else:
            print('[-] No target. ')
            exit()
        if parser.verbose: scan_obj.verbose = True
        if parser.target_port: scan_obj.port = parser.target_port
        if parser.output: 
            if os.path.isdir(parser.output): 
                scan_obj.output = parser.output
            else: 
                print('[-] No such directory :(')
                exit()
            
        ### Init ciphers 
        if parser.ciph_file:
            scan_obj.ciphers = strip_targets(parser.ciph_file)
        return scan_obj
    except Exception as error:
        print('[!] Init error:', error)
        exit()

### ============================
def strip_targets(target_f):
    try:
        result = []
        for item in target_f:
            item = item.strip()
            if not item == '': result.append(item)
        return result
    except Exception as error:
        print('[!] Strip error:', error)
        exit()

def clear_files():
    open(os.path.join(self.output, 'log.txt'), 'w')
    open(os.path.join(self.output, 'success.txt'), 'w')
    open(os.path.join(self.output, 'no_answ.txt'), 'w')
    open(os.path.join(self.output, 'rejects.txt'), 'w')

### ============================
if __name__ == '__main__':
    scan_obj = args()
    print('[*] Starting...\nGot {} IP\nGot {} Ciphers'.format(len(scan_obj.targets), len(scan_obj.ciphers)))
    if scan_obj.verbose: scan_obj.show_details()
    scan_obj.start_scan()
