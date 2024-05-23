#!/usr/bin/env python3
#
#    AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import asyncio
import atexit
import argparse
from colorama import Fore, Style
from concurrent.futures import ProcessPoolExecutor, as_completed, FIRST_COMPLETED
import csv
import ipaddress as pis
import re
import socket
import os
import sys
import string
import time
import tldextract
import termios
import toml

def _quit():
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, TERM_FLAGS)

atexit.register(_quit)

TERM_FLAGS = termios.tcgetattr(sys.stdin.fileno())
verbose = 0
srvname = ''
#port_scan_profile = None
#port_scan_profiles_config = None
#service_scans_config = None
global_patterns = []
results = {}
osint_basic_profile = None

#username_wordlist = '/usr/share/seclists/Usernames/top-usernames-shortlist.txt'
#password_wordlist = '/usr/share/seclists/Passwords/darkweb2017-top100.txt'

rootdir = os.path.dirname(os.path.realpath(__file__))

single_target = False
only_scans_dir = False

def e(*args, frame_index=1, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {}

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    return string.Formatter().vformat(' '.join(args), args, vals)

def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {
        'bgreen':  Fore.GREEN  + Style.BRIGHT,
        'bred':    Fore.RED    + Style.BRIGHT,
        'bblue':   Fore.BLUE   + Style.BRIGHT,
        'byellow': Fore.YELLOW + Style.BRIGHT,
        'bmagenta': Fore.MAGENTA + Style.BRIGHT,

        'green':  Fore.GREEN,
        'red':    Fore.RED,
        'blue':   Fore.BLUE,
        'yellow': Fore.YELLOW,
        'magenta': Fore.MAGENTA,

        'bright': Style.BRIGHT,
        'srst':   Style.NORMAL,
        'crst':   Fore.RESET,
        'rst':    Style.NORMAL + Fore.RESET
    }

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    unfmt = ''
    if char is not None:
        unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, vals)
            break
        except KeyError as err:
            key = err.args[0]
            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end, file=file)

def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
    if verbose >= 2:
        cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def info(*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
    cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def warn(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def fail(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
    exit(-1)

def calculate_elapsed_time(start_time):
    elapsed_seconds = round(time.time() - start_time)

    m, s = divmod(elapsed_seconds, 60)
    h, m = divmod(m, 60)

    elapsed_time = []
    if h == 1:
        elapsed_time.append(str(h) + ' hour')
    elif h > 1:
        elapsed_time.append(str(h) + ' hours')

    if m == 1:
        elapsed_time.append(str(m) + ' minute')
    elif m > 1:
        elapsed_time.append(str(m) + ' minutes')

    if s == 1:
        elapsed_time.append(str(s) + ' second')
    elif s > 1:
        elapsed_time.append(str(s) + ' seconds')
    else:
        elapsed_time.append('less than a second')

    return ', '.join(elapsed_time)

osint_basic_profiles_config_file = 'osint-basic-profiles.toml'
with open(os.path.join(rootdir, 'config', osint_basic_profiles_config_file), 'r') as p:
    try:
        osint_basic_profiles_config = toml.load(p)

        if len(osint_basic_profiles_config) == 0:
            fail('There do not appear to be any osint scan profiles configured in the {osint_scan_profiles_config_file} config file.')

    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse {osint_basic_profiles_config_file} config file. Check syntax and duplicate tags.')

with open(os.path.join(rootdir, 'config', 'osint-scan-profiles.toml'), 'r') as c:
    try:
        osint_scans_config = toml.load(c)
    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse service-scans.toml config file. Check syntax and duplicate tags.')

with open(os.path.join(rootdir, 'config', 'global-patterns.toml'), 'r') as p:
    try:
        global_patterns = toml.load(p)
        if 'pattern' in global_patterns:
            global_patterns = global_patterns['pattern']
        else:
            global_patterns = []
    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse global-patterns.toml config file. Check syntax and duplicate tags.')


async def read_stream(stream, target, tag='?', patterns=[], color=Fore.BLUE):
    address = target.address

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(color + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)

            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        
                        
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n'))

            
            for p in patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('[*] {tag}' + ' => ' + p['description'] + '\n'))
                            with open(os.path.join(target.reportdir, 'csv', 'Patterns.csv'), 'a') as file:
                                writer_csv = csv.writer(file, delimiter=':')
                                _tool , _ipaddr, _subdom = tag.split(':')
                                _flag, _data = e(p['description']).split(':',1)
                                if 'sublist3r-ports' != _tool:
                                    writer_csv.writerow([_tool, _ipaddr, _subdom, _flag, _data])
                                else:    
                                    _tmp  = re.search(r'(?P<domain>[\w.-]+)\s+-\s+Found open ports:\s+(?P<ports>[\d,\s]+)', _data)
                                    _subdomm = str(_tmp.group('domain'))
                                    _ports = str(_tmp.group('ports'))
                                    writer_csv.writerow([_tool, _subdom, _subdomm, _flag, _ports])
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n'))
        else:
            break

async def run_cmd(semaphore, cmd, target, tag='?', patterns=[]):
    async with semaphore:
        address = target.address
        scandir = target.scandir

        info('Running task {bgreen}{tag}{rst} on {byellow}{address}{rst}') # + (' with {bblue}{cmd}{rst}' if verbose >= 1 else ''))

        async with target.lock:
            with open(os.path.join(scandir, '_commands.log'), 'a') as file:
                file.writelines(e('{cmd}\n\n'))

        start_time = time.time()
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
        async with target.lock:
            target.running_tasks.append(tag)

        await asyncio.wait([
            asyncio.create_task(read_stream(process.stdout, target, tag=tag, patterns=patterns)),
            asyncio.create_task(read_stream(process.stderr, target, tag=tag, patterns=patterns, color=Fore.RED))
        ])

        await process.wait()
        async with target.lock:
            target.running_tasks.remove(tag)
        elapsed_time = calculate_elapsed_time(start_time)

    if process.returncode != 0:
        error('Task {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
        async with target.lock:
            with open(os.path.join(scandir, '_errors.log'), 'a') as file:
                file.writelines(e('[*] Task {tag} returned non-zero exit code: {process.returncode}. Command: {cmd}\n'))
    else:
        info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')

    return {'returncode': process.returncode, 'name': 'run_cmd'}

async def parse_domains_detection(stream, tag, target, pattern):
    address = target.address
    # Check subdomains ends at the same _domain
    extract = tldextract.TLDExtract()
    _domain = str(extract(address).domain + '.' + extract(address).suffix)

    results = {}
    
    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(Fore.BLUE + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=Fore.BLUE)
            
            parse_match = re.search(pattern, line)
            
            _xydomain = str(parse_match.group('domain')) if parse_match and parse_match.group('domain') else None
            _ip = str(parse_match.group('ipaddress')) if parse_match and parse_match.group('ipaddress') else None
  
            if _xydomain and 'arpa' not in extract(_xydomain).fqdn and not _ip:
                if target.token != 'ipaddress' and _xydomain.endswith(_domain):
                    try:
                        _ip = socket.gethostbyname(_xydomain)
                        if _ip not in results.keys():
                            results[_ip] = [_xydomain]
                        elif _xydomain not in results[_ip]:
                            results[_ip].append(_xydomain)
                    except socket.gaierror:
                        error(_xydomain + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                        errors = True

            elif _xydomain and 'arpa' not in extract(_xydomain).fqdn and _ip:
                if target.token != 'domain':
                    if _ip not in results.keys():
                        results[_ip] = [_xydomain]
                    elif _xydomain not in results[_ip]:
                        results[_ip].append(_xydomain)
                else:
                    if _xydomain.endswith(_domain):
                        if _ip not in results.keys():
                            results[_ip] = [_xydomain]
                        elif _xydomain not in results[_ip]:
                            results[_ip].append(_xydomain)


            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))
            
        else:
            break
    
    return results

async def run_scans(semaphore, tag, target, scripts=None):
    async with semaphore:

        address = target.address
        scandir = target.scandir 

        command = e(scripts[0])
        pattern = scripts[1]
      
        info('Running OSINT scan {bgreen}{tag}{rst} on {byellow}{address}{rst}') # + (' with {bblue}{command}{rst}' if verbose >= 1 else ''))

        async with target.lock:
            with open(os.path.join(scandir, '_commands.log'), 'a') as file:
                file.writelines(e('{command}\n\n'))

        start_time = time.time()
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
        async with target.lock:
            target.running_tasks.append(tag)

        output = [
                parse_domains_detection(process.stdout, tag, target, pattern),
                read_stream(process.stderr, target, tag=tag, color=Fore.RED)
            ]
        
        
        results = await asyncio.gather(*output)

        await process.wait()
        async with target.lock:
            target.running_tasks.remove(tag)
        elapsed_time = calculate_elapsed_time(start_time)

        if process.returncode != 0:
            error('OSINT scan {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
            async with target.lock:
                with open(os.path.join(scandir, '_errors.log'), 'a') as file:
                    file.writelines(e('[*] OSINT scan {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
            return {'returncode': process.returncode}
        else:
            info('OSINT scan {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')
        

        return {'returncode': process.returncode, 'name': 'run_osintscan' , 'scans': results[0]}
    
async def scan_osint(loop, semaphore, target):
    address = target.address
    scandir = target.scandir
    pending = []
    _ip2domain, _domains = dict(), dict()

    for profile in osint_basic_profiles_config:
        if profile == osint_basic_profile:
            for scan, _token in osint_basic_profiles_config[profile].items():
                if  'domain' not in _token.keys():
                    _ip2domain[scan] = [osint_basic_profiles_config[profile][scan]['ipaddress']['command'],\
                                        osint_basic_profiles_config[profile][scan]['ipaddress']['pattern']]
                else:
                    _domains[scan] = [osint_basic_profiles_config[profile][scan]['domain']['command'],\
                                      osint_basic_profiles_config[profile][scan]['domain']['pattern']]
                    
        if target.token != 'domain':
            for scan, ip_scan in _ip2domain.items():
                pending.append(asyncio.create_task(run_scans(semaphore, scan, target, scripts=ip_scan)))
            break    
                
        else:
            for scan, domain_detection in _domains.items():
                pending.append(asyncio.create_task(run_scans(semaphore, scan, target, scripts=domain_detection)))
            break    
    
    results = {}

    while True:
                
        done, pending = await asyncio.wait(pending, return_when=FIRST_COMPLETED)
        
        for task in done:
            result = task.result()
            if result['returncode'] == 0 and result['name'] == 'run_osintscan':
                for _ip, _subdomains in result['scans'].items():
                    if all(isinstance(_subdomain, str) for _subdomain in _subdomains):
                        for _subdomain in _subdomains:
                            if _ip not in results.keys():
                                results[_ip] = [_subdomain]
                                flag = 'ip-subdomain'
                            elif _subdomain not in results[_ip]:
                                results[_ip].append(_subdomain)
                                flag = 'subdomain-recon'
                            else:
                                continue

                            #print(results)
                            # SCAN PROFILES FLAGS:
                            # domains-enum | subdomin | revlookup

                            if target.token != 'domain':
                                flag = 'revlookup'
                            elif address == _subdomain:
                                flag = 'domain-enum'
                        
                            domain = _subdomain
                            ipaddress = _ip
              
                            info('Found {bmagenta}{domain}{rst} at {bmagenta}{ipaddress}{rst} on target {byellow}{address}{rst}')

                            with open(os.path.join(target.reportdir, 'csv', 'IpSubdomain.csv'), 'a') as file:
                                writer_csv = csv.writer(file, delimiter=':')
                                writer_csv.writerow([ipaddress,domain])
                        
                            if not only_scans_dir:
                                with open(os.path.join(target.reportdir, 'notes.txt'), 'a') as file:
                                    file.writelines(e('[*] {domain} found on {ipaddress}\n'))

                            for domain_scan in osint_scans_config:
                                ignore_service = False
                                if ignore_service:
                                    continue
                            
                                matched_service = False

                                if 'service-names' in osint_scans_config[domain_scan]:
                                    for service_name in osint_scans_config[domain_scan]['service-names']:
                                        if re.search(service_name,flag):
                                            matched_service = True
                                            break

                                if not matched_service:
                                    continue

                                if 'manual' in osint_scans_config[domain_scan]:
                                    heading = False
                                    with open(os.path.join(scandir, '_manual_commands.txt'), 'a') as file:
                                        for manual in osint_scans_config[domain_scan]['manual']:
                                            if 'description' in manual:
                                                if not heading:
                                                    file.writelines(e('[*] {domain} on {ipaddress}\n\n'))
                                                    heading = True
                                                description = manual['description']
                                                file.writelines(e('\t[-] {description}\n\n'))
                                            if 'commands' in manual:
                                                if not heading:
                                                    file.writelines(e('[*] {domain} on {ipaddress}\n\n'))
                                                    heading = True
                                                for manual_command in manual['commands']:
                                                    manual_command = e(manual_command)
                                                    file.writelines('\t\t' + e('{manual_command}\n\n'))
                                        if heading:
                                            file.writelines('\n')
                                if 'scan' in osint_scans_config[domain_scan]:
                                    for scan in osint_scans_config[domain_scan]['scan']:

                                        if 'name' in scan:
                                            name = scan['name']
                                            if 'command' in scan:
                                                tag = e('{name}:{ipaddress}:{domain}')
                                                command = scan['command']

                                                if 'run_once' in scan and scan['run_once'] == True:
                                                    scan_tuple = (name,)
                                                    if scan_tuple in target.scans:
                                                        warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + domain + Style.NORMAL + '] Scan should only be run once and it appears to have already been queued. Skipping.' + Fore.RESET)
                                                        continue
                                                    else:
                                                        target.scans.append(scan_tuple)
                                                else:
                                                    scan_tuple = (ipaddress, domain, name)
                                                    if scan_tuple in target.scans:
                                                        warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + domain + Style.NORMAL + '] Scan appears to have already been queued, but it is not marked as run_once in service-scans.toml. Possible duplicate tag? Skipping.' + Fore.RESET)
                                                        continue
                                                    else:
                                                        target.scans.append(scan_tuple)
                                                patterns = []
                                                if 'pattern' in scan:
                                                    patterns = scan['pattern']

                                                pending.add(asyncio.create_task(run_cmd(semaphore, e(command), target, tag=tag, patterns=patterns)))



def scan_xxxx(target, concurrent_scans):
    
    start_time = time.time()
    info('Scanning target {byellow}{target.address}{rst}')

    if target.token == 'domain':
        basedir = os.path.abspath(os.path.join(outdir, target.address))
    else:
        basedir = os.path.abspath(os.path.join(outdir, 'revlookup'))

    target.basedir = basedir
    os.makedirs(basedir, exist_ok=True)

    if not only_scans_dir:
        reportdir = os.path.abspath(os.path.join(basedir, 'report'))
        target.reportdir = reportdir
        os.makedirs(reportdir, exist_ok=True)

        os.makedirs(os.path.abspath(os.path.join(reportdir, 'csv')), exist_ok=True)    
    
    scandir = os.path.abspath(os.path.join(basedir, 'scans'))

    target.scandir = scandir
    os.makedirs(scandir, exist_ok=True)

    os.makedirs(os.path.abspath(os.path.join(scandir, 'recon')), exist_ok=True)
    os.makedirs(os.path.abspath(os.path.join(scandir, 'files')), exist_ok=True)
    os.makedirs(os.path.abspath(os.path.join(scandir, 'ports')), exist_ok=True)
    os.makedirs(os.path.abspath(os.path.join(scandir, 'vulns')), exist_ok=True)
    os.makedirs(os.path.abspath(os.path.join(scandir, 'web')), exist_ok=True)
    os.makedirs(os.path.abspath(os.path.join(scandir, 'info')), exist_ok=True)

    # Use a lock when writing to specific files that may be written to by other asynchronous functions.
    target.lock = asyncio.Lock()

    # Get event loop for current process.
    loop = asyncio.get_event_loop()

    # Create a semaphore to limit number of concurrent scans.
    semaphore = asyncio.Semaphore(concurrent_scans)

    try:
        loop.run_until_complete(scan_osint(loop, semaphore, target))
        elapsed_time = calculate_elapsed_time(start_time)
        info('Finished scanning target {byellow}{target}{rst} in {elapsed_time}')
    except KeyboardInterrupt:
        sys.exit(1)


class Target:
    def __init__(self, address, token):
        self.address = address
        self.token = token
        self.basedir = ''
        self.reportdir = ''
        self.scandir = ''
        self.scans = []
        self.lock = None
        self.running_tasks = []
        


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OSINT Enumeration')
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="*")
    parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', help='Read only IP address from file, every domain will be translate to ip.')
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=2, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=3, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--profile', action='store', default='default', dest='profile_name', help='The port scanning profile to use (defined in port-scan-profiles.toml). Default: %(default)s')
    parser.add_argument('-o', '--output', action='store', default='osint', dest='output_dir', help='The output directory for results. Default: %(default)s')
    parser.add_argument('--single-target', action='store_true', default=False, help='Only scan a domain or a list of ipaddress. A directory named after the target will not be created. Instead, the directory structure will be created within the output directory. Default: false')
    parser.add_argument('--only-scans-dir', action='store_true', default=False, help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running. Default: false')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    single_target = args.single_target
    
    only_scans_dir = args.only_scans_dir
    errors = False
    
    if args.concurrent_targets <= 0:
        error('Argument -ch/--concurrent-targets: must be at least 1.')
        errors = True
    
    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        error('Argument -ct/--concurrent-scans: must be at least 1.')
        errors = True

    osint_basic_profile = args.profile_name

    found_scan_profile = False
    for profile in osint_basic_profiles_config:
        if profile == osint_basic_profile:
            found_scan_profile = True
            for scan in osint_basic_profiles_config[profile]:
                if 'domain' in osint_basic_profiles_config[profile][scan]:
                    if 'command' not in osint_basic_profiles_config[profile][scan]['domain']:
                        error('The {profile}.{scan}.domain section does not have a command defined. Every domain section must have a command.')
                        errors = True
                elif 'ipaddress' in osint_basic_profiles_config[profile][scan]:
                    if 'command' not in osint_basic_profiles_config[profile][scan]['ipaddress']:
                        error('The {profile}.{scan}.ipaddress section does not have a command defined. Every ipaddress section must have a command.')
                        errors = True
                elif 'domain' not in osint_basic_profiles_config[profile][scan]:
                    error('The {profile}.{scan} scan do not have defined domain section for domain recognition. Every osint scan must at least have a domain and ipaddress section defined with a command.')
                    errors = True
                elif 'ipaddress' not in osint_basic_profiles_config[profile][scan]:
                    error('The {profile}.{scan} scan do not have defined ipaddress section  for ip to domain. Every osint scan must at least have a domain and ipaddress section defined with a command.')
                    errors = True
                
            break

    if not found_scan_profile:
        error('Argument --profile: must reference a osint scan profile defined in {osint_scan_profiles_config_file}. No such profile found: {osint_scan_profile}')
        errors = True
    
    outdir = args.output_dir
    srvname = ''
    verbose = args.verbose

    raw_targets = args.targets
    
    targets = []
    
    if len(args.target_file) > 0:
        if not os.path.isfile(args.target_file):
            error('The target file {args.target_file} was not found.')
            sys.exit(1)
        try:
            with open(args.target_file, 'r') as f:
                lines = f.read()
                for line in lines.splitlines():
                    if line.startswith('#') or len(line) == 0: continue
                    if line not in raw_targets:
                        #print(raw_targets)
                        raw_targets.append(line)                
        except OSError:
            error('The target file {args.target_file} could not be read.')
            sys.exit(1)
    
    if len(raw_targets) > 1:
        targets_net = [str(pis.ip_network(target, strict=False)) for target in raw_targets]
        for _tmp in targets_net:
            if _tmp not in targets:
                targets.append(_tmp)
                token = 'ipaddress'
    
    for target in raw_targets:
        if single_target:
            try:
                _tmp = tldextract.extract(target)
                _dom = str(_tmp.domain + '.' + _tmp.suffix)
                if _dom not in targets:
                    targets.append(_dom)
                    token = 'domain'
            except ValueError:
                               
                try:
                    _ip = str(pis.ip_network(target))
                    if _ip not in targets:
                        targets.append(_ip)
                        token = 'ipaddress'
                except ValueError:
                    error(target + 'does not appear to be a valid IP address or domain,')
                    errors = True

        try:
            target_range = pis.ip_network(target, strict=False)
            if not args.disable_sanity_checks and target_range.num_addresses > 256:
                error(target + ' contains ' + str(target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. If it is, re-run with the --disable-sanity-checks option to suppress this check.')
                errors = True
            elif target_range not in targets:
                target_range = str(target_range)
                targets.append(target_range)
                token = 'ipaddress'
        except ValueError:

            try:
                ip = socket.gethostbyname(target)
                   
                if target not in targets:
                    targets.append(target)
                    token = 'ipaddress'
            except socket.gaierror:
                error(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                errors = True
        
    if len(targets) == 0:
        error('You must specify at least one target to scan!')
        errors = True

    if not args.disable_sanity_checks and len(targets) > 256:
        error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if errors:
        sys.exit(1)
    
    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        start_time = time.time()
        futures = []

        for target_net in targets:
            target = Target(target_net, token)
            futures.append(executor.submit(scan_xxxx, target, concurrent_scans))

        try:
            for future in as_completed(futures):
                try:
                    future.result()
                except (KeyError, ValueError):
                    continue
                
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            sys.exit(1)

        elapsed_time = calculate_elapsed_time(start_time)
        info('{bgreen}Finished scanning all targets in {elapsed_time}!{rst}')
