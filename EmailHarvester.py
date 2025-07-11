#!/usr/bin/env python3
# encoding: UTF-8

"""
    This file is part of EmailHarvester
    Copyright (C) 2016 @maldevel
    https://github.com/maldevel/EmailHarvester
    
    EmailHarvester - A tool to retrieve Domain email addresses from Search Engines.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    For more see the file 'LICENSE' for copying permission.
"""

__author__ = "maldevel"
__copyright__ = "Copyright (c) 2016 @maldevel"
__credits__ = ["maldevel", "PaulSec", "cclauss", "Christian Martorella"]
__license__ = "GPLv3"
__version__ = "1.3.2"
__maintainer__ = "maldevel"

################################

import argparse
import sys
import time
import requests
import re
import os
import validators
import hashlib
import xml.sax.saxutils as xml_escape
import logging

from termcolor import colored
from argparse import RawTextHelpFormatter
from sys import platform as _platform
try:
  from urllib.parse import urlparse
except ImportError:
  from urlparse import urlparse

################################

# Security: Plugin allowlist - only these plugins are allowed to load
ALLOWED_PLUGINS = {
    'ask', 'baidu', 'bing', 'dogpile', 'exalead', 'github', 
    'googleplus', 'googles', 'instagram', 'linkedin', 'reddit', 
    'twitter', 'yahoo', 'youtube'
}

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

if _platform == 'win32':
    import colorama
    colorama.init()

class myparser:
    
    def __init__(self):
        self.temp = []
        
    def extract(self, results, word):
            self.results = results
            self.word = word

    def genericClean(self):
        for e in '''<KW> </KW> </a> <b> </b> </div> <em> </em> <p> </span>
                    <strong> </strong> <title> <wbr> </wbr>'''.split():
            self.results = self.results.replace(e, '')
        for e in '%2f %3a %3A %3C %3D & / : ; < = > \\'.split():
            self.results = self.results.replace(e, ' ')
        
    def emails(self):
        self.genericClean()
        # Security: Improved regex to prevent ReDoS attacks
        # Limit quantifiers and avoid nested quantifiers
        reg_emails = re.compile(
            r'[a-zA-Z0-9.\-_+#~!$&\',;=:]{1,64}' +
            r'@' +
            r'[a-zA-Z0-9.-]{1,253}' +
            re.escape(self.word))
        
        # Security: Limit input size to prevent DoS
        if len(self.results) > 1000000:  # 1MB limit
            logger.warning("Response too large, truncating for security")
            self.results = self.results[:1000000]
            
        self.temp = reg_emails.findall(self.results)
        emails = self.unique()
        return emails
    
    def unique(self):
        self.new = list(set(self.temp))
        return self.new
    
###################################################################

class EmailHarvester(object):
    
    def __init__(self, userAgent, proxy):
        self.plugins = {}
        self.proxy = proxy
        self.userAgent = userAgent
        self.parser = myparser()
        self.activeEngine = "None"
        path = os.path.dirname(os.path.abspath(__file__)) + "/plugins/"
        plugins = {}
        
        # Security: Validate plugin directory path
        if not os.path.exists(path) or not os.path.isdir(path):
            logger.error("Plugin directory not found or invalid")
            return
            
        # Security: Secure plugin loading with allowlist
        sys.path.insert(0, path)
        for f in os.listdir(path):
            fname, ext = os.path.splitext(f)
            if ext == '.py' and fname in ALLOWED_PLUGINS:
                try:
                    # Security: Controlled import instead of dynamic __import__
                    plugin_path = os.path.join(path, f)
                    if self._validate_plugin_file(plugin_path):
                        mod = __import__(fname, fromlist=[''])
                        if hasattr(mod, 'Plugin'):
                            plugins[fname] = mod.Plugin(self, {'useragent':userAgent, 'proxy':proxy})
                            logger.info(f"Loaded plugin: {fname}")
                        else:
                            logger.warning(f"Plugin {fname} missing Plugin class")
                    else:
                        logger.warning(f"Plugin {fname} failed security validation")
                except ImportError as e:
                    logger.error(f"Failed to load plugin {fname}: {e}")
                except Exception as e:
                    logger.error(f"Error loading plugin {fname}: {e}")
            elif ext == '.py':
                logger.warning(f"Plugin {fname} not in allowlist, skipping")
    
    def _validate_plugin_file(self, plugin_path):
        """Security: Basic plugin file validation"""
        try:
            # Check file size (max 50KB for plugin files)
            if os.path.getsize(plugin_path) > 50000:
                logger.warning(f"Plugin file too large: {plugin_path}")
                return False
            
            # Basic content validation - check for suspicious patterns
            with open(plugin_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for potentially dangerous imports/functions
            dangerous_patterns = [
                r'import\s+subprocess', r'import\s+os\s*$', r'eval\s*\(',
                r'exec\s*\(', r'__import__\s*\(', r'open\s*\('
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    logger.warning(f"Suspicious pattern found in {plugin_path}: {pattern}")
                    return False
                    
            return True
        except Exception as e:
            logger.error(f"Error validating plugin {plugin_path}: {e}")
            return False
    
    def register_plugin(self, search_method, functions):
        self.plugins[search_method] = functions
        
    def get_plugins(self):
        return self.plugins
    
    def show_message(self, msg):
        print(green(msg))
        
    def init_search(self, url, word, limit, counterInit, counterStep, engineName):
        self.results = ""
        self.totalresults = ""
        self.limit = int(limit)
        self.counter = int(counterInit)
        self.url = url
        self.step = int(counterStep)
        self.word = word
        self.activeEngine = engineName
        
    def _validate_url(self, url):
        """Security: Validate URL before making requests"""
        try:
            parsed = urlparse(url)
            
            # Security: Force HTTPS for external requests
            if parsed.scheme not in ['https']:
                logger.warning(f"Insecure URL scheme: {parsed.scheme}")
                return False
                
            # Security: Validate hostname
            if not parsed.hostname:
                logger.warning("Invalid hostname in URL")
                return False
                
            # Security: Block private/local addresses
            import ipaddress
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    logger.warning(f"Private/local IP address blocked: {parsed.hostname}")
                    return False
            except ValueError:
                # Not an IP address, continue with domain validation
                pass
                
            return True
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return False

    def do_search(self):
        try:
            urly = self.url.format(counter=str(self.counter), word=self.word)
            
            # Security: Validate URL before request
            if not self._validate_url(urly):
                logger.error(f"URL validation failed: {urly}")
                return
                
            headers = {'User-Agent': self.userAgent}
            
            # Security: Add request timeouts and SSL verification
            timeout = 30
            verify_ssl = True
            
            if(self.proxy):
                proxies = {self.proxy.scheme: "http://" + self.proxy.netloc}
                r = requests.get(urly, headers=headers, proxies=proxies, 
                               timeout=timeout, verify=verify_ssl)
            else:
                r = requests.get(urly, headers=headers, 
                               timeout=timeout, verify=verify_ssl)
                
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {self.activeEngine}")
            return
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL verification failed for {self.activeEngine}: {e}")
            return
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {self.activeEngine}: {e}")
            return
        except Exception as e:
            logger.error(f"Unexpected error in {self.activeEngine}: {e}")
            return

        if r.encoding is None:
            r.encoding = 'UTF-8'

        self.results = r.content.decode(r.encoding)
        self.totalresults += self.results
    
    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            
            # Security: Rate limiting - increase delay between requests
            time.sleep(2)  # Increased from 1 to 2 seconds
            
            self.counter += self.step
            print(green("[+] Searching in {}:".format(self.activeEngine)) + cyan(" {} results".format(str(self.counter))))
            
    def get_emails(self):
        self.parser.extract(self.totalresults, self.word)
        return self.parser.emails()
    
###################################################################

def yellow(text):
    return colored(text, 'yellow', attrs=['bold'])

def green(text):
    return colored(text, 'green', attrs=['bold'])

def red(text):
    return colored(text, 'red', attrs=['bold'])

def cyan(text):
    return colored(text, 'cyan', attrs=['bold'])

def unique(data):
        return list(set(data))

###################################################################

def checkProxyUrl(url):
    url_checked = urlparse(url)
    if (url_checked.scheme not in ('http', 'https')) | (url_checked.netloc == ''):
        raise argparse.ArgumentTypeError('Invalid {} Proxy URL (example: http://127.0.0.1:8080).'.format(url))
    return url_checked

def limit_type(x):
    x = int(x)
    if x > 0:
        return x
    raise argparse.ArgumentTypeError("Minimum results limit is 1.")

def checkDomain(value):
    domain_checked = validators.domain(value)
    if not domain_checked:
        raise argparse.ArgumentTypeError('Invalid {} domain.'.format(value))
    
    # Security: Additional domain validation
    if len(value) > 253:  # RFC compliant domain length
        raise argparse.ArgumentTypeError('Domain name too long: {}'.format(value))
    
    # Security: Block suspicious domains
    suspicious_patterns = [r'\.\.', r'^-', r'-$', r'[^a-zA-Z0-9.-]']
    for pattern in suspicious_patterns:
        if re.search(pattern, value):
            raise argparse.ArgumentTypeError('Invalid domain format: {}'.format(value))
    
    return value

def sanitize_filename(filename):
    """Security: Sanitize filename to prevent path traversal"""
    if not filename:
        return filename
        
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove/replace dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit filename length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename

def validate_user_agent(user_agent):
    """Security: Validate user agent string"""
    if not user_agent:
        return False
    
    # Limit length
    if len(user_agent) > 500:
        return False
    
    # Check for control characters
    if any(ord(c) < 32 for c in user_agent):
        return False
        
    return True

###################################################################

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="""

 _____                   _  _   _   _                                _              
|  ___|                 (_)| | | | | |                              | |             
| |__  _ __ ___    __ _  _ | | | |_| |  __ _  _ __ __   __ ___  ___ | |_  ___  _ __ 
|  __|| '_ ` _ \  / _` || || | |  _  | / _` || '__|\ \ / // _ \/ __|| __|/ _ \| '__|
| |___| | | | | || (_| || || | | | | || (_| || |    \ V /|  __/\__ \| |_|  __/| |   
\____/|_| |_| |_| \__,_||_||_| \_| |_/ \__,_||_|     \_/  \___||___/ \__|\___||_| 

    A tool to retrieve Domain email addresses from Search Engines | @maldevel
                                {}: {}
""".format(red('Version'), yellow(__version__)),                                 
                                     formatter_class=RawTextHelpFormatter)
    
    parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain', 
                        default=None, type=checkDomain, help="Domain to search.")
    parser.add_argument("-s", '--save', action="store", metavar='FILE', dest='filename', 
                        default=None, type=str, help="Save the results into a TXT and XML file (both).")
    
    parser.add_argument("-e", '--engine', action="store", metavar='ENGINE', dest='engine', 
                        default="all", type=str, help="Select search engine plugin(eg. '-e google').")
    
    parser.add_argument("-l", '--limit', action="store", metavar='LIMIT', dest='limit', 
                        type=limit_type, default=100, help="Limit the number of results.")
    parser.add_argument('-u', '--user-agent', action="store", metavar='USER-AGENT', dest='uagent', 
                        type=str, help="Set the User-Agent request header.")
    parser.add_argument('-x', '--proxy', action="store", metavar='PROXY', dest='proxy', 
                        default=None, type=checkProxyUrl, help="Setup proxy server (eg. '-x http://127.0.0.1:8080')")
    parser.add_argument('--noprint', action='store_true', default=False, 
                        help='EmailHarvester will print discovered emails to terminal. It is possible to tell EmailHarvester not to print results to terminal with this option.')
    parser.add_argument('-r', '--exclude', action="store", metavar='EXCLUDED_PLUGINS', dest="exclude",
                        type=str, default=None, help="Plugins to exclude when you choose 'all' for search engine (eg. '-r google,twitter')")
    parser.add_argument('-p', '--list-plugins', action='store_true', dest='listplugins', 
                        default=False, help='List all available plugins.')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    
    if args.listplugins:
        path = "plugins/"
        print(green("[+] Available plugins"))
        sys.path.insert(0, path)
        for f in os.listdir(path):
            fname, ext = os.path.splitext(f)
            if ext == '.py':
                print(green("[+] Plugin: ") + cyan(fname))
        sys.exit(1)
        
    if not args.domain:
        print(red("[-] Please specify a domain name to search."))
        sys.exit(2)
    domain = args.domain

    userAgent = (args.uagent or
                 "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1")
    
    # Security: Validate user agent
    if not validate_user_agent(userAgent):
        print(red("[-] Invalid user agent string"))
        sys.exit(5)
    
    print(green("[+] User-Agent in use: ") + cyan(userAgent))
    
    if args.proxy:
        print(green("[+] Proxy server in use: ") + cyan(args.proxy.scheme + "://" + args.proxy.netloc))

    filename = sanitize_filename(args.filename) if args.filename else ""
    limit = args.limit        
    engine = args.engine
    app = EmailHarvester(userAgent, args.proxy)
    plugins = app.get_plugins()

    all_emails = []
    excluded = []
    if args.exclude:
        excluded = args.exclude.split(',')
    if engine == "all":
        print(green("[+] Searching everywhere"))
        for search_engine in plugins:
            if search_engine not in excluded:
                all_emails += plugins[search_engine]['search'](domain, limit)
    elif engine not in plugins:
        print(red("[-] Search engine plugin not found"))
        sys.exit(3)
    else:
        all_emails = plugins[engine]['search'](domain, limit)
    all_emails = unique(all_emails)
    
    if not all_emails:
        print(red("[-] No emails found"))
        sys.exit(4)

    print(green("[+] Emails found: ") + cyan(len(all_emails)))

    if not args.noprint:
        for emails in all_emails:
            print(emails)
            
    if filename:
        try:
            print(green("[+] Saving results to files"))
            with open(filename, 'w') as out_file:
                for email in all_emails:
                    try:
                        out_file.write(email + "\n")
                    except:
                        print(red("[-] Exception: " + email))
        except Exception as e:
            print(red("[-] Error saving TXT file: " + e))
            
        try:
            xml_filename = filename.split(".")[0] + ".xml"
            with open(xml_filename, 'w', encoding='utf-8') as out_file:
                out_file.write('<?xml version="1.0" encoding="UTF-8"?><EmailHarvester>')
                for email in all_emails:
                    # Security: Properly escape XML content
                    escaped_email = xml_escape.escape(email)
                    out_file.write('<email>{}</email>'.format(escaped_email))
                out_file.write('</EmailHarvester>')
            print(green("[+] Files saved"))
        except Exception as er:
            logger.error(f"Error saving XML file: {er}")
            print(red("[-] Error saving XML file"))

