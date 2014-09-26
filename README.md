shellshock-hunter
========

Search Bing and concurrently test each result for vulnerability to CVE-2014-6271: remote code execute bug in bash otherwise known as Shellshock.

Usage
-----

``` shell
git clone https://github.com/DanMcInerney/shellshock-hunter
cd shellshock-hunter/
python shellshock-hunter -s "search_terms" -k your_bing_api_key -p number_of_pages_to_check
```

-p will default to 1 page giving 50 results if not specified

Example
-----

``` shell
python shellshock-hunter.py -s "instreamset:(url):cgi-bin ext:sh" -k AqTGBsziZHIJYYxgivLBf0hVdrAk9mWO5cQcb8Yux8sW5M8c8opEC2lZqKR1ZZXf -p 10
```

Bing doesn't recognize inurl: like Google does so we search "instreamset:(url):cgi-bin ext:sh" to catch all results with "cgi-bin" in the URL and an extension of .sh meaning it's a bash cgi script, the best case scenario for exploiting Shellshock. Bing API allows 50 results per query so multiply the number of pages by 50 to see how many URLs will be tested. In this case, -p 10 means we'll check the top 500 results. Get a free Bing API key at: https://datamarket.azure.com/dataset/bing/search

Output will look like:
``` shell
[!] SHELLSHOCK VULNERABLE: http://domain.com/cgi-bin/script.sh
```
