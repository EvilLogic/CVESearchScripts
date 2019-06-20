#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import re
from pycvesearch import CVESearch


if len(sys.argv) < 2:
    print('Syntax \'python ./CVESearch.py [file name]\'')
    exit(1)


vendor= product= ''
gitlist = open(sys.argv[1]).read().splitlines()

for link in gitlist:
    cve = CVESearch()
    m = re.search('github.com\/(.+?)\/(.+?)($|\/.+)', link)
    if m:
        vendor = m.group(1)
        product = m.group(2)
    else:
        #print('Could not parse github link')
        continue

    #Generate a CPE string with user as vender and repo as product
    search_string = 'cpe:/a:{0}:{1}'.format(vendor, product)
    #Convert spacing conventions
    search_string = search_string.replace('-','_')
    print(search_string)
    results = cve.cvefor(search_string)

    for cve in results:
        print(cve['id'] + ': ' + str(cve['cvss']))
