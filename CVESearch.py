#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
from pycvesearch import CVESearch

if len(sys.argv) < 4:
    print('Syntax \'python ./CVESearch.py [vendor] [product] [version]\'')
    exit(1)

cve = CVESearch()
vendor = sys.argv[1]
product = sys.argv[2]
version = sys.argv[3]

search_string = 'cpe:/a:{0}:{1}:{2}'.format(vendor, product, version)
print(search_string)

results = cve.cvefor(search_string)
print(results)

for cve in results:
    print(cve['id'])
    print(cve['cvss'])
