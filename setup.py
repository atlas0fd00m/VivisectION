import os
import sys
from setuptools import find_packages, setup

VERSION = open('VERSION').read().strip()
with open(os.path.join(dirn, 'README.md'), 'r') as fd:
    desc = fd.read()

mods = []
pkgdata = {'scripts': ['scripts/*']}

scripts = []
for s in os.listdir('scripts'):
    if s != '.git':
        scripts.append('scripts/%s'%s)


setup  (name        = 'VivisectION',
        version     = VERSION,
        description = desc,
        long_description=desc,
        long_description_content_type='text/markdown',
        author = 'atlas of d00m',
        author_email = 'atlas@r4780y.com',
        url = 'https://github.com/atlas0fd00m/VivisectION',
        download_url     = 'https://github.com/atlas0fd00m/VivisectION/archive/v%s.tar.gz' % VERSION,
        packages = find_packages(),
        package_data = pkgdata,
        install_requires = [
            'vivisect>=1.0.8'
        ],
        ext_modules = mods,
        scripts = scripts
       )
