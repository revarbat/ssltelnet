#!/usr/bin/env python

from setuptools import setup

VERSION = "0.9.1"


with open('README.rst') as f:
    LONG_DESCR = f.read()

data_files = []

setup(
    name='ssltelnet',
    version=VERSION,
    description='An wrapper to add SSL/TLS support to telnetlib.',
    long_description=LONG_DESCR,
    author='Revar Desmera',
    author_email='revarbat@gmail.com',
    url='https://github.com/revarbat/ssltelnet',
    download_url='https://github.com/revarbat/ssltelnet/archive/master.zip',
    packages=['ssltelnet'],
    license='MIT License',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
    ],
    keywords='ssl telnet communication',
    install_requires=['setuptools'],
    data_files=data_files,
)
