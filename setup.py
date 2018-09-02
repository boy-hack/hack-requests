#!/usr/bin/env python
# coding:utf-8
from setuptools import setup
from HackRequests import (
    __title__, __version__, __author__, __url__,
    __author_email__, __license__)
setup(
    name=__title__,
    version=__version__,
    description="The hack-requests is an HTTP network library for hackers.",
    long_description='''HackRequests is an HTTP network library for hackers. Based on python3.x. If you need a less bulky and like requests design, and provide the request/response package to facilitate your next analysis, if you use the Burp Suite, you can copy and replay the original message directly, and for a large number of HTTP requests, the HackRequests's threadpool can help you implement the quickest response.''',
    author=__author__,
    author_email=__author_email__,
    url=__url__,
    license=__license__,
    package_data={'HackRequests': ['*.md']},
    package_dir={'HackRequests': 'HackRequests'},
    packages=['HackRequests'],
    include_package_data=True,
    keywords='http requests hacker',
)