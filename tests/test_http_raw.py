#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/3/9 11:22 AM
# @Author  : w8ay
# @File    : test_http.py
import unittest
import HackRequests
import json


class TestCase(unittest.TestCase):
    def setUp(self):
        self.hack = HackRequests.hackRequests()

    def test_get(self):
        raw = '''
GET /get?a=1&b=2&c=heloo HTTP/1.1
Host: httpbin.org
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: celebrate hack-requests 1.0 !
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: _gauges_unique_hour=1; _gauges_unique_day=1; _gauges_unique_month=1; _gauges_unique_year=1; _gauges_unique=1
        '''
        r = self.hack.httpraw(raw)
        self.assertTrue(json.loads(r.text())["args"] == {"a": "1", "b": "2", "c": "heloo"})

    def test_post(self):
        raw = '''
POST /post HTTP/1.1
Host: httpbin.org
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: celebrate hack-requests 1.0 !
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: _gauges_unique_hour=1; _gauges_unique_day=1; _gauges_unique_month=1; _gauges_unique_year=1; _gauges_unique=1

a=1&b=2&c=heloo
        '''
        r = self.hack.httpraw(raw)
        self.assertTrue("a=1&b=2&c=heloo" in r.text())

    def test_json(self):
        raw = '''
POST /post HTTP/1.1
Host: httpbin.org
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: celebrate hack-requests 1.0 !
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: _gauges_unique_hour=1; _gauges_unique_day=1; _gauges_unique_month=1; _gauges_unique_year=1; _gauges_unique=1

{"hack-requests":"v1.0","author":"w8ay"}
        '''
        r = self.hack.httpraw(raw)
        self.assertTrue(json.loads(r.text())["json"] == {"author": "w8ay", "hack-requests": "v1.0"})

    def test_chunked(self):
        raw = '''
POST /post HTTP/1.1
Host: httpbin.org
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Transfer-Encoding: Chunked

7;asdasdzxc
hellowo
7;qq321
rld!hel
7;asd
loworld
7;qqq
 hellow
5;88
or ld
0

        '''
        r = self.hack.httpraw(raw)
        print(r.text())
        self.assertTrue("helloworld!helloworld hellowor ld" in r.text())

    def test_redirect(self):
        raw = ''' 
GET / HTTP/1.1
Host: www.python.org
Connection: Keep-Alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
        '''
        r = self.hack.httpraw(raw)
        self.assertEqual(r.status_code, 200)
        self.assertIn('class="python home"', r.text())

        r = self.hack.httpraw(raw, location=False)
        self.assertEqual(r.status_code, 301)
        self.assertTrue(r.text() == "")
