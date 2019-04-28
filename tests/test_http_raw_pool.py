#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/4/28 9:16 PM
# @Author  : w8ay
# @File    : test_http_raw_pool.py
import HackRequests


def _callback(r: HackRequests.response):
    # 从回调函数取出结果，参数r是response结果
    print(len(r.text()))


threadpool = HackRequests.threadpool(threadnum=10, callback=_callback, timeout=10)
raw = '''
GET / HTTP/1.1
Host: x.hacking8.com
Connection: Keep-Alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
'''

for i in range(20):
    threadpool.httpraw(raw)
threadpool.run()
