#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/3/9 2:53 PM
# @Author  : w8ay
# @File    : test_http.py
import unittest
import HackRequests
import json


class TestCase(unittest.TestCase):
    def setUp(self):
        self.hack = HackRequests.hackRequests()

    def test_get(self):
        r = self.hack.http("http://httpbin.org/get?a=1&b=2&c=heloo")
        self.assertTrue(json.loads(r.text())["args"] == {"a": "1", "b": "2", "c": "heloo"})

    def test_post(self):
        data = "a=1&b=2&c=heloo"
        r = self.hack.http("http://httpbin.org/post", post=data)
        self.assertTrue(json.loads(r.text())["form"] == {"a": "1", "b": "2", "c": "heloo"})

    def test_json(self):
        data = '{"hack-requests":"v1.0","author":"w8ay"}'
        r = self.hack.http("http://httpbin.org/post", post=data)
        self.assertTrue("hack-requests" in r.text())

    def test_localhost(self):
        headers = {
            "Referer": "xx",
            "referer": "xx"
        }
        r = self.hack.http("https://x.hacking8.com", headers=headers)
        print(r.text())
