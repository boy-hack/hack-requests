#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author   :   w8ay
# @Mail     :   w8ay@qq.com
# @File     :   utils.py

def extract_dict(text, sep, sep2="="):
    """根据分割方式将字符串分割为字典
    Args:
        text: 分割的文本
        sep: 分割的第一个字符 一般为'\n'
        sep2: 分割的第二个字符，默认为'='
    Return:
        返回一个dict类型，key为sep2的第0个位置，value为sep2的第一个位置

        只能将文本转换为字典，若text为其他类型则会出错
    """
    _dict = dict([l.split(sep2, 1) for l in text.split(sep)])
    return _dict


class HackError(Exception):
    def __init__(self, content):
        self.content = content

    def __str__(self):
        return self.content
