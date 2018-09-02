#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author   :   w8ay
# @Mail     :   w8ay@qq.com
# @File     :   hackRequests.py

from http import client
from urllib import parse
from threading import Lock
import threading
import ssl
import collections
import copy
import gzip
import zlib
import time
import queue


class Compatibleheader(str):
    def setdict(self, d):
        self.dict = d

    def __getitem__(self, key):
        return self.dict.__getitem__(key)

    def get(self, key, d=None):
        return self.dict.get(key, d)


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


class httpconpool(object):
    '''
    httpconpool是http连接池。

    所有http请求的tcp连接都会在这里缓存，通过对url解析出hash字串，若hash字串相匹配，则可以进行TCP复用，节省TCP连接的时间。
    连接池默认缓存20条连接，若连接超出，则按照先来后到的顺序踢出连接。

    Attributes:
        maxconnectpool: 连接池大小
        timeout: 超时时间
    '''

    def __init__(self, maxconnectpool=20, timeout=10):
        self.maxconnectpool = maxconnectpool
        self.timeout = timeout
        self.protocol = []
        self.connectpool = collections.OrderedDict()   # 空闲连接池
        self.lock = Lock()
        self._get_protocol()

    def __del__(self):
        self.lock.acquire()
        for k, v in self.connectpool.items():
            v.close()
        del self.connectpool
        self.lock.release()

    def _get_protocol(self):
        if not self.protocol:
            ps = (
                'PROTOCOL_SSLv3', 'PROTOCOL_SSLv23', 'PROTOCOL_TLSv1',
                'PROTOCOL_SSLv2', 'PROTOCOL_TLSv1_1', 'PROTOCOL_TLSv1_2')
            for p in ps:
                pa = getattr(ssl, p, None)
                if pa:
                    self.protocol.append(pa)

    '''
    得到一个连接
    
    这是连接池中最重要的一个参数，连接生成、复用相关操作都在这
    '''
    def get_con(self, url, proxy=None):
        scheme, host, port, path = url
        conhash = "{}_{}_{}".format(scheme, host, port)
        self.lock.acquire()
        len_connect = len(self.connectpool)
        self.lock.release()

        if conhash in self.connectpool:
            conn = self.connectpool[conhash]
            if not getattr(conn, 'sock', None):  # AppEngine might not have  `.sock`
                conn.connect()
            return conn

        if len_connect > self.maxconnectpool:
            self.release()
        conn = self._make_con(scheme, host, port, proxy)
        self.lock.acquire()
        self.connectpool[conhash] = conn
        self.lock.release()
        return conn

    def _make_con(self, scheme, host, port, proxy=None):
        if "https" != scheme:
            if proxy:
                con = client.HTTPConnection(
                    proxy[0], int(proxy[1]), timeout=self.timeout)
                con.set_tunnel(host, port)
            else:
                con = client.HTTPConnection(host, port, timeout=self.timeout)
            # con.connect()
            return con
        for p in self.protocol:
            context = ssl._create_unverified_context(p)
            try:
                if proxy:
                    con = client.HTTPSConnection(
                        proxy[0], proxy[1], context=context,
                        timeout=self.timeout)
                    con.set_tunnel(host, port)
                else:
                    con = client.HTTPSConnection(
                        host, port, context=context, timeout=self.timeout)
                # con.connect()
                return con
            except ssl.SSLError:
                pass
        raise Exception('connect err')

    def release(self):
        self.lock.acquire()
        k, v = self.connectpool.popitem()
        v.close()
        self.lock.release()


class hackRequests(object):
    '''
    hackRequests是主要http请求函数。

    可以通过http或者httpraw来访问网络
    '''
    def __init__(self,conpool = None):
        self.status_code = 0
        self.content = b''
        self.text = ""
        self.headers = {}
        self.log = {}
        self.encoding = ""

        if conpool is None:
            self.httpcon = httpconpool(maxconnectpool=20, timeout=10)
        else:
            self.httpcon = conpool

    def _get_urlinfo(self, url):
        p = parse.urlparse(url)
        scheme = p.scheme.lower()
        if scheme != "http" and scheme != "https":
            raise Exception("http/https only")
        hostname = p.netloc
        port = 80 if scheme == "http" else 443
        if ":" in hostname:
            hostname, name = hostname.split(":")
        path = ""
        if p.path:
            path = p.path
            if p.query:
                path = path + "?" + p.query
        return scheme, hostname, port, path

    def _send_output(self, oldfun, con, log):
        def _send_output_hook(*args, **kwargs):
            log['request'] = b"\r\n".join(con._buffer)
            log['request'] = log["request"].decode('utf-8')
            oldfun(*args, **kwargs)
            con._send_output = oldfun
        return _send_output_hook

    def httpraw(self, raw: str, ssl: bool = False, proxy=None, location=True):
        raw = raw.strip()
        raws = raw.splitlines()
        try:
            method, path, protocol = raws[0].split(" ")
        except:
            raise Exception("Protocol format error")
        post = None
        if method == "POST":
            index = 0
            for i in raws:
                index += 1
                if i.strip() == "":
                    break
            if len(raws) == index:
                raise Exception
            d = raws[1:index-1]
            d = extract_dict('\n'.join(d), '\n', ": ")
            post = raws[index]

        else:
            d = extract_dict('\n'.join(raws[1:]), '\n', ": ")
        netloc = "http" if not ssl else "https"
        host = d.get("Host", None)
        if host is None:
            raise Exception
        del d["Host"]
        url = "{}://{}".format(netloc, host + path)
        return self.http(url, post=post, headers=d, proxy=proxy, location=location)

    def http(self, url, **kwargs):
        method = kwargs.get("method", "GET")
        post = kwargs.get("post", None)
        location = kwargs.get('location', True)
        locationcount = kwargs.get("locationcount", 0)

        proxy = kwargs.get('proxy', None)
        headers = kwargs.get('headers', {})
        if isinstance(headers, str):
            headers = extract_dict(headers.strip(), '\n', ': ')
        cookie = kwargs.get("cookie", None)
        if cookie:
            cookiestr = cookie
            if isinstance(cookie, dict):
                cookiestr = ""
                for k, v in cookie.items():
                    cookiestr += "{}={}; ".format(k, v)
                cookiestr = cookiestr.strip("; ")
            headers["Cookie"] = cookiestr
        for arg_key, h in [
            ('referer', 'Referer'),
                ('user_agent', 'User-Agent'), ]:
            if kwargs.get(arg_key):
                headers[h] = kwargs.get(arg_key)

        urlinfo = scheme, host, port, path = self._get_urlinfo(url)
        log = {}
        try:
            conn = self.httpcon.get_con(urlinfo, proxy=proxy)
        except:
            raise
        conn._send_output = self._send_output(conn._send_output, conn, log)
        if post:
            method = "POST"
            if isinstance(post, str):
                post = extract_dict(post, sep="&")
            post = parse.urlencode(post)
            headers["Content-type"] = kwargs.get(
                "Content-type", "application/x-www-form-urlencoded")
            headers["Accept"] = "text/plain"
        tmp_headers = copy.deepcopy(headers)
        tmp_headers['Accept-Encoding'] = 'gzip, deflate'
        tmp_headers['Connection'] = 'Keep-Alive'
        tmp_headers['User-Agent'] = tmp_headers['User-Agent'] if tmp_headers.get(
            'User-Agent') else 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36'

        conn.request(method, path, post, tmp_headers)
        rep = conn.getresponse()
        body = rep.read()
        if post:
            log["request"] += "\r\n\r\n" + post
        log["response"] = "HTTP/%.1f %d %s" % (
            rep.version * 0.1, rep.status,
            rep.reason) + '\r\n' + str(rep.msg)

        redirect = rep.msg.get('location', None)  # handle 301/302
        if redirect and location and locationcount < 10:
            if not redirect.startswith('http'):
                redirect = parse.urljoin(url, redirect)
            return self.http(redirect, post=None, method=method, headers=tmp_headers, location=True, locationcount=locationcount + 1)

        if not redirect:
            redirect = url
        log["url"] = redirect
        return response(rep, redirect, body, log)


class response(object):

    def __init__(self, rep, redirect, body, log):
        self.rep = rep
        self.body = body
        self.status_code = self.rep.status      # response code
        self.url = redirect

        _header_dict = dict()
        self.cookie = ""
        for k, v in self.rep.getheaders():
            _header_dict[k] = v
            # handle cookie
            if k == "Set-Cookie":
                if ";" in v:
                    self.cookie += v.strip().split(";")[0] + "; "
                else:
                    self.cookie = v.strip() + "; "
        self.cookie = self.cookie.rstrip("; ")
        self.headers = _header_dict
        self.header = self.rep.msg              # response header
        self.log = {}                           # response log
        self.charset = ""                       # response encoding
        self.log = log
        charset = self.rep.msg.get('content-type', 'utf-8')
        try:
            self.charset = charset.split("charset=")[1]
        except:
            self.charset = "utf-8"

    def content(self):
        encode = self.rep.msg.get('content-encoding', None)
        body = self.body
        if encode == 'gzip':
            body = gzip.decompress(body)
        elif encode == 'deflate':
            try:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except:
                body = zlib.decompress(body)
        # redirect = self.rep.msg.get('location', None)   # handle 301/302
        return body

    def text(self):
        '''

        :return: text
        '''
        body = self.content()

        try:
            text = body.decode(self.charset, 'ignore')
        except:
            text = str(body)
        self.log["response"] += '\r\n' + text[:4096]
        return text


class threadpool:

    def __init__(self, threadnum, callback):
        self.thread_count = self.thread_nums = threadnum
        self.queue = queue.Queue()
        self.hack = hackRequests()
        self.isContinue = True
        self.thread_count_lock = threading.Lock()
        self.thread_lock = threading.Lock()
        self._callback = callback

    def push(self, payload):
        self.queue.put(payload)

    def changeThreadCount(self, num):
        self.thread_count_lock.acquire()
        self.thread_count += num
        self.thread_count_lock.release()

    def stop(self):
        self.thread_lock.acquire()
        self.isContinue = False
        self.thread_lock.release()

    def run(self):
        th = []
        for i in range(self.thread_nums):
            t = threading.Thread(target=self.scan)
            t.setDaemon(True)
            t.start()
            th.append(t)

        # It can quit with Ctrl-C
        try:
            while 1:
                if self.thread_count > 0 and self.isContinue:
                    time.sleep(0.01)
                else:
                    break
        except KeyboardInterrupt:
            exit("User Quit")

    def http(self, url, **kwargs):
        func = self.hack.http
        self.queue.put({"func": func, "url": url, "kw": kwargs})

    def httpraw(self, raw: str, ssl: bool = False, proxy=None, location=True):
        func = self.hack.httpraw
        self.queue.put({"func": func, "raw": raw, "ssl": ssl,
                        "proxy": proxy, "location": location})

    def scan(self):
        while 1:
            if self.queue.qsize() > 0 and self.isContinue:
                p = self.queue.get()
            else:
                break

            func = p.get("func")
            url = p.get("url", None)
            self.thread_lock.acquire()
            if url is None:
                h = func(p.get("raw"), p.get("ssl"),
                         p.get("proxy"), p.get("location"))
            else:
                h = func(url, **p.get("kw"))
            self.thread_lock.release()
            self._callback(h)

        self.changeThreadCount(-1)


if __name__ == '__main__':
    pass
