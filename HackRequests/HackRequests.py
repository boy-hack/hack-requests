#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author   :   w8ay
# @Mail     :   w8ay@qq.com
# @File     :   hackRequests.py

import copy
import gzip
import queue
import socket
import ssl
import threading
import time
import zlib
from http import client
from urllib import parse


class HackError(Exception):
    def __init__(self, content):
        self.content = content

    def __str__(self):
        return self.content


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


class httpcon(object):
    '''
    httpcon用于生成HTTP中的连接。

    Attributes:
        timeout: 超时时间
    '''

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.protocol = []
        self._get_protocol()

    def _get_protocol(self):
        if not self.protocol:
            ps = (
                'PROTOCOL_SSLv23', 'PROTOCOL_TLSv1',
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
        conn = self._make_con(scheme, host, port, proxy)
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


class hackRequests(object):
    '''
    hackRequests是主要http请求函数。

    可以通过http或者httpraw来访问网络
    '''

    def __init__(self, conpool=None):
        self.lock = threading.Lock()

        if conpool is None:
            self.httpcon = httpcon(timeout=17)
        else:
            self.httpcon = conpool

    def _get_urlinfo(self, url, realhost: str):
        p = parse.urlparse(url)
        scheme = p.scheme.lower()
        if scheme != "http" and scheme != "https":
            raise Exception("http/https only")
        hostname = p.netloc
        port = 80 if scheme == "http" else 443
        if ":" in hostname:
            hostname, port = hostname.split(":")
        path = ""
        if p.path:
            path = p.path
            if p.query:
                path = path + "?" + p.query
        if realhost:
            if ":" not in realhost:
                realhost = realhost + ":80"
            hostname, port = realhost.split(":")
        return scheme, hostname, int(port), path

    def _send_output(self, oldfun, con, log):
        def _send_output_hook(*args, **kwargs):
            log['request'] = b"\r\n".join(con._buffer).decode('utf-8')
            oldfun(*args, **kwargs)
            con._send_output = oldfun

        return _send_output_hook

    def httpraw(self, raw: str, **kwargs):
        raw = raw.strip()
        proxy = kwargs.get("proxy", None)
        real_host = kwargs.get("real_host", None)
        ssl = kwargs.get("ssl", False)
        location = kwargs.get("location", True)

        scheme = 'http'
        port = 80
        if ssl:
            scheme = 'https'
            port = 443

        try:
            index = raw.index('\n')
        except ValueError:
            raise Exception("ValueError")
        log = {}
        try:
            method, path, protocol = raw[:index].split(" ")
        except:
            raise Exception("Protocol format error")
        raw = raw[index + 1:]

        try:
            host_start = raw.index("Host: ")
            host_end = raw.index('\n', host_start)

        except ValueError:
            raise ValueError("Host headers not found")

        if real_host:
            host = real_host
            if ":" in real_host:
                host, port = real_host.split(":")
        else:
            host = raw[host_start + len("Host: "):host_end]
            if ":" in host:
                host, port = host.split(":")
        raws = raw.splitlines()
        headers = {}

        # index = 0
        # for r in raws:
        #     raws[index] = r.lstrip()
        #     index += 1

        index = 0
        for r in raws:
            if r == "":
                break
            try:
                k, v = r.split(": ")
            except:
                k = r
                v = ""
            headers[k] = v
            index += 1
        headers["Connection"] = "close"
        if len(raws) < index + 1:
            body = ''
        else:
            body = '\n'.join(raws[index + 1:]).lstrip()

        urlinfo = scheme, host, int(port), path

        try:
            conn = self.httpcon.get_con(urlinfo, proxy=proxy)
        except:
            raise
        conn._send_output = self._send_output(conn._send_output, conn, log)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in headers.items():
                conn.putheader(k, v)
            if body and "Content-Length" not in headers and "Transfer-Encoding" not in headers:
                length = conn._get_content_length(body, method)
                conn.putheader("Content-Length", length)
            conn.endheaders()
            if body:
                if headers.get("Transfer-Encoding", '').lower() == "chunked":
                    body = body.replace('\r\n', '\n')
                    body = body.replace('\n', '\r\n')
                    body = body + "\r\n" * 2
                log["request"] += "\r\n" + body
                conn.send(body.encode('utf-8'))
            rep = conn.getresponse()
        except socket.timeout:
            raise HackError("socket connect timeout")
        except socket.gaierror:
            raise HackError("socket don't get hostname")
        except KeyboardInterrupt:
            raise HackError("user exit")
        finally:
            conn.close()
        log["response"] = "HTTP/%.1f %d %s" % (
            rep.version * 0.1, rep.status,
            rep.reason) + '\r\n' + str(rep.msg)
        if port == 80 or port == 443:
            _url = "{scheme}://{host}{path}".format(scheme=scheme, host=host, path=path)
        else:
            _url = "{scheme}://{host}{path}".format(scheme=scheme, host=host + ":" + port, path=path)
        
        redirect = rep.msg.get('location', None)  # handle 301/302
        if redirect and location:
            if not redirect.startswith('http'):
                redirect = parse.urljoin(_url, redirect)
            return self.http(redirect, post=None, method=method, headers=headers, location=True, locationcount=1)

        return response(rep, _url, log, )

    def http(self, url, **kwargs):
        method = kwargs.get("method", "GET")
        post = kwargs.get("post", None) or kwargs.get("data", None)
        location = kwargs.get('location', True)
        locationcount = kwargs.get("locationcount", 0)

        proxy = kwargs.get('proxy', None)
        headers = kwargs.get('headers', {})

        # real host:ip
        real_host = kwargs.get("real_host", None)

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
        if "Content-Length" in headers:
            del headers["Content-Length"]

        urlinfo = scheme, host, port, path = self._get_urlinfo(url, real_host)
        log = {}
        try:
            conn = self.httpcon.get_con(urlinfo, proxy=proxy)
        except:
            raise
        conn._send_output = self._send_output(conn._send_output, conn, log)
        tmp_headers = copy.deepcopy(headers)
        if post:
            method = "POST"
            if isinstance(post, str):
                try:
                    post = extract_dict(post, sep="&")
                except:
                    pass
            try:
                post = parse.urlencode(post)
            except:
                pass
            if "Content-Type" not in headers:
                tmp_headers["Content-Type"] = kwargs.get(
                    "Content-type", "application/json")
            if 'Accept' not in headers:
                tmp_headers["Accept"] = tmp_headers.get("Accept", "*/*")
        if 'Accept-Encoding' not in headers:
            tmp_headers['Accept-Encoding'] = tmp_headers.get("Accept-Encoding", "gzip, deflate")
        if 'Connection' not in headers:
            tmp_headers['Connection'] = 'close'
        if 'User-Agent' not in headers:
            tmp_headers['User-Agent'] = tmp_headers['User-Agent'] if tmp_headers.get(
                'User-Agent') else 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36'

        try:
            conn.request(method, path, post, tmp_headers)
            rep = conn.getresponse()
            # body = rep.read()
        except socket.timeout:
            raise HackError("socket connect timeout")
        except socket.gaierror:
            raise HackError("socket don't get hostname")
        except KeyboardInterrupt:
            raise HackError("user exit")
        finally:
            conn.close()

        if post:
            log["request"] += "\r\n\r\n" + post
        log["response"] = "HTTP/%.1f %d %s" % (
            rep.version * 0.1, rep.status,
            rep.reason) + '\r\n' + str(rep.msg)

        redirect = rep.msg.get('location', None)  # handle 301/302
        if redirect and location and locationcount < 10:
            if not redirect.startswith('http'):
                redirect = parse.urljoin(url, redirect)
            return self.http(redirect, post=None, method=method, headers=tmp_headers, location=True,
                             locationcount=locationcount + 1)

        if not redirect:
            redirect = url
        log["url"] = redirect
        return response(rep, redirect, log, cookie)


class response(object):

    def __init__(self, rep, redirect, log, oldcookie=''):
        self.rep = rep
        self.status_code = self.rep.status  # response code
        self.url = redirect
        self._content = b''

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

        if oldcookie:
            cookie_dict = self._cookie_update(oldcookie, self.cookie)
            self.cookie = ""
            for k, v in cookie_dict.items():
                self.cookie += "{}={}; ".format(k, v)
        self.cookie = self.cookie.rstrip("; ")
        try:
            self.cookies = extract_dict(self.cookie, "; ", "=")
        except:
            self.cookies = {}

        self.headers = _header_dict
        self.header = str(self.rep.msg)  # response header
        self.log = log
        charset = self.rep.msg.get('content-type', 'utf-8')
        try:
            self.charset = charset.split("charset=")[1]
        except:
            self.charset = "utf-8"

    def content(self):
        if self._content:
            return self._content
        encode = self.rep.msg.get('content-encoding', None)
        try:
            body = self.rep.read()
        except socket.timeout:
            body = b''
        if encode == 'gzip':
            body = gzip.decompress(body)
        elif encode == 'deflate':
            try:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except:
                body = zlib.decompress(body)
        # redirect = self.rep.msg.get('location', None)   # handle 301/302
        self._content = body
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

    def _cookie_update(self, old, new):
        '''
        用于更新旧cookie,与新cookie得出交集后返回新的cookie
        :param old:旧cookie
        :param new:新cookie
        :return:Str:新cookie
        '''
        # 先将旧cookie转换为字典，再将新cookie转换为字典时覆盖旧cookie
        old_sep = old.strip().split(";")
        new_sep = new.strip().split(";")
        cookie_dict = {}
        for sep in old_sep:
            if sep == "":
                continue
            try:
                k, v = sep.split("=")
                cookie_dict[k.strip()] = v
            except:
                continue
        for sep in new_sep:
            if sep == "":
                continue
            try:
                k, v = sep.split("=")
                cookie_dict[k.strip()] = v
            except:
                continue
        return cookie_dict


class threadpool:

    def __init__(self, threadnum, callback, timeout=10):
        self.thread_count = self.thread_nums = threadnum
        self.queue = queue.Queue()
        con = httpcon(timeout=timeout)
        self.hack = hackRequests(con)
        self.isContinue = True
        self.thread_count_lock = threading.Lock()
        self._callback = callback

    def push(self, payload):
        self.queue.put(payload)

    def changeThreadCount(self, num):
        self.thread_count_lock.acquire()
        self.thread_count += num
        self.thread_count_lock.release()

    def stop(self):
        self.isContinue = False

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

            func = p.pop("func")
            url = p.get("url", None)
            try:
                if url is None:
                    raw = p.pop('raw')
                    h = func(raw, **p)
                else:
                    h = func(url, **p.get("kw"))
                self._callback(h)
            except Exception as e:
                print(url, e)
        self.changeThreadCount(-1)


def http(url, **kwargs):
    # timeout = kwargs.get("timeout", 10)
    # con = httpcon(timeout=timeout)
    hack = hackRequests()
    return hack.http(url, **kwargs)


def httpraw(raw: str, **kwargs):
    # con = httpcon(timeout=timeout)
    # hack = hackRequests(con)
    hack = hackRequests()
    return hack.httpraw(raw, **kwargs)


if __name__ == '__main__':
    pass
