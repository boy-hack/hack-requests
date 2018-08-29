from http import client
from urllib import parse
from threading import Lock
import ssl
import collections
import copy
import gzip
import zlib


class Compatibleheader(str):
    def setdict(self, d):
        self.dict = d

    def __getitem__(self, key):
        return self.dict.__getitem__(key)

    def get(self, key, d=None):
        return self.dict.get(key, d)

class httpconpool(object):
    '''
    HTTP连接池
    '''

    def __init__(self, maxconnectpool=20, timeout=10):
        self.maxconnectpool = maxconnectpool
        self.timeout = timeout
        self.protocol = []
        self.connectpool = collections.OrderedDict()   # 空闲连接池
        self.lock = Lock()
        self._get_protocol()

    def _get_protocol(self):
        if not self.protocol:
            ps = (
                'PROTOCOL_SSLv3', 'PROTOCOL_SSLv23', 'PROTOCOL_TLSv1',
                'PROTOCOL_SSLv2', 'PROTOCOL_TLSv1_1', 'PROTOCOL_TLSv1_2')
            for p in ps:
                pa = getattr(ssl, p, None)
                if pa:
                    self.protocol.append(pa)

    def get_con(self,url,proxy = None):
        scheme,host,port,path = url
        conhash = "{}_{}_{}".format(scheme,host,port)
        self.lock.acquire()
        len_connect = len(self.connectpool)
        self.lock.release()

        if conhash in self.connectpool:
            return self.connectpool[conhash]

        if len_connect > self.maxconnectpool:
            self.release()
        conn = self._make_con(scheme,host,port,proxy)
        self.lock.acquire()
        self.connectpool[conhash] = conn
        self.lock.release()
        return conn

    def _make_con(self,scheme,host,port,proxy=None):
        if "https" != scheme:
            if proxy:
                con = client.HTTPConnection(proxy[0],proxy[1],timeout=self.timeout)
                con.set_tunnel(host,port)
            else:
                con = client.HTTPConnection(host,port,timeout=self.timeout)
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
        k,v = self.connectpool.popitem()
        v.close()
        self.lock.release()


class hackRequests(object):

    def __init__(self):
        self.status_code = 0
        self.content = b''
        self.text = ""
        self.headers = {}
        self.log = {}
        self.encoding = ""
        self.httpcon = httpconpool()

    def _get_urlinfo(self,url):
        p = parse.urlparse(url)
        scheme = p.scheme.lower()
        if scheme != "http" and scheme != "https":
            raise Exception("http/https only")
        hostname = p.netloc
        port = 80 if scheme == "http" else 443
        if ":" in hostname:
            hostname,name = hostname.split(":")
        path = ""
        if p.path:
            path = p.path
            if p.query:
                path = path + "?" + p.query
        return scheme,hostname,port,path

    def http(self,url,post=None,**kwargs):
        '''

        :param url:
        :param post:
        :return:
        '''
        method = kwargs.get("method", "GET")
        if post is not None:
            method = "POST"
        location = kwargs.get('location', True)
        proxy = kwargs.get('proxy', None)
        headers = kwargs.get('headers', {})
        for arg_key, h in [
            ('cookie', 'Cookie'),
            ('referer', 'Referer'),
            ('user_agent', 'User-Agent'), ]:
            if kwargs.get(arg_key):
                headers[h] = kwargs.get(arg_key)

        urlinfo = scheme, host, port, path = self._get_urlinfo(url)
        conn = self.httpcon.get_con(urlinfo,proxy=proxy)

        tmp_headers = copy.deepcopy(headers)
        tmp_headers['Accept-Encoding'] = 'gzip, deflate'
        tmp_headers['Connection'] = 'Keep-Alive'
        tmp_headers['User-Agent'] = tmp_headers['User-Agent'] if tmp_headers.get(
            'User-Agent') else 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36'

        conn.request(method,path,post,tmp_headers)
        return response(conn)


class response(object):

    def __init__(self,conn):
        self.rep = conn.getresponse()
        self.status_code = self.rep.status      # response code

        _header_dict = dict()
        for k,v in self.rep.getheaders():
            _header_dict[k] = v
        self.headers = _header_dict
        self.header = self.rep.msg              # response header
        self.log = {}                           # response log
        self.charset = ""                      # response encoding
        charset = self.rep.msg.get('content-type', 'utf-8')
        try:
            self.charset = charset.split("charset=")[1]
        except:
            self.charset = "utf-8"



    def content(self):
        encode = self.rep.msg.get('content-encoding', None)
        body = self.rep.read()
        if encode == 'gzip':
            body = gzip.decompress(body)
        elif encode == 'deflate':
            try:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except:
                body = zlib.decompress(body)
        redirect = self.rep.msg.get('location', None)   # handle 301/302

        return body

    def text(self):
        '''

        :return: text
        '''
        body = self.content()


        try:
            text = body.decode(self.charset,'ignore')
        except:
            text = str(body)
        return text


if __name__ == '__main__':
    hack = hackRequests()
    u = "http://www.baidu.com"
    p = hack.http(u)
    print(p.header)



