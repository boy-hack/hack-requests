# hack-requests
hack-requests 是一个给黑客们使用的http底层网络库,基于python3.目前还在开发中。

## 我的想法
我的想法很简单，`hack-requests`既可以像`requests`模块一样好用而且也提供底层的请求包、返回包。所以列了一个列表，期待完成这个网络库~
- [x] 像requests一样好用的设计
- [ ] 提供接口获得底层请求包、返回包原文，方便下一步分析
- [ ] 支持发送HTTP原始报文，支持从Burp Suite等抓包软件中重放
- [ ] hack-requests内部使用连接池、线程池等技术，hack-requests会用最快的方式获取响应数据。使大量I/O密集型操作无需关注这些细节
- [x] hack-requests是单文件模块，可方便移植到其他项目中。

## PS
谁叫`hackhttp`不能兼容py3呢？哼~

## Useage

### 快速使用

```python
from hackRequests import hackRequests

hack = hackRequests()
url = "http://www.hacking8.com"
u = hack.http(url)
print(u.header)
```

返回

```python
Server: nginx
Date: Thu, 30 Aug 2018 02:23:55 GMT
Content-Type: text/html
Content-Length: 580
Last-Modified: Thu, 16 Aug 2018 09:50:56 GMT
Connection: keep-alive
ETag: "5b754900-244"
Accept-Ranges: bytes
```

使用`hack.http()`可以填写下列参数，当然，除了`url`参数外都不是必须的。

| 参数名      | 参数功能                                                     | 参数类型 |
| ----------- | ------------------------------------------------------------ | -------- |
| url（必须） | 用于传递一个地址                                             | Str      |
| post        | post参数用于传递post提交，此参数被选择时，`method`自动变为`POST`,post参数的类型可以为`Str`或者`Dict` | Str/Dict |
| method      | 访问模式，目前支持三种 HEAD、GET、POST，默认为GET            | Str      |
| location    | 当状态码为301、302时会自动跳转，默认为True                   | Bool     |
| proxy       | 代理，需要传入一个tuple，类似 ('127.0.0.1','8080')           | Tuple    |
| headers     | 自定义HTTP头，可传入字典或原始的请求头                       | Str/Dict |
| cookie      | 自定义Cookie，可传入字典或原始cookie字符串                   | Str/Dict |
| referer     | 模拟用户Referer                                              | Str      |
| user_agent  | 用户请求头，若为空则会模拟一个正常的请求头                   | Str      |

可使用如下接口获取`hack.http()`的返回值

| 接口函数    | 功能                            | 返回值类型 |
| ----------- | ------------------------------- | ---------- |
| status_code | 获取返回状态码                  | Int        |
| content()   | 获取返回字节                    | Bytes      |
| text()      | 获取返回文本(会自动转码)        | Str        |
| header      | 返回原始响应头                  | Str        |
| headers     | 返回原始响应头的字典形式        | Dict       |
| charset     | 获取编码类型                    | Str        |
| log         | 获取底层发送的请求包/返回包     | Dict       |
| url         | 返回url，若发生跳转则为跳转后的 | Str        |

