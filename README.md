# hack-requests
hack-requests 是一个给黑客们使用的http底层网络库python3.目前还在开发中。

## 我的想法
我的想法很简单，`hack-requests`既可以像`requests`模块一样好用而且也提供返回底层的请求包、返回包提供参考。所以列了一个列表，期待完成这个网络库~
- 像requests一样好用的设计
- 提供接口获得底层请求包、返回包原文，方便下一步分析
- 支持发送HTTP原始报文，支持从Burp Suite等抓包软件中重放
- hack-requests内部使用连接池、线程池等技术，hack-requests会用最快的方式获取响应数据。使大量I/O密集型操作无需关注这些细节
- hack-requests是单文件模块，可方便移植到其他项目中。

## PS
谁叫`hackhttp`不能兼容py3呢？哼~
