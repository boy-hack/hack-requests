import HackRequests as hack

u = "https://bbs.125.la/"
cookie1 = "user=useraa; "
hh = hack.http(u, cookie=cookie1)
new = hh.cookie
print(new)
print(hh.cookies)


