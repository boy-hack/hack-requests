import HackRequests as hack
import hashlib

u = "https://bbs.125.la/"
cookie1 = "user=useraa; "
hh = hack.http(u, cookie=cookie1, post="1")
print(hh.text())
print(hh.log["request"])