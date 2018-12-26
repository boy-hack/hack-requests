import HackRequests as hack
import hashlib

u = "http://x.hacking8.com/"
cookie1 = "user=useraa; "
hh = hack.http(u, cookie=cookie1, location=False)
# print(hh.text())
print(hh.status_code)
print(hh.log["request"], hh.log["response"])
