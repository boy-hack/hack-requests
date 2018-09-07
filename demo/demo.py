import HackRequests

u = "https://bbs.125.la/"
hack = HackRequests.hackRequests()
cookie1 = "user=useraa; "
hh = hack.http(u)
new = hh.cookie
print(new)
print(hh.cookies)


