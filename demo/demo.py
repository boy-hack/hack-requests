import HackRequests

u = "http://www.hacking8.com/test.php"
hack = HackRequests.hackRequests()
cookie1 = "user=useraa; "
hh = hack.http(u, cookie=cookie1)
new = hh.cookie
print(new)


