import requests
import urllib

data = {'Comment': 'fake', 'Name':'fake name', 'Email':'e2d0e0n4@gmail.com', 'Website':''}
r = requests.post('https://0af50091043e27ff80f003f00041009c.web-security-academy.net/post?postId=1', data=data)
print(r.text)
