Title = "Django  Sessions 伪造"
description = "对Django Sessions的研究记录"
tags = ["Web","Python","Django"]
publishtime = 2020-04-29T13:54:54
lastedittime = 2020-04-29T13:54:54
uuid = "b6d1f1e4-c77f-4c67-b18d-56478eb8ed4c"
-+_+-

## 场景

已知或泄露SECRET_KEY

可获得user的加密后password，比如注入





## 知识

### Password

在Django中，用户的密码是经过hash之后存放于后端数据库中`auth_user`的`password`字段中

其格式如下所示：

```
{algorithm}${iteration times}${salt}${encryped password}
```

举个例子，在数据库中：

![1571194705783](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571194705783.png)

以其中一条记录来说明

```
pbkdf2_sha256$150000$KkiPe6beZ4MS$UWamIORhxnonmT4yAVnoUxScVzrqDTiE9YrrKFmX3hE=
```

以$为分隔符

```
pbkdf2_sha256      //加密算法
150000              //迭代次数
KkiPe6beZ4MS         //盐值
UWamIORhxnonmT4yAVnoUxScVzrqDTiE9YrrKFmX3hE= //hash之后的base加密后的值
```



### 会话

Django通过一个内置中间件来实现会话功能。要启用会话就要先启用该中间件。编辑settings.py中的MIDDLEWARE设置，确保存在`django.contrib.sessions.middleware.SessionMiddleware`这一行。默认情况在新建的项目中它是存在的。

如果你不想使用会话功能，那么在settings文件中，将SessionMiddleware从MIDDLEWARE中删除，将`django.contrib.sessions`从`INSTALLED_APPS`中删除就OK了。

默认情况下，Django将会话数据保存在文件系统或者缓存内。



### Using cookie-based sessions



在Django中，如果使用了基于cookie的session，cookie中的sessionid字段用于标识用户。

![1571195016658](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571195016658.png)

在使用基于cookie的session时，需要指定`SESSION_ENGINE`为

```python
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
```

session在后端数据库中存储时使用了`cryptographic signing`的签名工具和`SECRET_KEY`

> 注意：建议将SESSION_COOKIE_HTTPONLY设置为True，提高安全性。



### django-admin 创建项目

![1571217613112](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571217613112.png)

创建后的目录如下

![1571217631494](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571217631494.png)

![1571217645016](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571217645016.png)

在使用startproject来创建Django项目时，settings.py是自动生成的，并且得到一个随机的SECRET_KEY

![1571217682225](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571217682225.png)

这个SECRET_KEY需要妥善保管，否则会有严重的隐患。





### Cryptographic signing

![1571195399748](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571195399748.png)

在web安全里有一条重要的法则，外部数据永远是不可信的，因此，Cryptographic signing工具实现了签名，防止数据被篡改，从而导致session伪造等情况发生。

在该工具中，重点看对于复杂数据结构的签名

> 类似于pickle 序列化，但是使用的是JSON serialization

![1571197631711](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571197631711.png)

查看函数说明

![1571197914534](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571197914534.png)

从函数说明中，可以知道，如果key为None，则默认使用settings文件的SECRET_KEY

Salt参数是所使用的hash算法的声明，类型为字符串，默认为`django.core.signing`

如果使用的是基于cookie的session方案，此处为`django.contrib.sessions.backends.signed_cookies`



## 题目

Hackgame 2019 迷失的姜戈

此处写的是做题时候的思路，前面的知识是做题以后的总结

题目提示了源码泄露，从最大的同性交友社区porn，啊不对，Gay，不对，GitHub中找到源码

![1571218461972](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571218461972.png)

根据setting.py，openlug是使用django-admin启动的项目，可以获得到了SECRET_KEY，以及关键信息，使用的SESSION_ENGINE为

```python
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
```

而且给了数据库文件，使用SQLiteSpy查看，获得了密码的密文

![1571218557267](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571218557267.png)

题目只有两个账户，一个admin，一个guest，我们不知道admin的密码，很明显是需要伪造session进行登录

既然要伪造session，那就需要直到cookie中的sessionid的明文格式，此处可以自己本地起一个app来动态调试，也可以调用Cryptographic signing的api来解出明文

解密脚本：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2019-10-16 14:42:18
# @Author  : Mote(mrzhangsec@163.com)
import os
from django.core import signing
# 根据情况修改
SECRET_KEY = 'd7um#o19q+v24!vkgzrxme41wz5#_h0#f_6u62fx0m@k&uwe39'
sessionid = '.eJxVjDEOgzAMRe_iGUUQULE7du8ZIid2GtoqkQhMVe8OSAzt-t97_wOO1yW5tersJoErWGh-N8_hpfkA8uT8KCaUvMyTN4diTlrNvYi-b6f7d5C4pr1uGXGI6AnHGLhjsuESqRdqByvYq_JohVDguwH3fzGM:1iKQDA:Jb1-z7-bGyX7G6Tv-1BBn0ZjEmc'
salt = 'django.contrib.sessions.backends.signed_cookies'
print(signing.loads(sessionid,key=SECRET_KEY,salt=salt))
```

寻找salt的信息，当时在做题时并不知道salt具体是什么

猜测跟session_engine有关，因为之前指定了session_engine所以去寻找一下django.contrib.sessions.backends.signed_cookies的实现

![1571199340778](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571199340778.png)

**django/contrib/sessions/backends/signed_cookies.py**

在signed_cookies.py里封装了一层load

![1571199379732](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571199379732.png)

指定为`salt='django.contrib.sessions.backends.signed_cookies'`

解密得到的数据如下图

![1571219032788](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571219032788.png)

其中：

- _auth_user_id 是用户id
- _auth_user_backend  使用的认证模块 默认为`django.contrib.auth.backends.ModelBackend`
- _auth_user_hash  是用于签名的hash值，使用加密后的密码，后面会讲



做题的时候并不知道`_auth_user_hash`是什么，于是查找`_auth_user_hash`相关关键字

![1571198420260](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571198420260.png)

**django/contrib/auth/\_\_init\_\_.py**

给`_auth_user_hash`取了别名

![1571199457053](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571199457053.png)

看在哪里使用，是怎么生成的

在login函数中进行比对

![1571199549114](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571199549114.png)

于是很明显，首先从数据库中获取的user对象，调用get_session_auth_hash方法得到一个session_auth_hash

然后从request请求中发送过来的数据中的`_auth_user_hash`进行比对

所以，这个`_auth_user_hash`其实是对密码的鉴别



跟入get_session_auth_hash()的实现

**django/contrib/auth/base_user.py#L120**

![1571199596583](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571199596583.png)

我们的目的是伪造session来登录，如果知道了原始password，直接登录就完事了还搞那么多事情干嘛

user.get_session_auth_hash方法其实是调用了salted_hmac方法，传入key_salt的值和self.password

先根据id从数据库中获取到user对象，其中包含了存储的密码密文，也就是self.password

![1571210206152](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571210206152.png)

获取到user对象guest

![1571210299430](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571210299430.png)

从数据库中取出来的user对象的password就是数据库中存储的password字段的值。

![1571209672008](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571209672008.png)

![1571209595001](Django_session_hijack.assets/1571209595001.png)



验证一下salted_hmac方法

![1571220219986](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571220219986.png)

可以看到，验证成功

根据我们之前获取到的admin的密文，我们不需要解开，就可以直接伪造admin的sessionid进行登录

得到了_auth_user_hash以后

可以开始伪造sessionid，进行以admin身份进行登录，即可得到flag

![1571199952128](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/1571199952128.png)







## 参考

https://github.com/xros/py_django_crack

https://docs.djangoproject.com/en/2.2/topics/http/sessions/

https://www.cnblogs.com/fbli/p/5925075.html