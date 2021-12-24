Title = "PHP调试环境"
description = "记录使用phpstorm配合xdebug远程调试php docker的步骤"
tags = ["PHP","Debug"]
publishtime = 2021-07-28T14:43:00
lastedittime = 2021-07-28T14:43:00
uuid = "440af599-bd5b-4524-af50-90647fcb1648"
-+_+-



# docker-compose



**启动方法如下**

```bash
docker-compose build
docker-compose up -d
```



**目录结构如下**

- php
	- Dockerfile
	- xdebug-2.6.1.tgz
- source
	- php文件
- docker-compose.yml



**docker-compose.yml如下**

```yml
version: "3"
services: 
    php:
        build: "./php"
        volumes: 
            - ./source:/var/www/html
        ports: 
            - "63333:80"
        networks: 
            internal: 
                ipv4_address: 172.21.23.2
            external:
networks: 
    internal: 
        internal: true
        ipam: 
            driver: default
            config: 
                - subnet: 172.21.23.0/24
    external: 
        ipam: 
            driver: default
```

**Dockerfile如下**

```dockerfile
# 基础镜像
FROM php:7.0-apache

# 换源 php:x.x-apache系列的镜像采用的是debian发行版
RUN sed -i 's#http://deb.debian.org#https://mirrors.ustc.edu.cn#g' /etc/apt/sources.list && sed -i 's|security.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' /etc/apt/sources.list

# 安装必要的依赖
RUN apt-get update -y && apt-get install  -y  vim

# pecl安装、docker-php-ext-enable开启扩展
# xdebug文件可以copy或者远程wget下载
COPY xdebug-2.6.1.tgz  ./xdebug-2.6.1.tgz
RUN pecl install xdebug-2.6.1.tgz \
    && rm -rf xdebug-2.6.1.tgz \
    && docker-php-ext-enable xdebug

# 写入配置  有的docker版本不支持host.docker.internal的写法需要改成对应网段的网关，也就是宿主机在当前网段的地址 ex: 172.21.23.1
RUN echo "xdebug.remote_enable=on" >> /usr/local/etc/php/php.ini \
    && echo "xdebug.auto_trace=on" >> /usr/local/etc/php/php.ini \
    && echo "xdebug.remote_log = /tmp/xdebug.log" >> /usr/local/etc/php/php.ini \
    && echo 'xdebug.remote_handler = dbgp' >> /usr/local/etc/php/php.ini \
    && echo "xdebug.idekey=PHPSTORM" >> /usr/local/etc/php/php.ini \
    && echo "xdebug.remote_host=host.docker.internal" >> /usr/local/etc/php/php.ini \
    && echo "xdebug.remote_post=9000" >> /usr/local/etc/php/php.ini \
    && echo "phar.readonly = Off" >> /usr/local/etc/php/php.ini
    
# 配置重载
RUN a2enmod rewrite
```



# PhpStorm

1. 设置phpstorm通过docker api远程连接

settings->Build, Execution, Deployment->Docker

添加docker，名字可以自己填写，选择TCP socket进行远程通信，Engine API URL填写 `tcp://localhost:2375`，如果显示Connection successful则连接成功，如果失败，需要检查以下内容。

- docker容器内/tmp/下的xdebug的日志是否显示getaddrinfo失败，有可能是xdebug的远程主机配置错

```
修改xdebug.remote_host
```

- docker的守护进程并没有监听2375

```json
修改/etc/docker/daemon.json为
{
  "registry-mirrors": [
    "https://hub-mirror.c.163.com",
    "https://mirror.baidubce.com"
  ]
},{
"hosts": ["unix:///var/run/docker.sock","tcp://127.0.0.1:2375"]
}
重新启动daemon以及docker
```

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20211224112854.png)

- 停止docker daemon并指定remote api绑定端口

```bash
service docker stop
docker -d -H unix:///var/run/docker.sock -H 127.0.0.1:2375
```



2. 设置php cli interpreter

settings->Languages & Frameworks->PHP

添加一个PHP解释器，选择从docker中添加，然后选择启动的容器

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20211224112818.png)



3. 设置Run/Debug Configurations

新建一项配置文件并填写端口、选择调试浏览器

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20211224113308.png)
