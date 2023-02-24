## 前言

本文就之前看到的linux的/prof/self进行学习，并写关于这个知识点的wp。 

## Linux的/proc/self/学习

可以通过/proc/$pid/来获取指定进程的信息，例如内存映射、CPU绑定信息等等。如果某个进程想要获取本进程的系统信息，就可以通过进程的pid来访问/proc/$pid/目录。但是这个方法还需要获取进程pid，在fork、daemon等情况下pid还可能发生变化。为了更方便的获取本进程的信息，linux提供了/proc/self/目录，这个目录比较独特，不同的进程访问该目录时获得的信息是不同的，内容等价于/proc/本进程pid/。进程可以通过访问/proc/self/目录来获取自己的系统信息，而不用每次都获取pid。

###  /proc目录

```
Linux系统上的/proc目录是一种文件系统，即proc文件系统。与其它常见的文件系统不同的是，/proc是一种伪文件系统（也即虚拟文件系统），存储的是当前内核运行状态的一系列特殊文件，用户可以通过这些文件查看有关系统硬件及当前正在运行进程的信息，甚至可以通过更改其中某些文件来改变内核的运行状态。 

基于/proc文件系统如上所述的特殊性，其内的文件也常被称作虚拟文件，并具有一些独特的特点。例如，其中有些文件虽然使用查看命令查看时会返回大量信息，但文件本身的大小却会显示为0字节。此外，这些特殊文件中大多数文件的时间及日期属性通常为当前系统时间和日期，这跟它们随时会被刷新（存储于RAM中）有关。 

为了查看及使用上的方便，这些文件通常会按照相关性进行分类存储于不同的目录甚至子目录中，如/proc/scsi目录中存储的就是当前系统上所有SCSI设备的相关信息，/proc/N中存储的则是系统当前正在运行的进程的相关信息，其中N为正在运行的进程（可以想象得到，在某进程结束后其相关目录则会消失）。 

大多数虚拟文件可以使用文件查看命令如cat、more或者less进行查看，有些文件信息表述的内容可以一目了然，但也有文件的信息却不怎么具有可读性。不过，这些可读性较差的文件在使用一些命令如apm、free、lspci或top查看时却可以有着不错的表现。
```

```
ls -al /proc 直接列出/proc下的进程信息等
```

###  打开进程

```
ls -al /proc/进程号
```

```
[root@z3eyond ~]# ls -al /proc/2674
total 0
dr-xr-xr-x 2 root root 0 Feb  8 17:15 attr
-r-------- 1 root root 0 Feb  8 17:14 auxv
-r--r--r-- 1 root root 0 Feb  8 17:09 cmdline
-rw-r--r-- 1 root root 0 Feb  8 17:14 coredump_filter
-r--r--r-- 1 root root 0 Feb  8 17:14 cpuset
lrwxrwxrwx 1 root root 0 Feb  8 17:14 cwd -> /var/run/saslauthd
-r-------- 1 root root 0 Feb  8 17:14 environ
lrwxrwxrwx 1 root root 0 Feb  8 17:09 exe -> /usr/sbin/saslauthd
dr-x------ 2 root root 0 Feb  8 17:15 fd
-r-------- 1 root root 0 Feb  8 17:14 limits
-rw-r--r-- 1 root root 0 Feb  8 17:14 loginuid
-r--r--r-- 1 root root 0 Feb  8 17:14 maps
-rw------- 1 root root 0 Feb  8 17:14 mem
-r--r--r-- 1 root root 0 Feb  8 17:14 mounts
-r-------- 1 root root 0 Feb  8 17:14 mountstats
-rw-r--r-- 1 root root 0 Feb  8 17:14 oom_adj
-r--r--r-- 1 root root 0 Feb  8 17:14 oom_score
lrwxrwxrwx 1 root root 0 Feb  8 17:14 root -> /
-r--r--r-- 1 root root 0 Feb  8 17:14 schedstat
-r-------- 1 root root 0 Feb  8 17:14 smaps
-r--r--r-- 1 root root 0 Feb  8 17:09 stat
-r--r--r-- 1 root root 0 Feb  8 17:14 statm
-r--r--r-- 1 root root 0 Feb  8 17:10 status
dr-xr-xr-x 3 root root 0 Feb  8 17:15 task
-r--r--r-- 1 root root 0 Feb  8 17:14 wchan
```

###  进程目录中的常见文件介绍

1.cmdline

cmdline 文件存储着启动**当前进程的完整命令**，但僵尸进程目录中的此文件不包含任何信息。可以通过查看cmdline目录获取启动指定进程的完整命令：

```php
cat /proc/1035/cmdline
```

```
[root@z3eyond ~]# more /proc/2674/cmdline 
/usr/sbin/saslauthd
```

2.cwd 

cwd文件是一个指向当前进程运行**目录**的符号链接。可以通过查看cwd文件获取目标**指定进程环境**的**运行目录**

```
ls -al /proc/1090/cwd
```

3.exe

exe 是一个指向启动当前进程的可执行文件（完整路径）的符号链接。通过exe文件我们可以获得指定进程的可执行文件的完整路径

```
ls -al /proc/1090/exe
```

4.environ

environ文件存储着当前进程的**环境变量**列表，彼此间用空字符（NULL）隔开，变量用大写字母表示，其值用小写字母表示。可以通过查看**environ目录**来获取**指定进程**的**环境变量**信息：

```php
cat /proc/2889/environ
```

5.fd

fd是一个目录，里面包含着当前进程打开的每一个文件的描述符（file descriptor）差不多就是路径啦，这些文件描述符是指向实际文件的一个符号连接，即每个通过这个进程打开的文件都会显示在这里。所以我们可以通过fd目录的文件获取进程，从而打开每个文件的路径以及文件内容。

```
ls -al /proc/1070/fd 
```

查看指定进程打开的某个文件的内容。那个数字就是那个数字嘛

```
ls -al /proc/1070/fd/4
```

这个fd比较重要，因为在Linux系统中，如果一个程序用 open() 打开了一个文件，但是最终没有关闭它，即使从外部（如：os.remove(SECRET_FILE))删除这个文件之后，在/proc这个进程的 pid目录下的fd文件描述符 目录下 还是会有这个文件的文件描述符，通过这个文件描述符我们即可以得到被删除的文件的内容.

后面我们需要这个东西来获得已经删除了的文件。

6.self

在linux中，为了更方便的获取本进程的信息，Linux提供了`/proc/self/`目录，这个目录比较独特，不同的进程访问该目录时获得的信息时不同的，内容等价于`/proc/本进程pid/`。进程可以通过访问`/proc/self/`目录来获取自己的系统信息，而不用每次都获取pid。

所以上面的命令就可以直接把进程号换成数字了。

```php
1.获取当前启动进程的完成命令：
cat /proc/self/cmdline

2.获取目标当前进程的运行目录与目录里的文件：
ls -al /proc/self/cwd
ls /proc/self/cwd

3.获得当前进程的可执行文件的完整路径：
ls -al /proc/self/exe

3.获得当前进程的可执行文件的完整路径：
ls -al /proc/self/exe

4.获取当前环境变量
cat /proc/self/environ

5.获取当前进程打开的文件内容
cat /proc/self/fd/{id}
也可以是：
cat /proc/*/fd/*    --*可以代替任意数字和字母
```

但是，在真正做题的时候，我们是不能通过命令的方式执行通过cat命令读取cmdline的。因为如果 cat读取/proc/self/cmdline/的话，得到的是 cat进程的信息。所以我们要通过题目的当前进程使用读取文件（比如，文件包含漏洞，，SSTI，，file:\\\本地读取，，../../../目录穿越，，SSRF）的方式读取/proc/self/cmdline


上面是几个重要的文件，[更多的文件描述可以看这个](https://www.cnblogs.com/DswCnblog/p/5780389.html)

##  CTF题
[\[网鼎杯 2020 白虎组\]PicDown --proc文件的利用--python反弹shell](https://blog.csdn.net/unexpectedthing/article/details/121336625)
[\[V&N2020 公开赛\]CHECKIN](https://blog.csdn.net/SopRomeo/article/details/105653176)

##  参考文章
```
https://blog.csdn.net/Zero_Adam/article/details/114853022
```
