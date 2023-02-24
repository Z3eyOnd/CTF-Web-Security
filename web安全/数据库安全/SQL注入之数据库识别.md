## 判断数据库类型

###  常见数据库

Oracle、MySQL、SQL Server、Access、MSsql、Postgresql，mongodb

###  端口判断

```
Oracle：1521

mssql：1433

Mysql：3306
```

### 系统架构组合识别

```
asp、.net：mssql

php：mysql、postgresql

java：oracle、mysql

iis：mssql

apache：mysql、postgresql
```

###  报错信息判断

在注入点后直接加上单引号，根据服务器的报错信息来判断数据库。错误提示Microsoft JET Database Engine 错误 '80040e14'，说明是通过JET引擎连接数据库，则表明数据库为ACCESS数据库。

oracle数据库，报错信息通常带有ORA-xxx

mysql的报错信息比较常见了

### 特殊符号判断

accsee注释符:、

```
使用空字符"NULL"(%00)当作注释符
```

mssql、oracle、postgresql注释符：

```
--单行注释

/*...*/多行注释
```

mysql的注释符：

```
#单行注释后面所有内容，换行后注释失效

--+和#号一样，但是后边必须有个空格，没空格则视为两个减号

/*aaa*/可用多行注释

注释内容在sql语句中解析为空格
```

Oracle不支持对的查询，因此如果返回错误，则说明很可能是Oracle数据库。

### 字符串拼接判断

mssql:

```
select 'a'+'b'='ab'
```

mysql:

```
select 'a'+'b'='ab'

select 'a'+'b'='a''b'

select 'a'+'b'='a'||'b'

select 'ab'=concat('a','b')
```

oracle:

```
select 'a'+'b'='a'||'b'

select 'ab'=concat('a','b')
```

postsql

```
select 'a'+'b'='a'||'b'

select 'ab'=concat('a','b')
```

### 内置函数判断

mssql

```
len(string)--返回string的长度
waitfor delay '0:0:3' --延时3秒
```

mysql

```
length(string) #返回string的长度
sleep(3) -- 延时3秒
```

postgresql

```
length(string)--返回string的长度
length(string, 'UTF8')--string在给定编码中的字符数。string必须在这个编码中有效。
pg_sleep(3) --延时3秒
select extract(dow from now())
```

oracle

```
Length(string)--计算string所占的字符长度
Lengthb(string)--计算string所占的字符长度
1=dbms_pipe.receive_message('RDS',3)--延时3秒
trunc+(1.1)=1
bitand(1,1)
```

基本靠返回长度函数就能判断清楚了。

### 特殊语句

mssql使用@@version变量返回当前的版本信息



```
select @@version;
@@pack_received ，@@rowcount
```

postgresql使用version()函数

```
select version();
```

mysql则是@@version和version()两种方式都支持

```
select @@version;
select version();
select @@version,version();
```

oracle查看数据库版本则不同

```
select * from v$version;
select banner from v$version;
select banner from sys.v_$version where rownum = 1;
```