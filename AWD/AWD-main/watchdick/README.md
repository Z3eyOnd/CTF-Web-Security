# Watchdick
## 拿Watchbird改的WAF
## 改了啥？
- /文件.php?watchdick=ui 来访问 （防止被扫到）
- 修改了攻击被拦截时的特征
- 登陆密码直接就是401nb123，不需要修改
- 翻译成了英文 ，防止乱码的时候看球不懂
- 修改了函数名和类名，防止因为和被保护程序冲突而出错
- 编译了 waf.so，安装的时候自动复制到/var/www/html/fuckyou.so，通过PUTENV防止命令执行
- 优化了规则和配置，没卵用的拦截项就默认不开,扩充了文件上传的白名单
- <b>添加了PY功能</b>

## 关于PY功能

watchdick参数为chat的时候，command为get可以获取聊天记录（base64编码后的），为send可以发送内容，什么都不加返回401yyds（可以用于确认队友的机器位置）


```php
if ($_GET['watchdick'] === "chat") 
{
    $py_chat_path='/tmp/watchbird/chat.txt';
    if (!file_exists('/tmp/watchbird/')) 
        mkdir(dirname($py_chat_path), 0777, true); 
    if(!file_exists($py_chat_path))
        file_put_contents($py_chat_path,serialize(array()));

	if($_REQUEST['command']==='get')
    {
        die(base64_encode(json_encode(unserialize(file_get_contents($py_chat_path)))));
    }
    else if($_REQUEST['command']==='send')
    {
        $handle = fopen($py_chat_path,"r+");
        //Lock File, error if unable to lock
        if(flock($handle, LOCK_EX)) 
        {
            $content = fread($handle, filesize($py_chat_path));    
            $chat_history=unserialize($content);
            if(!$chat_history)
                $chat_history=array();            
            array_push($chat_history,array(
                "ip"=>$_SERVER['REMOTE_ADDR'],
                "sender"=>$_REQUEST['sender'],
                "content"=>$_REQUEST['content'],
            ));
            ftruncate($handle, 0);    
            rewind($handle);           
            fwrite($handle, serialize($chat_history));   
            flock($handle, LOCK_UN);    
            echo "success";
        } 
        else 
            echo "failed";
        fclose($handle);
        die();
    }
    die("401yyds");
}```
