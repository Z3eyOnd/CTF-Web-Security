

##  前言

这段时间，都是来加强自己代码审计的能力，希望自己的努力没有白费。

## 环境搭建

直接利用`phpstudy`来搭建

然后注意的是，需要在后台打开会员功能

系统 =>系统基本参数=>会员设置

![image-20220307211350754](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072113816.png)



##  前台任意用户修改

### 漏洞演示

进入会员中心，点击通过安全问题取回

![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072146521.png)



抓包改参数

```
dopost=safequestion&id=1&userid=admin&safequestion=00&safeanswer=0&vdcode=Vs4p
```

进入修改界面

![img](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072148915.png)

###  漏洞分析

类型：php弱类型比较

dedecms的`/member/resetpassword.php`，用来进行用户密码重置

问题出在73行开始处理验证密保问题处。

![image-20220307214042036](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072141071.png)



这段代码先是从数据库取出相关用户的密保问题及密保答案，在对用户输入做了一些处理后，进行了关键性的判断

```
if($row['safequestion'] == $safequestion && $row['safeanswer'] == $safeanswer)
```

如果没有设置密保的话safequestion从数据库取出默认为'0'，safeanswer为空。又是弱类型，所以我们赋值为0.



跟踪sn函数

![image-20220307214324418](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072143586.png)



跟踪newmail

![image-20220307214454639](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072144842.png)



sn函数中将`send`参数设置了'N'，type=`insert`，所以就直接跳转到修改密码的页面。

##  前台文件上传漏洞

漏洞在于用户发布文章上传图片处。处理文件在`/include/dialog/select_images_post.php`

而上传文件存在全局过滤`/include/uploadsafe.inc.php`

对文件后缀名，`content_type`,`getimagesize`过滤了。

![image-20220307221455877](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072214072.png)

文件后缀名和content_type,好解决

`getimagesize`,我们需要传图片马

制作图片马

`cmd`

```
copy 1.jpg/b + 2.php/a 3.jpg
```

`/include/dialog/select_images_post.php`也只是对文件后缀名过滤了。

![image-20220307221953780](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072219863.png)

所以我们传图片马构造，设置后缀名`3.jpg.p\*hp`。

这儿也用到了`apache的文件后缀解析漏洞`

##  任意用户登录漏洞

###  代码分析

```
 if($action == '')
    {
        include_once(DEDEINC."/channelunit.func.php");
        $dpl = new DedeTemplate();
        $tplfile = DEDEMEMBER."/space/{$_vars['spacestyle']}/index.htm";

        //更新最近访客记录及站点统计记录
        $vtime = time();
        $last_vtime = GetCookie('last_vtime');
        $last_vid = GetCookie('last_vid');
        if(empty($last_vtime))
        {
            $last_vtime = 0;
        }
        if($vtime - $last_vtime > 3600 || !preg_match('#,'.$uid.',#i', ','.$last_vid.',') )
        {
            if($last_vid!='')
            {
                $last_vids = explode(',',$last_vid);
                $i = 0;
                $last_vid = $uid;
                foreach($last_vids as $lsid)
                {
                    if($i>10)
                    {
                        break;
                    }
                    else if($lsid != $uid)
                    {
                        $i++;
                        $last_vid .= ','.$last_vid;
                    }
                }
            }
            else
            {
                $last_vid = $uid;
            }
            PutCookie('last_vtime', $vtime, 3600*24, '/');
            PutCookie('last_vid', $last_vid, 3600*24, '/');
```

跟踪putcookie函数

![image-20220307230745490](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072307640.png)



当uid存在值时就会进入我们现在的代码中，当cookie中的`last_vid`中不存在值为空时，就会将uid值赋予过去，`$last_vid = $uid;`，然后PutCookie。

意思就是控制了$uid就相当于可以返回任意值经过服务器处理的md5值。



看验证用户的认证系统的php文件：/include/memberlogin.class.php

![image-20220307230601274](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203072306471.png)



`$this->M_ID`等于Cookie中的DedUserID

跟踪`GetCookie`函数

```
if ( ! function_exists('GetCookie'))
{
    function GetCookie($key)
    {
        global $cfg_cookie_encode;
        if( !isset($_COOKIE[$key]) || !isset($_COOKIE[$key.'__ckMd5']) )
        {
            return '';
        }
        else
        {
            if($_COOKIE[$key.'__ckMd5']!=substr(md5($cfg_cookie_encode.$_COOKIE[$key]),0,16))
            {
                return '';
            }
            else
            {
                return $_COOKIE[$key];
            }
        }
    }
}
```

验证了cookie和md5值

说明，我们控制`uid`为admin的id，然后传入，就拿到md5值，然后直接登录admin用户。

这儿因为有个`intval`函数，那么这么说，如果我们想伪造ID为1的用户的Md5，我们只要在上面设置uid(用户名)为'000001'即可。



