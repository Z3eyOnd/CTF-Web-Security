##  什么是docker

docker就是一个应用容器，可以让开发者打包他们的应用以及依赖包到一个轻量级、可移植的容器中，然后发布到任何流行的 Linux 机器上，也可以实现虚拟化。

现在利用docker，搭建CTF题目环境就比较容易了。

## Docker的安装

参考菜鸟教程：https://www.runoob.com/docker/ubuntu-docker-install.html

##  docker的一些命令

1.启动docker

>systemctl start docker

2.获取docker的所有命令选项

>docker

3.拉取镜像。

> docker pull [image]

4.查看docker当前镜像。

> docker image ls 或 docker images

5.新建一个docker容器，并映射端口号。

> docker run -d -p [host port]:[docker port] [image]

6.新建一个ubuntu容器

>docker run --name ubuntu-test ubuntu

7.查看运行中的docker容器。

> docker ps -a

8.查看所有的docker容器

>docker ps

注意：镜像和容器是两个区别。

9.拷贝本地文件到docker。

> docker cp [本地路径] [container id]:[container 路径]

10.进入一个docker容器,执行命令。

> docker exec -it [container id] bash

11.开启一个docker容器

>docker start [container id]

12.停止一个docker容器

>docker stop [container id]

13.删除一个docker容器

>docker rm [container id]

14.删除一个容器

>docker rmi [image id]

##  利用lamp搭建CTF题目

lamp环境的介绍：类似于phpstudy，就是把mysql，apache，php安装在linux系统上，组成一个环境来运行php脚本语言。



第一步：打开docker环境

>systemctl start docker

第二步：寻找一个有lamp环境的镜像

>docker search lamp

![image-20220320145103353](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203201451459.png)

第三步:拉取lamp镜像

>docker pull tutum/lamp

第四步：查看镜像

>docker images

![image-20220320145215822](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203201452861.png)

第五步：打开容器，并映射端口

>docker run -d -p 10000:80 tutum/lamp

第六步：检测10000端口是否存在

浏览器访问：ip地址+端口

![image-20220320145419974](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203201454036.png)

第七步：把文件copy到容器中

>docker cp /www/wwwroot/docker/test 14614f8e3057:/var/www/html/

![image-20220320145721434](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203201457461.png)第八步：开始访问

![image-20220320145807326](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203201458368.png)

成功。

后面就是停止和删除容器。

##  vscode连接docker容器，实现直接编辑docker

https://zhuanlan.zhihu.com/p/361934730

##  dockerfile的编写

