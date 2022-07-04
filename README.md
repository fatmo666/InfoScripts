## :cat:项目简介

项目地址：[https://github.com/fatmo666/InfoScripts](https://github.com/shmilylty/OneForAll)

一个渗透测试/SRC挖掘中用于信息收集的脚本集合，旨在帮助测试人员/学生更快、更全、更准确的收集到渗透测试中有价值的信息。

### 优势：

1. 使用协程，效率高。

   经测试，进行10次DNS解析，使用协程比不使用协程快**510**倍；进行10次HTTP请求，使用协程比不使用协程快**3**倍。

2. 脚本全，收集面广。

   目标完成包含CDN探测与绕过、端口扫描、整站爬虫等脚本在内的全面的脚本集合，减少测试过程工具收集和切换成本。

3. 同步代码解读文章，代码可读性好。

   伴随脚本更新，会同步更新其脚本所收集的信息，收集思路和关键代码片段，帮助用户理解及修改脚本。

目前InfoScripts还在开发中，肯定有不少问题和需要改进的地方，欢迎大佬们提出宝贵意见，觉得还行就给个star吧:star2::star2::star2:。



## :rabbit:使用说明

### 1. 工具安装

#### Windows系统:

```
git clone https://github.com/fatmo666/InfoScripts.git
pip install -r requestments.txt
```

PS: 可直接下载zip文件至指定目录代替git clone

#### Linux系统：

```
git clone https://github.com/fatmo666/InfoScripts.git
pip3 install -r requestments.txt
```



### 2.查看参数

指定需要使用的脚本，添加参数-h即可

示例：

```
┌──(root??kali)-[~/InfoScript]
└─# python3 PhpInfoCheck.py -h                                                                                                                                                                                                               
usage: PhpInfoCheck.py [-h] --target TARGET [--threads THREADS]

InfoScripts can help you collect target's information

optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        A target like www.example.com or subdomains.txt
  --threads THREADS     Set the concurrent quantity

Usage: python3 PhpInfoCheck.py --target www.baidu.com
```



### 3.输出说明

本项目存在两个输出目录：`\result\`和`\CheckResult\`

1. 目录`\result\`中保存有以域名作为名称的文件夹，每个文件夹内保存有当前域名所有收集到的信息
2. 目录`\CheckResult\`中保存有以时间作为名称的文件夹，每个文件夹内保存有单次运行脚本所生成的结果

示例：

我于时间`2022-03-06 13:21:10`运行脚本`python3 PortScanner.py --target xxx.com`

那么目录`\result\`下会生成文件夹：`\xxx.com\`，且在脚本运行结束后生成文件ports.json

目录`\CheckResult\`会生成文件夹：`2022-03-06-13-21-10`，且在脚本运行结束后生成文件port-open.txt与port-vul.txt



## :dog:已完成功能一览

- 存活主机探测：[HostUpCheck.py](https://github.com/fatmo666/InfoScripts/blob/master/HostUpCheck.py)
- HTTP-header信息收集：[HeaderCheck.py](https://github.com/fatmo666/InfoScripts/blob/master/HeaderCheck.py)
- CDN探测：[CDNCheck.py](https://github.com/fatmo666/InfoScripts/blob/master/CDNCheck.py)
- CDN绕过：[CDNByPass.py](https://github.com/fatmo666/InfoScripts/blob/master/CDNByPass.py)
- C段扫描：[CWebScanner.py](https://github.com/fatmo666/InfoScripts/blob/master/CWebScanner.py)
- 目录爆破：[DirBruter.py](https://github.com/fatmo666/InfoScripts/blob/master/DirBruter.py)
- 整站爬虫：[Crawler.py](https://github.com/fatmo666/InfoScripts/blob/master/Crawler.py)
- phpinfo信息收集、分析：[PhpInfoCheck.py](https://github.com/fatmo666/InfoScripts/blob/master/PhpInfoCheck.py)
- 端口扫描：[PortScanner.py](https://github.com/fatmo666/InfoScripts/blob/master/PortScanner.py)
- 旁站查询：[OtherSiteSearcher.py](https://github.com/fatmo666/InfoScripts/blob/master/OtherSiteSearcher.py)



## :mouse:TODO

- 敏感目录/文件探测
- web指纹识别
- 常见服务弱口令探测
- 参数爆破
- ……



## :hamster:代码解读文章

代码解读文章均发布在ichunqiu论坛，目前已发布文章如下：

1. [SRC信息收集学习与自动化（一）：开发基础知识巩固](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=62287&fromuid=430620)
2. [SRC信息收集学习与自动化（二）：CDN探测](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=62288&fromuid=430620)
3. [SRC信息收集学习与自动化（三）：phpinfo信息收集与分析](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=62377&fromuid=430620)
4. [SRC信息收集学习与自动化（四）：C段&旁站信息](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=62825&fromuid=430620)

