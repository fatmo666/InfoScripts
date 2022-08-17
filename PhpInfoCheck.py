import asyncio
import json
import os
from asyncio import CancelledError

import aiohttp
from bs4 import BeautifulSoup, element

from Config.phpinfo.phpinfo import phpinfoList
from BaseObject import BaseObject


class PhpInfoCheck(BaseObject):
    """
    本脚本为项目：https://github.com/proudwind/phpinfo_scanner ,的修改与补充
    """
    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.result = {}

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
        self.threads = args.threads
        if not os.path.isfile(target):
            # target = 'http://' + target
            self.domains.append(target)
        elif os.path.isfile(target):
            with open(target, 'r+', encoding='utf-8') as f:
                for domain in f:
                    domain = domain.strip()
                    if not domain.startswith(('http://', 'https://')):
                        self.domains.append(domain)

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()

            for domain in self.domains:
                if os.path.exists(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + '/') is False:
                    os.mkdir(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.infoCollect(domain)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break By User.')
        except CancelledError:
            pass

        self.writeResult()

    def writeResult(self):
        """
        保存结果
        :return:
        """
        with open(os.getcwd() + '/CheckResult/' + self.fileName + "/" + 'phpinfo' + '.txt', 'a') as fp:
            for item in self.queryResult.keys():
                fp.write(item + '\n')

                with open(os.getcwd() + '/result/' + item + "/" + 'PhpInfoVul' + '.txt',
                          'w') as fpResult:
                    for i in self.result[item]:
                        fpResult.write(str(i) + '\n')

                with open(os.getcwd() + '/result/' + item + "/" + 'phpinfo' + '.json', 'w') as fpResult:
                    json.dump(self.queryResult[item], fpResult, indent=2)

    async def infoCollect(self, domain):
        self.queryResult[domain] = {}

        for item in phpinfoList:
            sem = asyncio.Semaphore(self.threads)
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                    async with sem:
                        async with session.get('http://' + domain + '/' + item, timeout=20, headers=self.headers) as req:
                            await asyncio.sleep(1)
                            response = await req.text('utf-8', 'ignore')
                            status = req.status
                            if status == 200:
                                self.logger.info("[+] Target: " + domain + " have phpinfo!")
                                self.infoCollecter(domain, response)
                                self.get_parsed_info(domain)
            except CancelledError:
                pass
            except ConnectionResetError:
                pass
            except Exception as e:
                return None


    async def getDomainIP(self, domain):
        for item in phpinfoList:
            sem = asyncio.Semaphore(1024)
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                    async with sem:
                        async with session.get('http://' + domain + '/' + item, timeout=20,
                                               headers=self.headers) as req:
                            await asyncio.sleep(1)
                            response = await req.text('utf-8', 'ignore')
                            status = req.status
                            if status == 200:
                                self.infoCollecter(domain, response)
                                self.get_parsed_info(domain)
                                return self.queryResult[domain]['PHP Variables']["$_SERVER['SERVER_ADDR']"]
            except CancelledError:
                pass
            except ConnectionResetError:
                pass
            except Exception as e:
                pass
        return None


    def infoCollecter(self, domain, response):
        self.queryResult[domain]["BaseInfo"] = {}
        soup = BeautifulSoup(response, "lxml")
        if len(soup.select("body > div >table:nth-child(2)")) != 0:
            baseInfo = soup.select("body > div >table:nth-child(2)")[0]
        else:
            baseInfo = soup.select("body > div >table:nth-child(3)")[0]

        for tr in baseInfo.find_all("tr"):
            key = tr.select("td.e")[0].string.strip()
            value = tr.select("td.v")[0].string.strip()
            self.queryResult[domain]["BaseInfo"][key] = value

        for h2 in soup.find_all("h2"):
            moduleName = h2.string.strip()
            self.queryResult[domain][moduleName] = {}
            # 每一个配置模块是从h2标题开始的，向下寻找所有的table标签
            # 有一个特殊情况PHP Credits，它在h1标签中，其内容是php及其sapi、module等的作者，对脚本功能没有意义，所以不解析
            for sibling in h2.next_siblings:
                # 使用next_siblings会匹配到许多\n \t等，需特殊处理，官方文档明确提到
                if sibling.name != "table" and type(sibling) != element.NavigableString and sibling.name != "br":
                    break
                if sibling.name == "table":
                    for tr in sibling.find_all("tr"):
                        keyElements = tr.select("td.e")
                        if len(keyElements) == 0:
                            continue
                        key = keyElements[0].string.strip()

                        valueElements = tr.select("td.v")
                        if len(valueElements) == 0:
                            value = ''
                        elif len(valueElements) == 2:
                            # 有些配置的value分为Local Value和Master Value
                            # local value是当前目录的设置，会受.htaccess、.user.ini、代码中ini_set()等的影响
                            # master value是php.ini中的值
                            value = [valueElements[0].string.strip(), valueElements[1].string.strip()]
                        else:
                            value = "no value" if valueElements[0].string == None else valueElements[0].string.strip()
                        self.queryResult[domain][moduleName][key] = value

        # windos _SERVER["xx"]
        # linux $_SERVER['xx']
        # 消除这种差异
        php_var_dict = {}
        if list(self.queryResult[domain]["PHP Variables"].keys())[0][0] == "_":
            for key in self.queryResult[domain]["PHP Variables"].keys():
                new_key = "$" + key.replace('"', "'")
                php_var_dict[new_key] = self.queryResult[domain]["PHP Variables"][key]
            self.queryResult[domain]["PHP Variables"] = php_var_dict

    # 解析获取到的信息，如bypass_disable_function、php版本特性等
    def get_parsed_info(self, domain):
        self.result[domain] = []
        # php version
        suggestion = self.get_version_feature(self.queryResult[domain]["Core"]["PHP Version"])
        if suggestion:
            self.result[domain].append([suggestion])
        # sapi
        sapi = self.queryResult[domain]["BaseInfo"]["Server API"]
        if "FPM" in sapi:
            self.result[domain].append(["SAPI为fpm，可能存在未授权访问漏洞"])
        # phar
        if "phar" in self.queryResult[domain]["BaseInfo"]["Registered PHP Streams"]:
            self.result[domain].append(["支持phar协议，可扩展反序列化攻击面"])
        # ssrf curl php_wrapper
        protocols = ["gopher", "dict"]
        available_protocols = []
        if "curl" in self.queryResult[domain]:
            for protocol in protocols:
                if protocol in self.queryResult[domain]["curl"]["Protocols"]:
                    available_protocols.append(protocol)
            self.result[domain].append(["libcurl支持%s协议" % (", ".join(available_protocols))])
        # libxml版本
        if "libxml" in self.queryResult[domain] and self.queryResult[domain]["libxml"]["libXML Compiled Version"] < "2.9":
            self.result[domain].append(["libxml版本 < 2.9 xxe可利用"])
        # session upload progress
        if self.queryResult[domain]["session"]["session.upload_progress.enabled"][0] == "On":
            suggestion = "可利用session.upload_progress上传临时文件然后包含"
            if self.queryResult[domain]["session"]["session.upload_progress.cleanup"][0] == "On":
                suggestion += "\n临时文件会立刻删除，需用条件竞争getshell"
            self.result[domain].append([suggestion])
        # session ser handler
        if self.queryResult[domain]["session"]["session.serialize_handler"][0] != \
                self.queryResult[domain]["session"]["session.serialize_handler"][1]:
            self.result[domain].append(["ser handler不一致，存在反序列化风险"])
        # imagick
        if "imagick" in self.queryResult[domain]:
            self.result[domain].append(["可利用imagick相关漏洞"])
        # xdebug
        if "xdebug" in self.queryResult[domain] and self.queryResult[domain]["xdebug"]["xdebug.remote_connect_back"][0] == "On" and \
                self.queryResult[domain]["xdebug"]["xdebug.remote_enable"][0] == "On":
            self.result[domain].append(["存在xdebug rce https://github.com/vulhub/vulhub/tree/master/php/xdebug-rce\nxdebug idekey: " +
                           self.queryResult[domain]["xdebug"]["xdebug.idekey"][0]])
        # opcache
        if "opcache" in self.queryResult[domain]:
            self.result[domain].append(["可上传opcache覆盖源文件"])
        # imap
        if "imap" in self.queryResult[domain]:
            self.result[domain].append(["可能存在imap rce https://github.com/vulhub/vulhub/blob/master/php/CVE-2018-19518/README.md"])
        # disable function
        if self.queryResult[domain]["Core"]["disable_functions"][0] != "no value":
            self.result[domain].append([self.bypass_disable_function(self.queryResult[domain]["Core"]["disable_functions"][0], self.queryResult[domain])])

    # 根据版本获取版本特性
    def get_version_feature(self, version):
        suggestion = ""
        if "7.2" in version:
            suggestion = "php 7.2: assert从函数变为语法结构，无法动态调用; 移除create_function"
        if "7.0" in version:
            suggestion = "php 7.0: 移除dl; 不再支持asp_tag、<script language=\"php\">"
        return suggestion

    # 如果存在disable_function，寻找可能的bypass
    def bypass_disable_function(self, disable_func, phpinfo_dict):
        disable_func = disable_func.split(",")
        suggestion = ""
        bypass_func = []

        if "dl" not in disable_func and phpinfo_dict["Core"]["enable_dl"] == "On":
            bypass_func.append("dl")
        if "pcntl_exec" not in disable_func and "--enable-pcntl" in phpinfo_dict["BaseInfo"]["Configure Command"]:
            bypass_func.append("pcntl_exec")
        common_funcs = ['exec', 'system', 'passthru', 'popen', 'proc_open', 'shell_exec']
        for func in common_funcs:
            if func not in disable_func:
                bypass_func.append(func)
        suggestion += "可用函数：" + ", ".join(bypass_func) + "\n"

        if "Linux" in phpinfo_dict["BaseInfo"][
            "System"] and "putenv" not in disable_func and "mail" not in disable_func:
            suggestion += "使用LD_PRELOAD https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD\n"
        if "imap" in phpinfo_dict:
            suggestion += "使用imap https://github.com/vulhub/vulhub/blob/master/php/CVE-2018-19518/README.md\n"
        if "imagemagick" in phpinfo_dict:
            suggestion += "使用 ImageMagick\n"
        suggestion += "disable function bypass合集 https://github.com/l3m0n/Bypass_Disable_functions_Shell"
        return suggestion


async def main():
    phpinfoCheck = PhpInfoCheck()
    # phpinfoCheck.startQuery()
    await phpinfoCheck.getDomainIP('www.wzonline.zj.cn')

if __name__ == '__main__':
    phpinfoCheck = PhpInfoCheck()
    phpinfoCheck.startQuery()
    # 获取EventLoop:
    # loop = asyncio.get_event_loop()
    # 执行coroutine
    # loop.run_until_complete(main())
    # loop.close()