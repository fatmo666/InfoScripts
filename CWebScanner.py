import asyncio
import json
import os
import sys
import IPy
from asyncio import CancelledError

import aiodns
import aiohttp
import argparse

from bs4 import BeautifulSoup

from BaseObject import BaseObject

class CWebScanner(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.resultList = []

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
        self.ports = args.port.split(",")
        if not os.path.isfile(target):
            # target = 'http://' + target
            self.domains.append(target)
        elif os.path.isfile(target):
            with open(target, 'r+', encoding='utf-8') as f:
                for domain in f:
                    domain = domain.strip()
                    if not domain.startswith(('http://', 'https://')):
                        self.domains.append(domain)

        self.headers = {}
        self.buildHeader()

    def argparser(self):
        """
        解析参数
        :return:参数解析结果
        """
        parser = argparse.ArgumentParser(description='InfoScripts can help you collect target\'s information',
                                         epilog='\tUsage:\npython3 ' + sys.argv[0] + " --target www.baidu.com --port 80,8080")
        parser.add_argument('--target', '-t', help='A target like www.example.com or subdomains.txt', required=True)
        parser.add_argument('--port', '-p', type=str, default="80", help='The port you chose to scan(default 80)', required=False)

        args = parser.parse_args()
        return args

    async def handleTarget(self, target, resolver):
        #处理给定扫描目标
        rawTarget = target
        try:
            if int(target.split('.')[-1]) >= 0:
                result = ""
                for item in target.split('.')[:3]:
                    result += item
                    result += "."
                result += '0/24'
                return result
        except:
            result = await self.getIP(target, resolver)
            if result != None:
                target = result.host
                if int(target.split('.')[-1]) >= 0:
                    result = ""
                    for item in target.split('.')[:3]:
                        result += item
                        result += "."
                    result += '0/24'
                    return result
            else:
                self.logger.error('[-]Input error: 输入有误: {}'.format(rawTarget))
                exit(1)

    async def getIP(self, domain, resolver):
        """
        尝试获得域名的IP地址
        :param domain:
        :return:
        """

        try:
            answer = await resolver.query(domain, 'A')
            return answer[0]
        except:
            self.logger.error('[-]CDNCheck-Check getIP: {} DNS A解析失败'.format(domain))
            return None

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()
            resolver = aiodns.DNSResolver(loop=loop)
            sem = asyncio.Semaphore(256)

            for domain in self.domains:
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.scan(domain, resolver, sem)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[-]用户手动终止程序.')
        except CancelledError:
            pass

        self.writeResult()

    async def scan(self, target, resolver, sem):
        async with sem:
            target = await self.handleTarget(target, resolver)
            ipLists = self.getIPList(target)

            for port in self.ports:
                for ip in ipLists:
                    url = "https://" + ip + ":" + port
                    response, header = await self.sendRequest(url)
                    if response != False:
                        self.resultList.append(ip)
                        self.queryResult[ip] = {}
                        self.queryResult[ip]["ip"] = ip
                        header = dict(header)
                        if "Server" in header.keys():
                            self.queryResult[ip]["server"] = header['Server']
                        if BeautifulSoup(response, 'lxml').title != None:
                            self.queryResult[ip]["title"] = BeautifulSoup(response, 'lxml').title.text.strip('\n').strip()

            return None


    def writeResult(self):
        """
        保存结果
        :return:
        """
        with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'ipList' + '.txt', 'a') as fpIs:
            with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'ipInfo' + '.txt', 'a') as fpInfo:
                for ip in self.resultList:
                    fpIs.write(ip + "\n")
                    fpInfo.write(str(self.queryResult[ip]) + "\n")

    def getIPList(self, target):
        ipList = []
        for ip in IPy.IP(target):
            ipList.append(str(ip))

        return ipList


    async def sendRequest(self, url):
        """
        发送http请求
        :param url:
        :return:
        """
        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                async with sem:
                    async with session.get(url, timeout=20, headers=self.headers, verify_ssl=None) as req:
                        await asyncio.sleep(1)
                        response = await req.text('utf-8', 'ignore')
                        header = req.headers
                        req.close()
                        return response, header
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            return False, False

if __name__ == '__main__':
    cWebScanner = CWebScanner()
    cWebScanner.startQuery()