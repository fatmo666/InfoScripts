import asyncio
import json
import os
import re
import sys
from asyncio import CancelledError

import aiodns
import aiohttp

from BaseObject import BaseObject

from Config.OtherSite.apis import *

class OtherSiteSearcher(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.resultList = []

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
        # self.ports = args.port.split(",")
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

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()
            resolver = aiodns.DNSResolver(loop=loop)

            for domain in self.domains:
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.search(domain, resolver)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[-]用户手动终止程序.')
        except CancelledError:
            pass

        self.writeResult()

    def writeResult(self):
        """
        保存结果
        :return:
        """

        for domain in self.domains:
            with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + "/" + 'OtherSite' + '.json', 'w') as fpResult:
                json.dump(self.queryResult[domain], fpResult, indent=2, ensure_ascii=False)



    async def search(self, domain, resolver):
        # 尝试获取IP地址
        if not re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            ip = await self.getIP(domain, resolver)
        else:
            ip = domain
        if ip is None:
            return

        # self.queryResult[domain] = {}

        webScanResult = await self.webScan(ip)
        self.queryResult[domain] = webScanResult
        pass

    async def getIP(self, domain, resolver):
        """
        尝试获得域名的IP地址
        :param domain:
        :return:
        """

        try:
            answer = await resolver.query(domain, 'A')
            return answer[0].host
        except:
            self.logger.error('[-]CDNCheck-Check getIP: {} DNS A解析失败'.format(domain))
            return None

    async def webScan(self, ip):
        url = webscanApi + ip
        response = await self.sendRequest(url)
        response = json.loads(response)
        return response

if __name__ == '__main__':
    otherSite = OtherSiteSearcher()
    otherSite.startQuery()