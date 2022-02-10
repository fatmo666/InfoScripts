import asyncio
import json
import os
from asyncio import CancelledError
import aiohttp
import mmh3, codecs
from bs4 import BeautifulSoup

from BaseObject import BaseObject
from ShodanObject import ShodanObject
from PhpInfoCheck import PhpInfoCheck
from CensysObject import CensysObject

class CDNByPass(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.shodanObject = ShodanObject()

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
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
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.cdnByPass(domain)))

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

        for domain in self.domains:
            with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + "/" + 'cdnPassInfo' + '.txt', 'a') as fpResult:
                for item in self.queryResult[domain]:
                    fpResult.write(item + "\n")

    async def cdnByPass(self, domain):
        self.queryResult[domain] = []

        icoHashString = await self.calcFaviconHash(domain)
        iconList = self.shodanObject.getIcoHashList(icoHashString)
        for item in iconList:
            self.queryResult[domain].append(item)
            # if await self.checkIP(item):
            #     self.queryResult[domain].append(item)

        titleString = await self.getDomainTitle(domain)
        if titleString != False:
            titleList = self.shodanObject.getTitleList("title:" + titleString)
            for item in titleList:
                self.queryResult[domain].append(item)
                # if await self.checkIP(item):
                #     self.queryResult[domain].append(item)

        phpinfoCheck = PhpInfoCheck()
        phpinfoIP = await phpinfoCheck.getDomainIP(domain)
        if phpinfoIP != None:
            self.queryResult[domain].append(phpinfoIP)
            # if await self.checkIP(phpinfoIP):
            #     self.queryResult[domain].append(phpinfoIP)

        censysCheck = CensysObject()
        censysIp = await censysCheck.getIP(domain)
        if censysIp != None:
            for item in censysIp:
                self.queryResult[domain].append(item)

        pass

    async def getDomainTitle(self, domain):
        """
        取出目标title
        :param domain:
        :return:
        """
        response = await self.sendRequest('http://' + domain)
        if response != False:
            soup = BeautifulSoup(response, 'lxml')
            return soup.find('title').string
        else:
            return False

    async def checkIP(self, ip):
        """
        验证ip是否可以正常访问
        :param ip:
        :return:
        """
        targetFir = 'http://' + ip + '/'
        targetSec = 'https://' + ip + '/'

        tagetFirResult = await self.sendRequest(targetFir)
        if tagetFirResult != False:
            return True

        tagetSecResult = await self.sendRequest(targetSec)
        if tagetSecResult != False:
            return True

    async def calcFaviconHash(self, domain):
        """
        计算目标站点的icon-hash
        :param domain:
        :return:
        """
        requestUrl = 'http://' + domain + '/favicon.ico'
        # responseContent = requests.get(requestUrl, verify=False).content

        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                async with sem:
                    async with session.get(requestUrl, timeout=20, headers=self.headers) as req:
                        await asyncio.sleep(1)
                        responseContent = await req.content.read()
                        req.close()
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            self.logger.error('[-]Resolve {} fail'.format(requestUrl))
            return False

        iconHash = mmh3.hash(codecs.lookup('base64').encode(responseContent)[0])
        return 'http.favicon.hash:' + str(iconHash)

    async def getIPFromPhpinfo(self, domain):
        """
        从phpinfo中获取ip
        :param domain:
        :return:
        """

        phpinfoCheck = PhpInfoCheck()
        return await phpinfoCheck.getDomainIP('www.wzonline.zj.cn')


if __name__ == '__main__':
    cdnByPass = CDNByPass()
    cdnByPass.startQuery()
    print(cdnByPass.queryResult)