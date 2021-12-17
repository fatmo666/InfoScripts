import asyncio
import json
import os
from asyncio import CancelledError

import aiohttp

from BaseObject import BaseObject

class HeaderCheck(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.shiroList = []

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

                tasks.append(asyncio.ensure_future(self.checkHeader('http://' + domain)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break By User.')
        except CancelledError:
            pass

        self.writeResult()

    async def checkHeader(self, domain):
        """
        收集HTTP请求头
        :param domain:需请求的域名
        :return:共两个返回值:
        1. 检查结果,True/False
        2. 若为True，命中的那个key
        """
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/79.0.3945.130 Safari/537.36',
            "Cookie": "rememberMe = yyds"
        }
        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                async with sem:
                    async with session.get(domain, timeout=20, headers=self.headers) as req:
                        await asyncio.sleep(1)
                        self.shiroCheck(domain, req.headers)
                        self.queryResult[domain.replace('http://', '')] = dict(req.headers)
                        req.close()
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            self.logger.info('[-]CDNCheck-Check header: {} http请求失败'.format(domain))

        return False, ""

    def shiroCheck(self, httpHeaders, domain):
        try:
            if 'rememberMe=deleteMe' in httpHeaders['Set-Cookie']:
                self.shiroList.append(domain)
                return True
            else:
                return False
        except:
            return False


    def writeResult(self):
        """
        保存结果
        :return:
        """
        with open('./CheckResult/' + self.fileName + "/" + 'isCDN' + '.txt', 'a') as fp:
            pass

        for domain in self.domains:
            with open('./result/' + domain + "/" + 'headerInfo' + '.json', 'w') as fpResult:
                json.dump(self.queryResult[domain], fpResult, indent=2)


if __name__ == '__main__':
    headerInfo = HeaderCheck()
    headerInfo.startQuery()