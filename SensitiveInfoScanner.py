import asyncio
import os
import sys
from asyncio import CancelledError

import aiohttp
import argparse

from BaseObject import BaseObject

class SensitiveInfoScanner(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}

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

        self.headers = {}
        self.buildHeader()

    def argparser(self):
        """
        解析参数
        :return:参数解析结果
        """
        parser = argparse.ArgumentParser(description='InfoScripts can help you collect target\'s information',
                                         epilog='\tUsage:\npython3 ' + sys.argv[0] + " --target www.baidu.com --threads 3")
        parser.add_argument('--target', '-t', help='A target like www.example.com or subdomains.txt', required=True)
        parser.add_argument('--threads', help='Set the concurrent quantity', default=3, required=False, type=int)

        args = parser.parse_args()
        return args

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()
            sem = asyncio.Semaphore(self.threads)

            for domain in self.domains:
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.SensitiveInfoScann('http://' + domain, sem)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break By User.')
        except CancelledError:
            pass

        self.writeResult()
    
    async def SensitiveInfoScann(self, domain, sem):
        """
        """

        self.queryResult[domain.replace('http://', '')] = {}
        self.queryResult[domain.replace('http://', '')]['200'] = []
        self.queryResult[domain.replace('http://', '')]['403'] = []

        with open(os.path.dirname(os.path.abspath(__file__)) + '/Config/Dir/sensitive.txt', 'r', encoding='utf-8') as fp:
            for row in fp.readlines():
                url = domain + row.strip()
                sem = asyncio.Semaphore(self.threads)
                try:
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                        async with sem:
                            # 设置禁止跳转
                            async with session.get(url, timeout=20, headers=self.headers, allow_redirects=False) as req:
                                await asyncio.sleep(1)
                                if req.status == 200:
                                    self.queryResult[domain.replace('http://', '')]['200'].append(url)
                                elif req.status == 403:
                                    self.queryResult[domain.replace('http://', '')]['403'].append(url)
                                req.close()
                except CancelledError:
                    pass
                except ConnectionResetError:
                    pass
                except Exception as e:
                    self.logger.info('[-]Sensitive: {} http请求失败'.format(domain))

        return None

    def writeResult(self):
        """
        保存结果
        :return:
        """

        for domain in self.domains:
            with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + "/" + 'sensitive' + '.txt', 'w') as fpResult:
                for row in self.queryResult[domain.replace('http://', '')]['200']:
                    fpResult.write(row + '\r\n')


if __name__ == '__main__':
    sensitiveInfoScanner = SensitiveInfoScanner()
    sensitiveInfoScanner.startQuery()