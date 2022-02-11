import asyncio
import json
import os
import sys
from asyncio import CancelledError

import aiohttp
import argparse
import aionmap

from BaseObject import BaseObject

class PortScanner(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
        self.ports = args.port
        if not os.path.isfile(target):
            # target = 'http://' + target
            self.domains.append(target)
        elif os.path.isfile(target):
            with open(target, 'r+', encoding='utf-8') as f:
                for domain in f:
                    domain = domain.strip()
                    if not domain.startswith(('http://', 'https://')):
                        self.domains.append(domain)

    def argparser(self):
        """
        解析参数
        :return:参数解析结果
        """
        parser = argparse.ArgumentParser(description='InfoScripts can help you collect target\'s information',
                                         epilog='\tUsage:\npython3 ' + sys.argv[0] + " --target www.baidu.com -p 80,8080")
        parser.add_argument('--target', '-t', help='A target like www.example.com or subdomains.txt', required=True)
        parser.add_argument('--port', '-p', help='the ports you want to scan', required=True)
        args = parser.parse_args()
        return args

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()
            sem = asyncio.Semaphore(256)
            scanner = aionmap.PortScanner()

            for domain in self.domains:
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.scan(domain, sem, scanner)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break From Queue.')
        except CancelledError:
            pass

        self.writeResult()

    async def scan(self, domain, sem, scanner):
        async with sem:
            result = await scanner.scan(domain, None, '-p {}'.format(self.ports))
            for item in result.hosts[0].services:
                if item.state == 'open':
                    if domain not in self.queryResult.keys():
                        self.queryResult[domain] = {}
                    if 'open' not in self.queryResult[domain].keys():
                        self.queryResult[domain]["open"] = []
                    self.queryResult[domain]["open"].append(item.port)
                elif item.state == 'filtered':
                    if domain not in self.queryResult.keys():
                        self.queryResult[domain] = {}
                    if 'filtered' not in self.queryResult[domain].keys():
                        self.queryResult[domain]["filtered"] = []
                    self.queryResult[domain]["filtered"].append(item.port)

    def writeResult(self):
        with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'port-open' + '.txt', 'a') as fp:
            for domain in self.domains:
                for port in self.queryResult[domain]["open"]:
                    fp.write(domain + "|" + str(port) + '\r\n')

                with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + '/' + 'ports.json', 'w') as fpResult:
                    json.dump(self.queryResult[domain], fpResult, indent=2)

        with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'port-filtered' + '.txt', 'a') as fp:
            for domain in self.domains:
                for port in self.queryResult[domain]["filtered"]:
                    fp.write(domain + "|" + str(port) + '\r\n')


if __name__ == '__main__':
    hostUpInfo = PortScanner()
    hostUpInfo.startQuery()