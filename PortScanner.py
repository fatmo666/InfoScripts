import asyncio
import json
import os
import sys
from asyncio import CancelledError

import aiohttp
import argparse
import aionmap

from BaseObject import BaseObject

from Config.Port.VulPort import portDict

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
        parser.add_argument('--port', '-p', help='the ports you want to scan', required=False, default='21,22,23,80-89,161,389,443,445,512-514,873,1025,111,1433,1521,2082,2083,2222,2601,2604,3128,3306,3312,3311,3389,4440,5432,5900,5984,6082,6379,7001,7002,7778,8000-9090,8080,8089,9090,8083,8649,8888,9200,9300,10000,11211,27017,27018,28017,50000,50070,50030')
        args = parser.parse_args()
        return args

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()
            sem = asyncio.Semaphore(48)
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
            if result.hosts == []:
                return
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
            with open('./CheckResult/' + self.fileName + '/port-vul.txt', 'a') as fpVulCheck:
                for domain in self.queryResult.keys():
                    with open('./result/' + domain + '/port-vul.txt', 'w') as fpVul:
                        if "open" in self.queryResult[domain].keys():
                            for port in self.queryResult[domain]["open"]:
                                fp.write(domain + "|" + str(port) + '\r\n')
                                if str(port) in portDict.keys():
                                    fpVul.write(str(port) + ":" + portDict[str(port)] + '\r\n')
                                    fpVulCheck.write(domain + ":" + str(port) + ":" + portDict[str(port)] + "\n")


                with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + '/' + 'ports.json', 'w') as fpResult:
                    json.dump(self.queryResult[domain], fpResult, indent=2)

        with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'port-filtered' + '.txt', 'a') as fp:
            for domain in self.queryResult.keys():
                if "filtered" in self.queryResult[domain].keys():
                    for port in self.queryResult[domain]["filtered"]:
                        fp.write(domain + "|" + str(port) + '\r\n')


if __name__ == '__main__':
    hostUpInfo = PortScanner()
    hostUpInfo.startQuery()