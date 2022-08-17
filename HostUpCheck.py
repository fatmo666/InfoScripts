import argparse
import json
import os
import asyncio
import sys
from asyncio import CancelledError

import IPy
import aioping
from ipaddress import IPv4Network, IPv4Address
from socket import AddressFamily

from BaseObject import BaseObject

class HostUpCheck(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.resultDictHostToIp = {}

        self.hostUp = []
        self.hostDown = []

        self.writeFlag = True

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
        self.threads = args.threads
        self.timeout = args.timeout
        if not os.path.isfile(target):
            # target = 'http://' + target
            if str(target.split('.')[-1]) == '0/24':
                self.writeFlag = False
                for ip in IPy.IP(target):
                    self.domains.append(str(ip))
            else:
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
            sem = asyncio.Semaphore(self.threads)


            for domain in self.domains:
                if os.path.exists(os.path.abspath(__file__) + '/CheckResult/' + self.fileName + "/") is False:
                    # os.mkdir(os.path.abspath(__file__) + '/CheckResult/' + self.fileName + "/")
                    os.mkdir(os.getcwd() + '/CheckResult/' + self.fileName + "/")

                if self.writeFlag == True:
                    if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                        os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.CheckHostUp(domain, sem)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+] Break From Queue.')
        except CancelledError:
            pass

        self.writeResult()

    async def CheckHostUp(self, domain, sem):
        self.queryResult[domain] = {}
        pingResult = await self.pingAIO(domain, sem, self.timeout)
        if pingResult == True:
            self.hostUp.append(domain)
            self.queryResult[domain]['HostUp'] = "1"
            self.logger.info('[+] Target: ' + domain + ' up!')
            return True
        else:
            self.hostDown.append(domain)
            self.queryResult[domain]['HostUp'] = "0"
            return False

    async def pingAIO(self, target, sem, timeout):
        async with sem:
            # print("Start:", target)
            try:
                delay = await aioping.ping(
                    str(target), timeout, family=AddressFamily.AF_INET
                )
                return True
            except TimeoutError:
                return False
            except OSError as error:
                return False

    def argparser(self):
        """
        解析参数
        :return:参数解析结果
        """
        parser = argparse.ArgumentParser(description='InfoScripts can help you collect target\'s information',
                                         epilog='\tUsage:\npython3 ' + sys.argv[0] + " --target www.baidu.com --timeout 10")
        parser.add_argument('--target', '-t', help='A target like www.example.com or subdomains.txt, target can be txt file,a domain, a ip address or a class c ip address like 192.168.0.0/24, when target is class c address, the script\
         will not create result folder for every ip', required=True)
        parser.add_argument('--timeout', help='Set the ping\'s timeout', default=3, required=False, type=int)
        parser.add_argument('--threads', help='Set the concurrent quantity', default=1024, required=False, type=int)

        args = parser.parse_args()
        return args

    def writeResult(self):
        with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'HostUp' + '.txt', 'a') as fp:
            for domain in self.hostUp:
                fp.write(domain + "\n")

                if self.writeFlag == True:
                    with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + '/' + 'HostUpInfo.json', 'w') as fpResult:
                        json.dump(self.queryResult[domain], fpResult, indent=2)

if __name__ == '__main__':
    hostUpInfo = HostUpCheck()
    hostUpInfo.startQuery()