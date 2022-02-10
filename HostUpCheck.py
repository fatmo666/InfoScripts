import json
import os
import asyncio
from asyncio import CancelledError

import nmap

from BaseObject import BaseObject

class HostUpCheck(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}
        self.resultDictHostToIp = {}

        self.hostUp = []
        self.hostDown = []

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

                tasks.append(asyncio.ensure_future(self.CheckHostUp(domain)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break From Queue.')
        except CancelledError:
            pass

        self.writeResult()

    async def CheckHostUp(self, domain):
        self.queryResult[domain] = {}
        ping_scan_raw = await self.scanHostUp(domain)
        for item in ping_scan_raw['scan'].items():
            if item[1]['status']['state'] == "up":
                self.hostUp.append(domain)
                self.queryResult[domain]['HostUp'] = "1"
                self.resultDictHostToIp[item[1]['hostnames'][0]['name']] = item[0]
                return True
            else:
                self.hostDown.append(domain)
                self.queryResult[domain]['HostUp'] = "0"
                return False

    async def scanHostUp(self, domain):
        await asyncio.sleep(1)
        nm = nmap.PortScanner()  # 设置为nmap扫描状态。
        ping_scan_raw = nm.scan(hosts=domain,
                                arguments='-sn')  # hosts可以是单个IP地址也可以是一整个网段。    arguments就是运用什么方式扫描，-sn就是ping扫描。
        return ping_scan_raw

    def writeResult(self):
        with open('./CheckResult/' + self.fileName + "/" + 'HostUp' + '.txt', 'a') as fp:
            for domain in self.domains:
                fp.write(domain + "\n")

                with open(os.getcwd() + '/result/' + domain + '/' + 'HostUpInfo.json', 'w') as fpResult:
                    json.dump(self.queryResult[domain], fpResult, indent=2)


if __name__ == '__main__':
    hostUpInfo = HostUpCheck()
    hostUpInfo.startQuery()