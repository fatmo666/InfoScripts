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

                tasks.append(asyncio.ensure_future(self.httpScan(domain)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break From Queue.')
        except CancelledError:
            pass

        self.writeResult()

    async def httpScan(self, domain):
        scanner = aionmap.PortScanner()
        print(await scanner.nmap_version())
        result = await scanner.scan(domain, None, '-p 80,7777')
        print(result)

    def writeResult(self):
        with open('./CheckResult/' + self.fileName + "/" + 'http' + '.txt', 'a') as fp:
            for domain in self.domains:
                pass
                # fp.write(domain + "\n")

                # with open(os.getcwd() + '/result/' + domain + '/' + 'HostUpInfo.json', 'w') as fpResult:
                #     json.dump(self.queryResult[domain], fpResult, indent=2)


if __name__ == '__main__':
    hostUpInfo = PortScanner()
    hostUpInfo.startQuery()