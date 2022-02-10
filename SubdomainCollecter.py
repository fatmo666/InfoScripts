import asyncio
import json
import os
import sys
from asyncio import CancelledError
import aiohttp
import argparse

import sublist3r
from ESD import EnumSubDomain

from bs4 import BeautifulSoup

from BaseObject import BaseObject

class SubdomainCollecter(BaseObject):

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

    def startQuery(self):
        try:
            tasks = []
            newLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(newLoop)
            loop = asyncio.get_event_loop()

            for domain in self.domains:
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.subdomainCollect(domain)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[-]用户手动终止程序.')
        except CancelledError:
            pass

        # self.writeResult()

    async def subdomainCollect(self, domain):
        pass

