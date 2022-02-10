import asyncio
import json
import os
from asyncio import CancelledError
import base64

import aiohttp

from BaseObject import BaseObject

from Config.ApiKeys.ApiKey import CenSysUid, CenSysSecret
from Config.Censys.Apis import baseAPi, getSha256, getIp

class CensysObject(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.uid = CenSysUid
        self.secret = CenSysSecret
        self.headers = {}
        self.buildHeader()

    async def getIP(self, domain):
        fingerprintList = []
        ipList = []
        for i in range(50):
            requestBody = {
                "query": "parsed.names:{} and tags.raw:trusted".format(domain),
                "fields": ["parsed.fingerprint_sha256"],
                "page": i+1,
                "flatten": False
            }

            response = await self.sendRequestPost(baseAPi + getSha256, json.dumps(requestBody))
            response = json.loads(response)
            if len(response['results']) == 0:
                break
            for item in response['results']:
                fingerprintList.append(item["parsed"]["fingerprint_sha256"])

        for item in fingerprintList:
            url = baseAPi + getIp.format(item)
            response = await self.sendRequestGet(url)
            response = json.loads(response)
            if len(response['result']['hosts']) != 0:
                for ip in response['result']['hosts']:
                    ipList.append(ip['ip'])

        return ipList

    async def sendRequestPost(self, url, queryBody):
        """
        发送http请求
        :param url:
        :return:
        """
        sem = asyncio.Semaphore(1024)
        try:
            auth = aiohttp.BasicAuth(self.uid, self.secret)
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), headers=self.headers, auth=auth) as session:
                async with sem:
                    async with session.post(url, timeout=20, headers=self.headers, data=queryBody) as req:
                        await asyncio.sleep(1)
                        response = await req.text('utf-8', 'ignore')
                        req.close()
                        return response
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            self.logger.error('[-]Resolve {} fail'.format(url))
            return False

    async def sendRequestGet(self, url):
        """
        发送http请求
        :param url:
        :return:
        """
        sem = asyncio.Semaphore(1024)
        try:
            auth = aiohttp.BasicAuth(self.uid, self.secret)
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), headers=self.headers, auth=auth) as session:
                async with sem:
                    async with session.get(url, timeout=20, headers=self.headers) as req:
                        await asyncio.sleep(1)
                        response = await req.text('utf-8', 'ignore')
                        req.close()
                        return response
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            self.logger.error('[-]Resolve {} fail'.format(url))
            return False

    def buildHeader(self):
        userAgent = self.fetchUserAgent()
        # self.headers['User-Agent'] = userAgent

def main():
    censysObject = CensysObject()

    tasks = []
    newLoop = asyncio.new_event_loop()
    asyncio.set_event_loop(newLoop)
    loop = asyncio.get_event_loop()

    tasks.append(asyncio.ensure_future(censysObject.getIP("jianshu.com")))

    loop.run_until_complete(asyncio.wait(tasks))

if __name__ == '__main__':
    main()