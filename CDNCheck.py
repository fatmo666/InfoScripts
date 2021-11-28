import asyncio
import json
import os
import re
import socket
from asyncio import CancelledError

import aiohttp
import dns.resolver
import geoip2.database
import ipaddress

from BaseObject import BaseObject
from Config.CDN.ASNs import ASNS
from Config.CDN.cnames import cnames
from Config.CDN.segments import segments
from Config.CDN.headers import headers

class CdnInfo(BaseObject):

    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}

        self.isCDN = []
        self.isNotCDN = []

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

                tasks.append(asyncio.ensure_future(self.checkCDN(domain)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[+]Break From Queue.')
        except CancelledError:
            pass

        self.writeResult()


    async def checkCDN(self, domain):
        self.queryResult[domain] = {}
        self.queryResult[domain]['isCdn'] = "0"
        isCDNByAddr = 0

        #尝试获取IP地址
        if not re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            isCDNByAddr, ip = await self.getIP(domain)
        else:
            ip = domain
        if ip is None:
            return

        if isCDNByAddr != 0:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['ipAddr'] = isCDNByAddr


        cdnSegment, segment = self.checkSegment(ip)
        if cdnSegment:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['segment'] = segment

        cdnASN = self.checkASN(ip)
        if cdnASN:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['ASN'] = cdnASN

        cdnHeader, header = await self.checkHeader('http://' + domain)
        if cdnHeader:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['header'] = header

        if not re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            cnameList = await self.getCNAMES(domain)
            match = False
            result = None
            for i in cnameList:
                match, result = self.matched(i, cnames)
                if match == True:
                    break
            if match == True:
                self.queryResult[domain]['isCdn'] = "1"
                self.queryResult[domain]['cname'] = result

        if self.queryResult[domain]['isCdn'] == '1':
            self.isCDN.append(domain)
        else:
            self.isNotCDN.append(domain)


    def writeResult(self):
        """
        保存结果
        :return:
        """
        with open('./CheckResult/' + self.fileName + "/" + 'isCDN' + '.txt', 'a') as fpIs:
            with open('./CheckResult/' + self.fileName + "/" + 'isNotCDN' + '.txt', 'a') as fpIsNot:
                for domain in self.domains:
                    if self.queryResult[domain]['isCdn'] == '1':
                        fpIs.write(domain + "\n")
                    else:
                        fpIsNot.write(domain + "\n")

                    with open('./result/' + domain + "/" + 'cdnInfo' + '.json', 'w') as fpResult:
                        json.dump(self.queryResult[domain], fpResult, indent=2)


    async def getIP(self, domain):
        """
        尝试获得域名的IP地址
        :param domain:
        :return:
        """
        try:
            await asyncio.sleep(1)
            addr = socket.getaddrinfo(domain, None)
            if len(addr) > 1:
                return len(addr), str(addr[0][4][0])
            else:
                return 0, str(addr[0][4][0])
        except:
            return 0, None

    def checkSegment(self, ip):
        try:
            for segment in segments:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(segment):
                    return True, segment
            return False, None
        except:
            return False, None

    def checkASN(self, ip):
        try:
            with geoip2.database.Reader('./Config/GeoLite2-ASN.mmdb') as reader:
                response = reader.asn(ip)
                for i in ASNS:
                    if response.autonomous_system_number == int(i):
                        return True
        except:
            return False
        return False

    async def checkHeader(self, domain):
        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                async with sem:
                    async with session.get(domain, timeout=20, headers=self.headers) as req:
                        await asyncio.sleep(1)
                        for header in headers:
                            if header in dict(req.headers).keys():
                                return True, header
                        req.close()
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            self.logger.error('[-]CDNCheck-Check header: Resolve {} fail'.format(domain))

        return False, ""

    async def getCNAMES(self, domain):
        cnames = []
        cname = self.getCNAME(domain)
        if cname is not None:
            cnames.append(cname)
        while (cname != None):
            cname = self.getCNAME(cname)
            if cname is not None:
                cnames.append(cname)
        return cnames

    def getCNAME(self, domain):
        try:
            # # 需要在域名前添加‘www.’
            # if domain.startswith('www.'):
            #     pass
            # else:
            #     domain = 'www.' + domain
            answer = dns.resolver.resolve(domain, 'CNAME')
        except:
            return None
        cname = [_.to_text() for _ in answer][0]
        return cname

    def matched(self, obj, list):
        # print(obj)
        for i in list:
            if i in obj:
                return True, list[i]
        return False, None


if __name__ == '__main__':
    cdnInfo = CdnInfo()
    cdnInfo.startQuery()

