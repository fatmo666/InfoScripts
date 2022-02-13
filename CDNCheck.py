# 参考项目：https://github.com/timwhitez/Frog-checkCDN
import asyncio
import json
import os
import re
import socket
from asyncio import CancelledError

import aiohttp, aiodns
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
            resolver = aiodns.DNSResolver(loop=loop)

            for domain in self.domains:
                if os.path.exists(os.getcwd() + '/result/' + domain + '/') is False:
                    os.mkdir(os.getcwd() + '/result/' + domain + '/')

                tasks.append(asyncio.ensure_future(self.checkCDN(domain, resolver)))

            loop.run_until_complete(asyncio.wait(tasks))
        except KeyboardInterrupt:
            self.logger.info('[-]用户手动终止程序.')
        except CancelledError:
            pass

        self.writeResult()


    async def checkCDN(self, domain, resolver):
        self.queryResult[domain] = {}
        self.queryResult[domain]['isCdn'] = "0"
        isCDNByAddr = 0

        #尝试获取IP地址
        if not re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            isCDNByAddr, ipList = await self.getIP(domain, resolver)
        else:
            ipList = list(domain)
        if ipList is None:
            return

        if isCDNByAddr != 0:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['ipAddr'] = isCDNByAddr


        cdnSegment, segment = self.checkSegment(ipList)
        if cdnSegment:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['segment'] = segment

        cdnASN = self.checkASN(ipList)
        if cdnASN:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['ASN'] = cdnASN

        cdnHeader, header = await self.checkHeader('http://' + domain)
        if cdnHeader:
            self.queryResult[domain]['isCdn'] = "1"
            self.queryResult[domain]['header'] = header

        if not re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            cnameList = await self.getCNAMES(domain, resolver)
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
        with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'isCDN' + '.txt', 'a') as fpIs:
            with open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + "/" + 'isNotCDN' + '.txt', 'a') as fpIsNot:
                for domain in self.domains:
                    if self.queryResult[domain]['isCdn'] == '1':
                        fpIs.write(domain + "\n")
                    else:
                        fpIsNot.write(domain + "\n")

                    with open(os.path.dirname(os.path.abspath(__file__)) + '/result/' + domain + "/" + 'cdnInfo' + '.json', 'w') as fpResult:
                        json.dump(self.queryResult[domain], fpResult, indent=2)


    async def getIP(self, domain, resolver):
        """
        尝试获得域名的IP地址
        :param domain:
        :return:
        """

        try:
            answer = await resolver.query(domain, 'A')
            ipList = []
            for ip in answer:
                ipList.append(ip.host)
            if len(answer) > 1:
                return len(answer), ipList
            else:
                return 0, ipList
        except Exception as e:
            # self.logger.error('[-]CDNCheck-Check getIP: {} DNS A解析失败:{}'.format(domain, str(e)))
            return 0, None

        # try:
        #     # await asyncio.sleep(1)
        #     addr = socket.getaddrinfo(domain, None)
        #     if len(addr) > 1:
        #         return len(addr), str(addr[0][4][0])
        #     else:
        #         return 0, str(addr[0][4][0])
        # except:
        #     return 0, None

    def checkSegment(self, ipList):
        """
        根据Segment判断CDN
        :param ipList:
        :return:
        """
        try:
            for ip in ipList:
                for segment in segments:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(segment):
                        return True, segment
            return False, None
        except:
            return False, None

    def checkASN(self, ipList):
        """
        根据ASN判断
        :param ipList:
        :return:
        """
        for ip in ipList:
            try:
                with geoip2.database.Reader('./Config/CDN/GeoLite2-ASN.mmdb') as reader:
                    response = reader.asn(ip)
                    for i in ASNS:
                        if response.autonomous_system_number == int(i):
                            return True
            except Exception as e:
                self.logger.error('[-]CDNCheck-Check checkASN: {} checkASN失败:{}'.format(ip, str(e)))

        return False

    async def checkHeader(self, domain):
        """
        检查HTTP请求头
        :param domain:需请求的域名
        :return:共两个返回值:
        1. 检查结果,True/False
        2. 若为True，命中的那个key
        """
        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                async with sem:
                    async with session.get(domain, timeout=20, headers=self.headers) as req:
                        await asyncio.sleep(1)
                        # 遍历字典
                        for header in headers:
                            if header in dict(req.headers).keys():
                                return True, header
                        req.close()
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            self.logger.info('[-]CDNCheck-Check header: {} http请求失败'.format(domain))

        return False, ""

    async def getCNAMES(self, domain, resolver):
        """
        根据DNS，CNAME解析结果判断，循环解析cname并推入列表
        :param domain:须解析的域名
        :param resolver:异步DNS解析对象
        :return:解析出的别名列表
        """
        cnames = []
        cname = await self.getCNAME(domain, resolver)
        if cname is not None:
            cnames.append(cname)
        while (cname != None):
            cname = await self.getCNAME(cname, resolver)
            if cname is not None:
                cnames.append(cname)
        return cnames

    async def getCNAME(self, domain, resolver):
        """
        异步cname解析
        :param domain:要解析的域名
        :param resolver:异步DNS解析对象
        :return:解析结果
        """
        try:
            # # 需要在域名前添加‘www.’
            # if domain.startswith('www.'):
            #     pass
            # else:
            #     domain = 'www.' + domain
            # answer = dns.resolver.resolve(domain, 'CNAME')
            answer = await resolver.query(domain, 'CNAME')
        except:
            return None
        # cname = [_.to_text() for _ in answer][0]
        cname = answer.cname
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

