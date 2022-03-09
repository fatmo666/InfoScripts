import asyncio, aiohttp
import datetime
import logging
import os
import random
import sys
import time
from asyncio import CancelledError
from logging.handlers import RotatingFileHandler

import argparse


class BaseObject(object):

    def __init__(self):
        self.fileName = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())

        # 初始化文件夹
        self.initDir()

        #初始化日志
        self.initLog()

        #User-Agent文件路径
        self.userAgentFile = os.path.dirname(os.path.abspath(__file__)) + "/Config/HttpHeader/user-agents.txt"

        # 设置HTTP请求头
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/79.0.3945.130 Safari/537.36'
        }

    def initLog(self):
        """
        日志配置,同时输出在日志文件和屏幕上
        :return:
        """
        self.logger = logging.Logger('log')
        self.logger.setLevel(logging.INFO)

        logFileName = os.getcwd() + '/log/' + datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S') + '.txt'
        rHandler = RotatingFileHandler(logFileName, maxBytes=100 * 1024, backupCount=3)
        rHandler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        rHandler.setFormatter(formatter)

        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)

        self.logger.addHandler(rHandler)
        self.logger.addHandler(console)

    def fetchUserAgent(self):
        with open(self.userAgentFile, 'r') as fp:
            userAgent = random.sample(fp.readlines(), 1)[0]

        return userAgent

    def initDir(self):
        """
        文件夹不存在则创建
        :return:
        """
        if os.path.exists(os.getcwd() + '/log/') is False:
            os.mkdir(os.getcwd() + '/log/')
        if os.path.exists(os.getcwd() + '/result/') is False:
            os.mkdir(os.getcwd() + '/result/')
        if os.path.exists(os.getcwd() + '/RunResult/') is False:
            os.mkdir(os.getcwd() + '/RunResult/')
        if os.path.exists(os.getcwd() + '/RunResult/' + self.fileName + '/') is False:
            os.mkdir(os.getcwd() + '/RunResult/' + self.fileName + '/')


    def argparser(self):
        """
        解析参数
        :return:参数解析结果
        """
        parser = argparse.ArgumentParser(description='InfoScripts can help you collect target\'s information',
                                         epilog='\tUsage:\npython3 ' + sys.argv[0] + " --target www.baidu.com")
        parser.add_argument('--target', '-t', help='A target like www.example.com or subdomains.txt', required=True)

        parser.add_argument('--threads', help='Set the concurrent quantity', default=3, required=False, type=int)

        args = parser.parse_args()
        return args

    def buildHeader(self):
        userAgent = self.fetchUserAgent()
        self.headers['User-Agent'] = userAgent

    async def sendRequest(self, url):
        """
        发送http请求
        :param url:
        :return:
        """
        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
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