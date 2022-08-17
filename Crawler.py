import asyncio
import json
import os
import re
import threading
from asyncio import CancelledError
from html import unescape
from queue import Queue
from urllib.parse import urlparse
from tldextract import extract

from Config.Crawler.CrawlerConfig import *

from BaseObject import BaseObject

import aiohttp


class CrawlerInfo(BaseObject):
    def __init__(self):
        BaseObject.__init__(self)
        self.domains = []
        self.queryResult = {}

        args = self.argparser()
        # 生成主域名列表，待检测域名入队
        target = args.target
        self.threads = args.threads
        if not os.path.isfile(target):
            # target = 'http://' + target
            self.domains.append(target)
        elif os.path.isfile(target):
            with open(target, 'r+', encoding='utf-8') as f:
                for domain in f:
                    domain = domain.strip()
                    if not domain.startswith(('http://', 'https://')):
                        self.domains.append(domain)

        self.queue = Queue()

        self.leak_infos_match = []
        self.leak_infos = []
        self.extract_urls = []

        self.headers = {}
        self.buildHeader()


        self._value_lock = threading.Lock()

        self.keywords = []
        for domain in self.domains:
            if domain.startswith(('http://', 'https://')):
                domain = domain.replace('http://', '')
                domain = domain.replace('https://', '')

            keyword = extract(domain).domain
            self.keywords.append(keyword)

        self.rootDomains = []
        for domain in self.domains:
            domain = extract(domain).registered_domain
            self.rootDomains.append(domain)

        self.sub_domains = []
        self.apis = []

        self.leak_infos_dict = {
            'mail': [],
            'accesskey_id': [],
            'accesskey_secret': [],
            'access_key': [],
            'google_captcha': [],
            'google_oauth': [],
            'amazon_aws_access_key_id': [],
            'amazon_mws_auth_toke': [],
            'amazon_aws_url': [],
            'amazon_aws_url2': [],
            'facebook_access_token': [],
            'authorization_basic': [],
            'authorization_bearer': [],
            'authorization_api': [],
            'mailgun_api_key': [],
            'twilio_api_key': [],
            'twilio_account_sid': [],
            'twilio_app_sid': [],
            'paypal_braintree_access_token': [],
            'square_oauth_secret': [],
            'square_access_token': [],
            'stripe_standard_api': [],
            'stripe_restricted_api': [],
            'github_access_token': [],
            'rsa_private_key': [],
            'ssh_dsa_private_key': [],
            'ssh_dc_private_key': [],
            'pgp_private_block': [],
            'json_web_token': [],
            'slack_token': [],
            'SSH_privKey': [],
            'possible_Creds': [],
        }

        # 打开文件
        self.fp = open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + '/crawlerLeakInfo.json', 'w')
        self.fpApi = open(os.path.dirname(os.path.abspath(__file__)) + '/CheckResult/' + self.fileName + '/crawlerDomainInfo.txt', 'w')

    def startQuery(self):
        tasks = []
        for domain in self.domains:
            self.queue.put("http://" + domain)

            # tasks.append(asyncio.ensure_future(self.getInfo(domain)))
            # done, pending = await asyncio.wait(tasks)

        # loop = asyncio.get_event_loop()

        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        loop = asyncio.get_event_loop()
        while self.queue.qsize() > 0:
            try:
                while not self.queue.empty():
                    tasks = []
                    i = 0
                    while i < 5 and not self.queue.empty():
                        url = self.queue.get()
                        filename = os.path.basename(url)
                        file_extend = self.get_file_extend(filename)
                        if file_extend == 'js':
                            tasks.append(asyncio.ensure_future(self.FindLinkInJs(url)))
                        else:
                            tasks.append(asyncio.ensure_future(self.FindLinkInPage(url)))
                        i += 1
                    if tasks:
                        loop.run_until_complete(asyncio.wait(tasks))
                        self.wirteResult()
            except KeyboardInterrupt:
                self.wirteResult()
                self.logger.info('[+]Break From Queue.')
                break
            except CancelledError:
                self.wirteResult()
                pass

    def get_file_extend(self, filename):
        return filename.split('/')[-1].split('?')[0].split('.')[-1].lower()

    async def FindLinkInJs(self, url):
        resp = await self.send_request(url)
        if not resp:
            return False
        if black_keyword_list:
            for black_keyword in black_keyword_list:
                if black_keyword in resp:
                    return False
        self.find_leak_info(url, resp)
        try:
            link_finder_matchs = re.finditer(link_pattern, str(resp))
        except:
            return None
        for match in link_finder_matchs:
            match = match.group().strip('"').strip("'")
            full_api_url = self.extract_link(urlparse(url), match)
            if full_api_url is False:
                continue

    async def FindLinkInPage(self, url):
        try:
            resp = await self.send_request(url)
        except ConnectionResetError:
            return None
        if not resp:
            return None

        # if black_keyword_list:
        #     for black_keyword in black_keyword_list:
        #         if black_keyword in resp:
        #             return False

        self.find_leak_info(url, resp)

        try:
            hrefs = re.findall(href_pattern, resp)
        except TypeError:
            hrefs = []
        try:
            js_urls = re.findall(js_pattern, resp)
        except TypeError:
            js_urls = []
        try:
            js_texts = re.findall('<script>(.*?)</script>', resp)
        except TypeError:
            js_texts = []

        parse_url = urlparse(url)

        parse_url = urlparse(url)
        for href in hrefs:
            full_href_url = self.extract_link(parse_url, href)
            if full_href_url is False:
                continue
        for js_url in js_urls:
            full_js_url = self.extract_link(parse_url, js_url)
            if full_js_url is False:
                continue
        for js_text in js_texts:
            self.FindLinkInJsText(url, js_text)

    def FindLinkInJsText(self, url, text):
        try:
            link_finder_matchs = re.finditer(self.link_pattern, str(text))
        except:
            return None
        self.find_leak_info(url, text)
        for match in link_finder_matchs:
            match = match.group().strip('"').strip("'")
            full_api_url = self.extract_link(urlparse(url), match)
            if full_api_url is False:
                continue


    def find_leak_info(self, url, text):
        for k in leak_info_patterns.keys():
            pattern = leak_info_patterns[k]
            if k == 'mail':
                for netloc in self.rootDomains:
                    mail_pattern = '([-_a-zA-Z0-9\.]{1,64}@%s)' % netloc
                    self.process_pattern(k, mail_pattern, text, url)
            else:
                self.process_pattern(k, pattern, text, url)

    def process_pattern(self, key, pattern, text, url):
        try:
            self._value_lock.acquire()
            matchs = re.findall(pattern, text, re.IGNORECASE)
            for match in matchs:
                match_tuple = (key, match, url)
                if match not in self.leak_infos_match:
                    self.leak_infos.append(match_tuple)
                    self.leak_infos_match.append(match)
                    self.leak_infos_dict[key].append(match)
                    self.logger.info("[+] Find info: " + match + " !")
        except Exception as e:
            self.logger.warning(e)
        finally:
            self._value_lock.release()

    async def send_request(self, url):
        sem = asyncio.Semaphore(self.threads)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
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
            # self.logger.error('[-]Resolve {} fail'.format(url))
            return False

    def extract_link(self, parse_url, link):
        link = unescape(link)

        filename = os.path.basename(link)
        file_extend = self.get_file_extend(filename)
        is_link = False
        if link.startswith(('http://', 'https://')) and file_extend not in black_keyword_list:
            full_url = link
        elif link.startswith('javascript:'):
            return False
        elif link.startswith('////') and len(link) > 4:
            full_url = 'http://' + link[2:]
        elif link.startswith('//') and len(link) > 2:
            full_url = 'http:' + link
        elif link.startswith('/'):
            full_url = parse_url.scheme + '://' + parse_url.netloc + link
        elif link.startswith('./'):
            full_url = parse_url.scheme + '://' + parse_url.netloc + parse_url.path + link[1:]
        else:
            full_url = parse_url.scheme + '://' + parse_url.netloc + parse_url.path + '/' + link

        extract_full_url_domain = extract(full_url)
        root_domain = extract_full_url_domain.domain + '.' + extract_full_url_domain.suffix
        sub_domain = urlparse(full_url).netloc

        in_keyword = False
        for keyword in self.keywords:
            if keyword in root_domain:
                in_keyword = True
        if not in_keyword:
            return False

        try:
            self._value_lock.acquire()
            if root_domain not in self.rootDomains:
                self.rootDomains.append(root_domain)
                # self.logger.info('[+]Find a new root domain ==> {}'.format(root_domain))
                if root_domain not in self.extract_urls:
                    self.extract_urls.append(root_domain)
                    self.queue.put('http://' + root_domain)
        finally:
            self._value_lock.release()

        try:
            self._value_lock.acquire()
            if sub_domain not in self.sub_domains and sub_domain != root_domain:
                self.sub_domains.append(sub_domain)
                # self.logger.info('[+]Find a new subdomain ==> {}'.format(sub_domain))
                if sub_domain not in self.extract_urls:
                    self.extract_urls.append(sub_domain)
                    self.queue.put('http://' + sub_domain)
        finally:
            self._value_lock.release()
        if file_extend in file_extend_list:
            return False
        if is_link is True:
            return link
        try:
            self._value_lock.acquire()
            if full_url not in self.apis and file_extend != 'html' and file_extend != 'js':
                self.apis.append(full_url)
                # logger.info('[+]Find a new api in {}'.format(parse_url.netloc))
        finally:
            self._value_lock.release()

        format_url = self.get_format_url(urlparse(full_url), filename, file_extend)

        try:
            self._value_lock.acquire()
            if format_url not in self.extract_urls:
                self.extract_urls.append(format_url)
                self.queue.put(full_url)
        finally:
            self._value_lock.release()

    def get_format_url(self, parse_link, filename, file_extend):
        if '-' in filename:
            split_filename = filename.split('-')
        elif '_' in filename:
            split_filename = filename.split('_')
        else:
            split_filename = filename.split('-')

        format_filename = ''
        for split_name in split_filename:
            try:
                load_json = json.loads(split_name)
                if isinstance(load_json, int) or isinstance(load_json, float):
                    format_filename += '-int'
            except:
                format_filename += split_name
        return parse_link.scheme + '://' + parse_link.netloc + parse_link.path.replace(filename, format_filename)


    def wirteResult(self):
        try:
            json.dump(self.leak_infos_dict, self.fp, indent=2)
            # fp.write(str(self.queryResult))
        except:
            self.logger.error("[-] write" + ' crawlerLeakInfo fail')

        try:
            for item in self.apis:
                self.fpApi.write(item + '\n')
        except:
            self.logger.error("[-] write" + ' crawlerDomainInfo fail')


if __name__ == '__main__':
    cdninfo = CrawlerInfo()
    cdninfo.startQuery()
    # print(cdninfo.leak_infos)