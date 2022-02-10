import shodan
from Config.ApiKeys.ApiKey import ShodanKey

class ShodanObject(object):
    def __init__(self):
        self.key = ShodanKey
        self.shodanConnect = shodan.Shodan(self.key)

    def getIcoHashList(self, queryString):
        """
        返回通过icon检索到的ip
        :param queryString:
        :return:
        """
        result = self.shodanConnect.search(query=queryString)
        resultList = []
        for item in result['matches']:
            resultList.append(item['ip_str'])
        return list(set(resultList))

    def getTitleList(self, queryString):
        result = self.shodanConnect.search(query=queryString)
        resultList = []
        for item in result['matches']:
            resultList.append(item['ip_str'])
        return list(set(resultList))

if __name__ == '__main__':
    shodanObject = ShodanObject()
    # print(shodanObject.getIcoHashList('http.favicon.hash:-80899517'))
    print(shodanObject.getTitleList('title:虎牙直播-技术驱动娱乐-弹幕式互动直播平台'))