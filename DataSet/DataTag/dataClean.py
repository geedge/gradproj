
import sys
import traceback

filenameList = [
    #"http.log.test",
    "./log/2019-12-06/http.log.2019-12-06-0",
    "./log/2019-12-06/http2.log.2019-12-06-0",
]

outputFile = "./result.txt"
appDict = {
    "wechat" : ["wechat", "MicroMessenger Client", "MicroMessenger"],
    "qq" : ["qq", "TencentMidasConnect"],
    "douyin" : ["Aweme", "ttplayer"],
    "taobao" : ["%E6%89%8B%E6%9C%BA%E6%B7%98%E5%AE%9D", "TBIOS", "MTOPSDK", "AliApp(TB"],
    "kuaishou" : ["kwai", "%E5%BF%AB%E6%89%8B"],
    "weibo" : ["weibo", "微博", "afma-sdk-onShow-v"],
    "toutiao" : ["News", "今日头条"],
    "iqiyi" : ["QIYIVideo", "iQiYi", "HCDNClient_IOS"],
    "tencentVideo" : ["live4iphone%20rel", "VBBaseCore"],
    "baidu" : ["Baidu", "%E7%99%BE%E5%BA%A6"],
    "pinduoduo" : ["pinduoduo", "phh_ios_version"],
    "jd" : ["jdapp", "%E4%BA%AC%E4%B8%9C", "JD4iPhone"],
    "huya" : ["kiwi"],
    "youku" : ["Youku", "%E4%BC%98%E9%85%B7", "AliXAdSDK"],
    "qqMusic" : ["QQ%E9%9F%B3%E4%B9%90"],
    "didi" : ["OneTravel", "Omega", "FusionKit"],
    "lianjia" : ["LianJia", "HomeLink"],
    "hupu" : ["hupu", "prokanqiu", "虎扑"],
    "gaode" : ["AMap", "%E9%AB%98%E5%BE%B7%E5%9C%B0%E5%9B%BE"],
    "neteaseNews" : ["NewsApp", "%E7%BD%91%E6%98%93%E6%96%B0%E9%97%BB"],
    "chrome" : ["CriOS"],
    "safari" : ["Version/12.1.2", "MobileSafari"],
    "firefox" : ["FxiOS"],
}


def getAppName(ua):
    for name, ids  in appDict.items():
        for id in ids:
            if id.lower() in ua.lower():
                return name

filterHostList = {
    "apple.com",
    "itunes.com",
    "icloud.com",
    "apple-finance",
    "AppleStocks",
    "douyu",
    "amap.com",
    "snssdk.com",
    "toutiao.com",
    "amemv.com",
    "facebook.com",
    "fb",
    "youtu",
    "tmall.com",
    "app.adjust.com",
    "dig.bdurl.net",
    "weixin110.qq.com",
    "captcha.gtimg.com",
    "weixin.qq.com",
    "googleapis.com",
    "baidu.com",
    "bdstatic.com",
    "app-measurement.com",
}

filterUaList = {
    "AppleStocks",
    "DYZB",
    "swcd",
    "null",
    "SafariSafeBrowsing",
}

def handleUnknownApp(host, stream, ua):
    if ua == "":
        return 
    for filterHost in filterHostList:
        if filterHost in host:
            return 
    for filterUa in filterUaList:
        if filterUa in ua:
            return
    print(stream + ",  " + host + ",  " + ua)

def main():
    stm2app_dict = dict()
    with open(outputFile, "w+") as f1:
        for filename in filenameList:
            with open(filename) as f:
                logs = f.readlines()
                for log in logs:
                    try:
                        li = log.split(',')
                        stream = li[3]
                        host = li[4]
                        if(stream.split(' ')[4] != '443'):
                            continue
                        ua = ""
                        for index in range(5, len(li), 1):
                            ua += li[index]
                        host = host.strip()
                        stream = stream.strip()
                        ua = ua.strip()
                        appName = getAppName(ua)
                        if appName != None:
                                stm2app_dict[stream] = appName
                        else:
                            handleUnknownApp(host, stream, ua)
                    except:
                        print("log: " + log)
                        traceback.print_exc()
        for stream, app in stm2app_dict.items():
            f1.write(stream + ":    " + app + "\n")

if __name__ == '__main__':
    main()