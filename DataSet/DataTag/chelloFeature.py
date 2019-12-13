

import json
import sys
import traceback

streamTagDict = dict()
appCipherDict = dict()

def streamTagDictBuild():
    filename = "../result/2019-12-06-0/stream_tag.txt"
    with open(filename) as f:
        logs = f.readlines()
        for log in logs:
            log = log.split(":")
            stream = log[0].split(" ")
            streamStr = ""
            for item in stream:
                streamStr += item
                streamStr += ','
            tag = log[1]
            streamTagDict[streamStr] = tag

def appCipherDictBuild():
    filename = "../result/2019-12-06-0/stream_feature.txt"
    tagFailCount = 0
    tagSuccCount = 0
    with open(filename) as f:
        logs = f.readlines()
        for log in logs:
            try:
                log = json.loads(log)
                streamStr = log["sip"] + "," + str(log["sport"]) + ',' + log["dip"] + ',' + str(log["dport"]) + ',' 
                appName = streamTagDict[streamStr]
                cipherSuites = log['tls']['cipher_suites']
                cipherSuitesStr = ""
                for cipherSuite in cipherSuites:
                    cipherSuitesStr += cipherSuite
                if appName not in appCipherDict.keys():
                    appCipherDict[appName] = set()
                appCipherDict[appName].add(cipherSuitesStr)
                tagSuccCount += 1
            except:
                tagFailCount += 1
                #traceback.print_exc()
                continue
    print("tagFailCount = " + str(tagFailCount))
    print("tagSuccCount = " + str(tagSuccCount))

def main():
    streamTagDictBuild()
    appCipherDictBuild()
    for appName, cipherList in appCipherDict.items():
        print(appName)
        print(cipherList)

if __name__ == '__main__':
    main()