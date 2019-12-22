




import sys
import traceback



filename = "./log/2019-12-20_21/http2.log.2019-12-21"


with open(filename) as f:
    lines = f.readlines()
    print(len(lines))