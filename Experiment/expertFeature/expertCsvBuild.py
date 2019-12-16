import sys
import os
import json
import pandas as pd
import numpy as np

PREFIX_DIR = "/Users/Leo/Documents/github/GradProj/"

def label_dict_build(date):
    example_label_file =  PREFIX_DIR + 'DataSet/result/' + date + '/stream_tag.txt'
    example_label_df = pd.read_table(example_label_file, sep='\s+', header=None)
    example_label_df[3] = 443
    example_label = {tuple(example_label_df.iloc[i,0:4].values):example_label_df.iloc[i,4] for i in example_label_df.index}
    return example_label

app_cert = dict()

def main():
    date = sys.argv[1]
    example_label = label_dict_build(date)
    #print(example_label)
    row_count = 1771
    cloumn_count = 25
    example_json_file = PREFIX_DIR + 'DataSet/result/' + date + '/ssl_stat.txt'
    example_json_f = open(example_json_file, 'r')
    array_shape = (row_count, cloumn_count)
    result_data = np.zeros(array_shape)
    result_label = list()
    i = 0
    for line in example_json_f.readlines():
        example_json = json.loads(line)
        #标签
        try:
            flow_key = (example_json['sip'], example_json['sport'], example_json['dip'], example_json['dport'])
            label = example_label[flow_key]
        except Exception:
            #traceback.print_exc()
            continue
        #专家特征
        result_label.append(label)
        san_count = 0
        if 'san' in example_json.keys():
            san = example_json['san']
            san_count = len(san.split(';'))
        cert_count = example_json['Cert']['cert_count']
        '''
        cert_len_str = ''
        for cert in example_json['Cert']['cert_list']:
            cert_len_str += (str(cert['length']) + ',')
        if label not in app_cert.keys():
            app_cert[label] = set()
        app_cert[label].add(cert_len_str)
        '''
        if label not in app_cert.keys():
            app_cert[label] = set()
        app_cert[label].add(san_count)
        #result_data[i,:] = result
        i += 1
    
    print(i)
    for k, v in app_cert.items():
        print(k)
        print(v)

    '''
    print('row = ' + str(row_count))
    print("result_label = " + str(len(result_label)))
    base_head = ['cert_count', 'cert_len', 'san_len', 's2c_pkts']
    header = base_head
    result_df = pd.DataFrame(result_data, columns=header)
    result_df['label'] = np.array(result_label)
    example_csv_file = PREFIX_DIR + 'Experiment/statFeature/csvFile/' + date + '/examples.csv'
    result_df.to_csv(example_csv_file, index=False)
    '''

if __name__ == '__main__':
    main()