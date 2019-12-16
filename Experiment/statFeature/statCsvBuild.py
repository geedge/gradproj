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

def main():
    date = sys.argv[1]
    example_label = label_dict_build(date)
    row_count = 1771
    cloumn_count = 25
    example_json_file = PREFIX_DIR + 'DataSet/result/' + date + '/stream_feature.txt'
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
            result_label.append(example_label[flow_key])
        except Exception:
            continue
        #统计特征
        packets = example_json['packets']
        c2s_packets_bytes = list()
        s2c_packets_bytes = list()
        c2s_packets_intervals = list()
        s2c_packets_intervals = list()
        for packet in packets:
            if packet['dir'] == 1:
                c2s_packets_bytes.append(packet['bytes'])
                c2s_packets_intervals.append(packet['interval'])
            elif packet['dir'] == 2:
                s2c_packets_bytes.append(packet['bytes'])
                s2c_packets_intervals.append(packet['interval'])
        c2s_bytes = example_json['c2s_bytes']
        s2c_bytes = example_json['s2c_bytes']
        c2s_pkts = example_json['c2s_pkts']
        s2c_pkts = example_json['s2c_pkts']
        duration = example_json['duration']
        c2s_packets_bytes_mean = 0
        c2s_packets_bytes_median = 0
        c2s_packets_bytes_std = 0
        c2s_packets_bytes_max = 0
        c2s_packets_bytes_min = 0

        c2s_packets_intervals_mean = 0
        c2s_packets_intervals_median = 0
        c2s_packets_intervals_std = 0
        c2s_packets_intervals_max = 0
        c2s_packets_intervals_min = 0

        s2c_packets_bytes_mean = 0
        s2c_packets_bytes_median = 0
        s2c_packets_bytes_std = 0
        s2c_packets_bytes_max = 0
        s2c_packets_bytes_min = 0

        s2c_packets_intervals_mean = 0
        s2c_packets_intervals_median = 0
        s2c_packets_intervals_std = 0
        s2c_packets_intervals_max = 0
        s2c_packets_intervals_min = 0
        
        if c2s_bytes > 0:
            c2s_packets_bytes_mean = np.mean(c2s_packets_bytes)
            c2s_packets_bytes_median = np.median(c2s_packets_bytes)
            c2s_packets_bytes_std = np.std(c2s_packets_bytes)
            c2s_packets_bytes_max = np.max(c2s_packets_bytes)
            c2s_packets_bytes_min = np.min(c2s_packets_bytes)

            c2s_packets_intervals_mean = np.mean(c2s_packets_intervals)
            c2s_packets_intervals_median = np.median(c2s_packets_intervals)
            c2s_packets_intervals_std = np.std(c2s_packets_intervals)
            c2s_packets_intervals_max = np.max(c2s_packets_intervals)
            c2s_packets_intervals_min = np.min(c2s_packets_intervals)
        
        if s2c_bytes > 0:
            s2c_packets_bytes_mean = np.mean(s2c_packets_bytes)
            s2c_packets_bytes_median = np.median(s2c_packets_bytes)
            s2c_packets_bytes_std = np.std(s2c_packets_bytes)
            s2c_packets_bytes_max = np.max(s2c_packets_bytes)
            s2c_packets_bytes_min = np.min(s2c_packets_bytes)

            s2c_packets_intervals_mean = np.mean(s2c_packets_intervals)
            s2c_packets_intervals_median = np.median(s2c_packets_intervals)
            s2c_packets_intervals_std = np.std(s2c_packets_intervals)
            s2c_packets_intervals_max = np.max(s2c_packets_intervals)
            s2c_packets_intervals_min = np.min(s2c_packets_intervals)
        result = [c2s_bytes, c2s_pkts, s2c_bytes, s2c_pkts, duration, c2s_packets_bytes_mean, c2s_packets_bytes_median, c2s_packets_bytes_std,\
                c2s_packets_bytes_max, c2s_packets_bytes_min, c2s_packets_intervals_mean, c2s_packets_intervals_median, c2s_packets_intervals_std,\
                c2s_packets_intervals_max, c2s_packets_intervals_min, s2c_packets_bytes_mean, s2c_packets_bytes_median, s2c_packets_bytes_std,\
                s2c_packets_bytes_max, s2c_packets_bytes_min, s2c_packets_intervals_mean, s2c_packets_intervals_median, s2c_packets_intervals_std,\
                s2c_packets_intervals_max, s2c_packets_intervals_min]
        result_data[i,:] = result
        i += 1
    print('row = ' + str(row_count))
    print("result_label = " + str(len(result_label)))
    base_head = ['c2s_bytes', 'c2s_pkts', 's2c_bytes', 's2c_pkts', 'duration', 'c2s_packets_bytes_mean', 'c2s_packets_bytes_median', 'c2s_packets_bytes_std',\
                'c2s_packets_bytes_max', 'c2s_packets_bytes_min', 'c2s_packets_intervals_mean', 'c2s_packets_intervals_median', 'c2s_packets_intervals_std',\
                'c2s_packets_intervals_max', 'c2s_packets_intervals_min', 's2c_packets_bytes_mean', 's2c_packets_bytes_median', 's2c_packets_bytes_std',\
                's2c_packets_bytes_max', 's2c_packets_bytes_min', 's2c_packets_intervals_mean', 's2c_packets_intervals_median', 's2c_packets_intervals_std',\
                's2c_packets_intervals_max', 's2c_packets_intervals_min']
    header = base_head
    result_df = pd.DataFrame(result_data, columns=header)
    result_df['label'] = np.array(result_label)
    example_csv_file = PREFIX_DIR + 'Experiment/statFeature/csvFile/' + date + '/examples.csv'
    result_df.to_csv(example_csv_file, index=False)


if __name__ == '__main__':
    main()