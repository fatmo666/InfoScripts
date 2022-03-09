import csv

def extractUrlAlive(file, output):
    with open(file) as f:
        with open(output, 'w') as fw:
            f_csv = csv.reader(f)
            for row in f_csv:
                if row[1] == '1':
                    fw.write(row[4] + '\r\n')

if __name__ == '__main__':
    extractUrlAlive('ustc.edu.cn.csv', 'ustc.txt')