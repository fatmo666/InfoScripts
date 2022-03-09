
def addHttpAndHttps(file, output):
    with open(file) as f:
        with open(output, 'a') as fw:
            for item in f.readlines():
                fw.write('http://' + item)
                fw.write('https://' + item)


if __name__ == '__main__':
    addHttpAndHttps('oldedu.txt', 'httpoldedu.txt')