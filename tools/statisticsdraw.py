import csv
import datetime
import pygal
import os

# 预处理
with open('mleakstatics.csv', 'r') as f:
    lines = f.readlines()

last_line = lines.pop()  # 移除最后一行
lines.insert(0, last_line)  # 插入到第一行

with open('tmp_mleakstatics.csv', 'w') as f:
    f.writelines(lines)

# 创建一个空列表来存储第一列的值
timestamps = []
with open('tmp_mleakstatics.csv', newline='') as csvfile:
    # 创建 CSV 文件读取器
    reader = csv.reader(csvfile)
    # 跳过第一行
    next(reader)
    # 遍历每一行并将第一列（除第一个元素之外的所有元素）添加到列表中
    for row in reader:
        timestamps.append(row[0])

# 读取csv文件并将数据存入列表
with open('tmp_mleakstatics.csv') as f:
    reader = csv.reader(f)
    headers = next(reader)
    data = [[] for i in range(len(headers)-1)]
    for row in reader:
        for i in range(1, len(row)):
            data[i-1].append(int(row[i]) if row[i] != '' else 0)

# 将第一列的时间戳转换成datetime类型的值
x_labels = []
for timestamp in map(int, timestamps):
    dt = datetime.datetime.fromtimestamp(timestamp)
    x_labels.append(dt.strftime('%Y-%m-%d %H:%M:%S'))

# 创建折线图对象
chart = pygal.Line(x_label_rotation=1024)
chart.title = 'Memory Statics'

# 添加数据
for i in range(1, len(headers)):
    chart.add(headers[i], data[i-1])

# 设置x轴标签
chart.x_labels = x_labels

# 输出svg格式的图表
chart.render_to_file('mleakstatics.svg')

os.remove("tmp_mleakstatics.csv")

