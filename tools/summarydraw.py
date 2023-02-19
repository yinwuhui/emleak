import csv
import pygal

with open('mleaksummary.csv', 'r') as csvfile:
    reader = csv.reader(csvfile)
    data = list(reader)

# 读取数据
labels = [row[0] for row in data]
total = [int(row[1]) for row in data]
times = [int(row[2]) for row in data]

# 创建柱状图
bar_chart = pygal.Bar()
bar_chart.title = 'All stack malloc memry total and times'
bar_chart.x_labels = labels
bar_chart.add('total', total)
bar_chart.add('times', times)

# 输出图表
bar_chart.render_to_file('mleaksummary.svg')

