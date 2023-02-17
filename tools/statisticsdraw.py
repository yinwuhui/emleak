import pygal

# 从文件中读取数据
with open('mleakstatics.txt', 'r') as f:
    lines = f.readlines()

# 将数据按列分割
data = [list(map(int, line.strip().split())) for line in lines]

# 获取横坐标
x_labels = [row[0] for row in data][1:]

# 获取数据列的名称和值
y_labels = {}
for i, row in enumerate(data[0]):
    if i > 0:
        y_labels[row] = [d[i] for d in data[1:]]

# 创建图表对象
chart = pygal.Line()
chart.title = 'memory statics'
chart.x_labels = x_labels

# 添加数据列
for label, values in y_labels.items():
    chart.add(str(label), values)

# 保存图表为SVG格式
chart.render_to_file('mleakstaticsoutput.svg')
