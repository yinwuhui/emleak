import plotly.express as px

# 构建数据
import csv

data = []
with open('mleaksummary.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        stackname, total, times = row
        total = int(total)
        times = int(times)
        data.append({"stackname": stackname, "total": total, "times": times})


# 使用Plotly Express创建柱状图
fig = px.bar(data, x="stackname", y=["total", "times"],
             color_discrete_sequence=["#1f77b4", "#ff7f0e"],
             hover_data=["stackname"],
             labels={"value": "Count", "variable": "Category"})

# 将绘图保存为SVG文件
fig.write_image("summaryout.svg")

