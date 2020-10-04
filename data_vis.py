from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap
import dataProcessing
from bokeh.plotting import figure, show, output_file
from bokeh.embed import components
from bokeh.models import DatetimeTickFormatter, Panel, Tabs, ColumnDataSource, HoverTool, FactorRange
from bokeh.palettes import Dark2
from bokeh.plotting import figure
from bokeh.transform import cumsum
import numpy as np
from math import pi
import pandas as pd
from bokeh.palettes import Turbo256
from bokeh.transform import cumsum
import urllib.request, json
from random import randint
from datetime import datetime, timedelta
from bokeh.transform import dodge

app = Flask(__name__)
app.secret_key = "super secret"
bootstrap = Bootstrap(app)


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():

    return render_template('IndiaCases.html')

orders = {'Chicken Burgers': 18,
          'Beef Burgers':15,
          'Fish Burgers':3,
          'Small chips':11,
          'Large Chips':16,
          'Family chicken pack':8,
          'Coke':22,
          'Sprite':19}

food=[]
number = []
for i in orders:
    food.append(i)
    number.append(orders[i])
    print(number)
    print(food)


@app.route('/bar')
def bar():
    if request.method == 'GET':
        plot = figure(plot_height=600, sizing_mode='stretch_width',
                      title="Orders",
                      x_axis_label="Food",
                      y_axis_label="No. of orders",
                      toolbar_location="above",
                      x_range=food
                      )
        plot.vbar(x=food, top=number, width=0.8)
        plot.xaxis.major_label_text_font_size= "15pt"
        plot.xaxis.major_label_text_font_size = "13pt"
        plot.xaxis.major_label_orientation = 1.0
        script, div = components(plot)
    return render_template('bar.html', script=script, div=div)


@app.route('/area')
def area():

    return render_template('area.html')

################################################################################
################################################################################
################################################################################
orders = {'Chicken Burgers': randint(10, 20),
          'Beef Burgers': randint(10, 15),
          'Fish Burgers':randint(1, 5),
          'Small chips':randint(25, 30),
          'Large Chips':randint(15, 20),
          'Family chicken pack':randint(5, 10),
          'Coke':randint(5, 15),
          'Sprite':randint(5, 12)}
print(orders)
date = (datetime.now() + timedelta(days=1)).strftime('%d-%m-%Y')
print(date)

food=[]
number = []
for i in orders:
    food.append(i)
    number.append(orders[i])
    print(number)
    print(food)

def new():
    orders = {'Chicken Burgers': randint(10, 20),
              'Beef Burgers': randint(10, 15),
              'Fish Burgers': randint(1, 5),
              'Small chips': randint(25, 30),
              'Large Chips': randint(15, 20),
              'Family chicken pack': randint(5, 10),
              'Coke': randint(5, 15),
              'Sprite': randint(5, 12)}
    return orders

data = []
date_list = []
cb = []
beef = []
fish = []
small = []
large = []
family =[]
coke = []
sprite = []
current = (datetime.now())
for week in range(4):
    data.append([])
    for day in range(1):
        data[week].append({})
        data[week][day]['date'] = {}
        data[week][day]['orders'] = {}
        x = new()
        current += timedelta(days=7)
        data[week][day]['date'] = current.strftime('%d-%m-%Y')
        date_list.append(data[week][day]['date'])
        for order in x:
            data[week][day]['orders'][order] = x[order]
            cb.append(data[week][day]['orders']['Chicken Burgers'])
            chicken_burgers = [cb[i] for i in range(0,len(cb),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            beef.append(data[week][day]['orders']['Beef Burgers'])
            beef_burgers = [beef[i] for i in range(0,len(beef),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            fish.append(data[week][day]['orders']['Fish Burgers'])
            fish_burgers = [fish[i] for i in range(0,len(fish),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            small.append(data[week][day]['orders']['Small chips'])
            small_chips = [small[i] for i in range(0,len(small),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            large.append(data[week][day]['orders']['Large Chips'])
            large_chips = [large[i] for i in range(0,len(large),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            family.append(data[week][day]['orders']['Family chicken pack'])
            family_chicken_pack = [family[i] for i in range(0,len(family),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            coke.append(data[week][day]['orders']['Coke'])
            cokee = [coke[i] for i in range(0,len(coke),8)]
        for order in x:
            data[week][day]['orders'][order] = x[order]
            sprite.append(data[week][day]['orders']['Sprite'])
            spritee = [sprite[i] for i in range(0,len(sprite),8)]

print(data)
print(date_list)
print(chicken_burgers)
print(beef_burgers)
print(fish_burgers)
print(small_chips)
print(large_chips)
print(family_chicken_pack)
print(cokee)
print(spritee)

week1 = []
add = chicken_burgers[0], beef_burgers[0], fish_burgers[0], small_chips[0], large_chips[0], family_chicken_pack[0], cokee[0], spritee[0]
week1.extend(add)
print(week1)

week2 = []
add2 = chicken_burgers[1], beef_burgers[1], fish_burgers[1], small_chips[1], large_chips[1], family_chicken_pack[1], cokee[1], spritee[1]
week2.extend(add2)
print(week2)

week3 = []
add3 = chicken_burgers[2], beef_burgers[2], fish_burgers[2], small_chips[2], large_chips[2], family_chicken_pack[2], cokee[2], spritee[2]
week3.extend(add3)
print(week3)

week4 = []
add4 = chicken_burgers[3], beef_burgers[3], fish_burgers[3], small_chips[3], large_chips[3], family_chicken_pack[3], cokee[3], spritee[3]
week4.extend(add4)
print(week4)

week1date = date_list[0]

@app.route('/district')
def district():

    return render_template('districts.html')


week1_sum = sum(week1)
print(week1_sum)

week2_sum = sum(week2) + week1_sum
print(week2_sum)

week3_sum = sum(week3) + week2_sum
print(week3_sum)

week4_sum = sum(week4) + week3_sum
print(week4_sum)

total_sums = [week1_sum, week2_sum, week3_sum, week4_sum]
print(total_sums)

print(date_list)

@app.route('/scatter')
def scatter():
    data = {'food': food,
            'week1': week1,
            'week2': week2,
            'week3': week3,
            'week4': week4}

    source = ColumnDataSource(data=data)
    plot = figure(x_range=food, y_range=(0, 35), plot_height=500, plot_width=1000, title="Order Counts by Week",
                  toolbar_location=None, tools="", x_axis_label="Food",
                  y_axis_label="Number of orders")
    plot.vbar(x=dodge('food', -0.15, range=plot.x_range), top='week1', width=0.1, source=source,
              color="#ff8533", legend_label=date_list[0])

    plot.vbar(x=dodge('food', -0.05, range=plot.x_range), top='week2', width=0.1, source=source,
              color="#80dfff", legend_label=date_list[1])

    plot.vbar(x=dodge('food', 0.05, range=plot.x_range), top='week3', width=0.1, source=source,
              color="#6fdc6f", legend_label=date_list[2])

    plot.vbar(x=dodge('food', 0.15, range=plot.x_range), top='week4', width=0.1, source=source,
              color="#ff4d4d", legend_label=date_list[3])

    plot.x_range.range_padding = 0
    plot.xgrid.grid_line_color = None
    plot.xaxis.major_label_text_font_size = "11pt"
    plot.yaxis.major_label_text_font_size = "11pt"
    plot.legend.location = "top_left"
    plot.legend.orientation = "horizontal"
    tab2 = Panel(child = plot, title = "Weekly Orders")
    plot1 = figure(plot_width = 800, title="Total Orders", x_axis_label="Date",
                      y_axis_label="Total Food Orders", plot_height = 600, x_range=date_list, tools="hover")
    plot1.line(x = date_list, y = total_sums, line_width = 4)
    plot1.circle(x = date_list, y = total_sums, fill_color = "white", size = 9)
    plot1.xaxis.major_label_text_font_size = "11pt"
    plot1.yaxis.major_label_text_font_size = "11pt"
    tab1 = Panel(child=plot1, title="Total Orders")
    tabs = Tabs(tabs=[tab1, tab2])
    script, div = components(tabs)
    return render_template('scatter.html', script=script, div=div)


@app.route('/about')
def about():
    return render_template('about.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')

if __name__ == '__main__':
    app.run()

