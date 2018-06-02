# -*- coding: utf-8 -*-
import time, os, sys
import numpy as np
import matplotlib.pyplot as plt

def parse_file(filename):
    x_list = []
    y_list = []
    last_second_time_int = 0
    with open(filename,'r') as f:
        for line in f:
            if len(line) == 1:
                continue
            speed_f = float(line[23:32])
            time_str = line[:19]
            timeArray = time.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            cur_second_time_int = int(time.mktime(timeArray))
            if last_second_time_int == 0:
                last_second_time_int = cur_second_time_int
            if cur_second_time_int < last_second_time_int:
                print("Error:cur_time_int < last_time_int")
            x_list.append(cur_second_time_int - last_second_time_int)
            y_list.append(speed_f)
    capture = filename.split(".")[0]
    plot_figure(x_list,y_list,capture)

def plot_figure(x, y, capture):
    plt.figure(figsize=(42,24), dpi=190, tight_layout=True) 
    plt.margins(x=0,y=0)
    plt.plot(x,y,linewidth=1)   
    plt.xticks(np.arange(min(x),max(x), 5000))
    plt.yticks(np.arange(0,2700,100))
    plt.tick_params(axis='x', labelsize=18)
    plt.tick_params(axis='y', labelsize=28)
    plt.xlabel("Time(s)", fontsize=34) 
    plt.ylabel("Speed(k/s)",fontsize=34)  
    plt.grid(axis='y')
    plt.title(capture, fontsize=40)
    plt.savefig(capture + ".jpg") 
#    plt.show() 
    
if __name__ == '__main__':
    if os.path.basename(os.getcwd()) != "results":
        print("Not in results directory.")
        sys.exit(0)

    for root, dirs, files in os.walk("."):  
        for filename in files:
            if "output" not in filename or not filename.endswith("txt"):
               print "Wrong file:%s" % filename
               continue
            parse_file(filename)

        