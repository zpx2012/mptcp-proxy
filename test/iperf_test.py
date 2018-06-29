import subprocess, os, time, datetime, socket
from os.path import expanduser

results_dir_abs_path = expanduser("~") + "/results"
os.system("mkdir %s" % results_dir_abs_path)
output_file_name = results_dir_abs_path + "/" + "iperf_" + socket.gethostname().replace("-","_") + "_" + datetime.datetime.now().strftime("%m%d%H%M")+".txt"
with open(output_file_name,"w") as f:
    f.writelines("localtime\t  speed\n")
while True:
    p = subprocess.Popen('iperf -c 54.191.68.140 -f kbits -b 1M',stderr=subprocess.PIPE,stdout=subprocess.PIPE, shell=True)
    stdoutdata, stderrdata = p.communicate()
    print stdoutdata
    lines = stdoutdata.split('\n')
    rlt_line = lines[len(lines)-2]
    check_str = rlt_line[39:48]
    if check_str == 'Kbits/sec':
        speed = float(rlt_line[32:39])
        localtime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        with open(output_file_name,"a") as f:
            f.writelines(localtime + "\t  %10.1fk/s \n" %(speed))
    else:
        print('read rlt_line error')
        print stdoutdata
    time.sleep(10)

