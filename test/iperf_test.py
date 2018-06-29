import subprocess, os, time, datetime, socket
from os.path import expanduser

results_dir_abs_path = expanduser("~") + "/results"
os.system("mkdir %s" % results_dir_abs_path)
output_file_name = results_dir_abs_path + "/" + "iperf_" + socket.gethostname().replace("-","_") + "_" + datetime.datetime.now().strftime("%m%d%H%M")+".txt"
with open(output_file_name,"w") as f:
    f.writelines("localtime\t  speed\n")
while True:
    p = subprocess.Popen('iperf -c 34.215.137.39 -f kbits -b 1M',stderr=subprocess.PIPE,stdout=subprocess.PIPE, shell=True)
    stdoutdata, stderrdata = p.communicate()
    print stdoutdata
    lines = stdoutdata.split('\n')
    for line in lines:
        check_str = line[39:48]
        if check_str == 'Kbits/sec':
            speed = float(line[32:39])
            localtime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
            with open(output_file_name,"a") as f:
                f.writelines(localtime + "\t  %10.1fk/s \n" %(speed))
                print(localtime + "\t  %10.1fk/s \n" %(speed))
    time.sleep(10)

