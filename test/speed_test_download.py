import io,pycurl,sys,os,time,datetime,traceback,socket
from os.path import expanduser

download_last = 0
last_time = int(round(time.time()))
output_file_name = ""
results_dir_abs_path = expanduser("~") + "results"

def call_back(download_t, download_d, upload_t, upload_d):
    global last_time
    global download_last
    new_time = int(round(time.time()))
    interval = new_time - last_time
    if(interval > 10):
        speed = ((download_d-download_last)/interval)
        last_time = new_time          #update
        download_last = download_d
        localtime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        with open(output_file_name,"a") as f:
            f.writelines(localtime + "\t  %10.3fk/s \n" %(speed/1024)) 

def pycurl_socks(test_url):
    c = pycurl.Curl()
    c.setopt(pycurl.PROXY,'socks5h://127.0.0.1')
    c.setopt(pycurl.PROXYPORT,1080)
    c.setopt(pycurl.PROXYTYPE,pycurl.PROXYTYPE_SOCKS5)
    c.setopt(pycurl.URL,test_url)
    pycurl_perform_and_log(c,"socks")

def pycurl_regular(test_url):
    c = pycurl.Curl()
    c.setopt(pycurl.URL,test_url)
    pycurl_perform_and_log(c,"regular")

def pycurl_perform_and_log(c, type_str):
        with open('/dev/null','wb') as test_f:
            global output_file_name
            start = datetime.datetime.now()
            sys_hostname = socket.gethostname()
            output_file_name = results_dir_abs_path + "/" + type_str + "_" + sys_hostname + "_" + start.strftime("%m%d%H")+".txt"
            with open(output_file_name,"w") as f:
                f.writelines("localtime\t  speed\n")
            try:
                c.setopt(pycurl.WRITEDATA,test_f)
                c.setopt(pycurl.ENCODING,'gzip')
                c.setopt(pycurl.NOPROGRESS,False)
                c.setopt(pycurl.XFERINFOFUNCTION,call_back)
                c.setopt(pycurl.MAXREDIRS,5)
                c.perform()
            except :
                print ('\n########## connection failed ##########\n')
                print 'traceback.format_exc():\n%s' %traceback.format_exc()
                print ('#######################################\n')
            else:
                speed = c.getinfo(pycurl.SPEED_DOWNLOAD)
                total_time = c.getinfo(pycurl.TOTAL_TIME)
                now = datetime.datetime.now()
                localtime = now.strftime("%Y-%m-%d %H:%M:%S")

                print ('speed ave : %10.3f k/s' %(speed/1024))
                print ('total time: %10.3f s' %(total_time))
                print ('localtime : ' + localtime)
                with open(output_file_name,"a") as f:
                    f.writelines(localtime + "\t  %10.3fk/s  %10.3fs Download Finished\n" %(speed/1024,total_time)) # speed(k/s) \t total_time(s)
                c.close()

if __name__ == '__main__':
    num_tasks = 1
    if len(sys.argv) != 2:
        print("Usage: %s <op>\n\t op: 0 for regular, 1 for socks" % sys.argv[0])
        sys.exit(-1)
    option = sys.argv[1]   #0->vpn 1->socks
    os.system("mkdir %s" % results_dir_abs_path)
    test_url = "http://mirror.enzu.com/ubuntu-releases/ubuntu-core/16/ubuntu-core-16-pi2.img.xz"
    while True:
        print ('Task : %d' %(num_tasks))
        last_time = int(round(time.time()))
        download_last = 0
        num_tasks = num_tasks +1
        if(option == '0'):
            print "Using regular now"
            pycurl_regular(test_url)
        else:
            print "Using Socks now"
            pycurl_socks(test_url)
        time.sleep(10)
    
    
