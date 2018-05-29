import io,pycurl,sys,os,time,datetime,traceback
    
def test_download_socks(test_url,output_file):
    with open('/dev/null','wb') as test_f:
        try:
            c = pycurl.Curl()
            c.setopt(pycurl.WRITEDATA,test_f)
            c.setopt(pycurl.NOPROGRESS,0)
            c.setopt(pycurl.URL,test_url)
            c.setopt(pycurl.PROXY,'socks5h://127.0.0.1')
            c.setopt(pycurl.PROXYPORT,1080)
            c.setopt(pycurl.PROXYTYPE,pycurl.PROXYTYPE_SOCKS5)
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
            with open(output_file,"a") as f:
                f.writelines(localtime + "\t  %10.3f  %10.3f\n" %(speed/1024,total_time)) # \t speed(k/s) \t total_time(ms)
            c.close()

def test_download(test_url,output_file):
        with open('/dev/null','wb') as test_f:
            try:
                c = pycurl.Curl()
                c.setopt(pycurl.WRITEDATA,test_f)
                c.setopt(pycurl.ENCODING,'gzip')
                c.setopt(pycurl.NOPROGRESS,0)
                c.setopt(pycurl.URL,test_url)
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
                with open(output_file,"a") as f:
                    f.writelines(localtime + "\t %10.3f  %10.3f\n" %(speed/1024,total_time)) # speed(k/s) \t total_time(ms)
                c.close()

if __name__ == '__main__':
    num_tasks = 1
    option = sys.argv[1]   #0->vpn 1->socks
    start = datetime.datetime.now()
    test_url = "http://mirror.enzu.com/ubuntu-releases/ubuntu-core/16/ubuntu-core-16-pi2.img.xz"
    if(option == '0'):
        print "Using VPN now"
        file_name = "output_vpn_"+start.strftime("%m%d%H")+".txt"
        with open(file_name,"w") as f:
            f.writelines("\n")
        while True:
            print ('Task : %d' %(num_tasks))
            test_download(test_url,file_name)
            num_tasks = num_tasks +1
            time.sleep(20)
    else:
        print "Using Socks now"
        file_name = "output_ssh_"+start.strftime("%m%d%H")+".txt"
        with open(file_name,"w") as f:
            f.writelines("\n")
        while True:
            print ('Task : %d' %(num_tasks))
            test_download_socks(test_url,file_name)
            num_tasks = num_tasks +1
            time.sleep(20)