import io,pycurl,sys,os,time,datetime,traceback,random


targets = [
    'http://www.berkeley.edu',
    'http://www.stanford.edu',
    'http://www.harvard.edu',
    'http://www.columbia.edu',
    'http://www.yale.edu',
    'http://www.caltech.edu',
    'http://www.ucla.edu',
    'http://www.princeton.edu',
    'http://www.cornell.edu',
    'http://www.upenn.edu',
    'http://home.dartmouth.edu',
    'http://web.mit.edu'
]

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
            with open(output_file,"a") as f:
		localtime = now.strftime("%Y-%m-%d %H:%M:%S")
                f.writelines(localtime + " " + test_url + " failed\n")
        else:
            now = datetime.datetime.now()
            localtime = now.strftime("%Y-%m-%d %H:%M:%S")

            print (localtime + " " + test_url + " success\n")
            with open(output_file,"a") as f:
                f.writelines(localtime + " " + test_url + " success\n")
            c.close()

def test_download_vpn(test_url,output_file):
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
                with open(output_file,"a") as f:
                    f.writelines(localtime + " " + test_url + " failed\n")
            else:
                now = datetime.datetime.now()
                localtime = now.strftime("%Y-%m-%d %H:%M:%S")

                print (localtime + " " + test_url + " success\n")
                with open(output_file,"a") as f:
                    f.writelines(localtime + " " + test_url + " success\n") 
                c.close()

if __name__ == '__main__':
    num_tasks = 1
    if len(sys.argv) != 2:
        print("Usage: %s <op(0->vpn;1->socks)>" % sys.argv[0])
    option = sys.argv[1]   #0->vpn 1->socks
    start = datetime.datetime.now()

    if(option == '0'):
        print "Using VPN now"
        file_name = "vpn_test_url_"+start.strftime("%m%d_%H:%M")+".txt"
    else :
        print "Using Socks now"
        file_name = "socks_test_url_"+start.strftime("%m%d_%H:%M")+".txt"
    with open(file_name,"w") as f:
        f.writelines("\n")
    while True:
        print ('Task : %d' %(num_tasks))
        test_download_socks(targets[random.randint(0, len(targets))],file_name)
        num_tasks = num_tasks +1
        time.sleep(20)
