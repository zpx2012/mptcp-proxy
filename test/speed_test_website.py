import io,pycurl,sys,os,time,datetime,traceback

#GOODWORD = 'goodword'
#BADWORD = 'ultrasurf'

OUTTER_WEBSITES = {
    'google.com': 'http://www.google.com',
    'facebook.com': 'http://www.facebook.com',
    'twitter.com': 'http://www.twitter.com',
    'whatsapp.com': 'http://www.whatsapp.com/',
    'amazon.com': 'http://www.amazon.com/',
    'instagram.com': 'http://www.instagram.com',
    'youtube.com' : 'http://www.youtube.com',
    'tumblr.com' : 'http://www.tumblr.com',
    'dropbox.com' : 'http://www.dropbox.com',
    'google.com': 'https://www.google.com',
    'facebook.com': 'https://www.facebook.com',
    'twitter.com': 'https://www.twitter.com',
    'whatsapp.com': 'https://www.whatsapp.com/',
    'amazon.com': 'https://www.amazon.com/',
    'instagram.com': 'https://www.instagram.com',
    'youtube.com' : 'https://www.youtube.com',
    'tumblr.com' : 'https://www.tumblr.com',
    'dropbox.com' : 'https://www.dropbox.com',


#    'hulu.com': 'http://www.hulu.com/',
#    'royalmail.com': 'http://www.royalmail.com/',
#    'nationwide.co.uk': 'http://www.nationwide.co.uk/',
#    'currys.co.uk': 'http://www.currys.co.uk/',
#    'livedoor.com': 'http://search.livedoor.com/',
#    'naver.jp': 'http://matome.naver.jp/',
#    'nonews.com': 'http://legacy.nownews.com/',
#    'cheers.com.tw': 'http://www.cheers.com.tw/',
#    'u-car.com.tw': 'http://www.u-car.com.tw/',
#    'gaana.com': 'http://gaana.com/',
#    'monster.com': 'http://www.monsterindia.com/',
#    'rambler.ru': 'http://nova.rambler.ru/',
#    'eldorado.ru': 'http://www.eldorado.ru/',
#    'shaw.ca': 'http://www.shaw.ca/',
#    'cic.gc.ca': 'http://www.cic.gc.ca/',
#    'sbs.com.au': 'http://www.sbs.com.au/',
#    'nla.gov.au': 'http://www.nla.gov.au/',
}

targets = OUTTER_WEBSITES

def test_download_socks(website,test_url,output_file):
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
                f.writelines(localtime + " " + website + " failed\n")
        else:
            now = datetime.datetime.now()
            localtime = now.strftime("%Y-%m-%d %H:%M:%S")

            print (localtime + " " + website + " success\n")
            with open(output_file,"a") as f:
                f.writelines(localtime + " " + website + " success\n")
            c.close()

def test_download_vpn(website,test_url,output_file):
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
		    localtime = now.strftime("%Y-%m-%d %H:%M:%S")
                    f.writelines(localtime + " " + website + " failed\n")
            else:
                now = datetime.datetime.now()
                localtime = now.strftime("%Y-%m-%d %H:%M:%S")

                print (localtime + " " + website + " success\n")
                with open(output_file,"a") as f:
                    f.writelines(localtime + " " + website + " success\n") 
                c.close()

if __name__ == '__main__':
    num_tasks = 1
    if len(sys.argv) != 2:
        print("Usage: %s <op(0->vpn;1->socks)>" % sys.argv[0])
    option = sys.argv[1]   #0->vpn 1->socks
    start = datetime.datetime.now()

    if(option == '0'):
        print "Using VPN now"
        file_name = "vpn_website_"+start.strftime("%m%d_%H:%M")+".txt"
        with open(file_name,"w") as f:
            f.writelines("\n")
        while True:
            print ('Task : %d' %(num_tasks))
            for website,url in targets.iteritems():
                test_download_vpn(website,url,file_name)
            num_tasks = num_tasks +1
            time.sleep(20)
    else :
        print "Using Socks now"
        file_name = "socks_website_"+start.strftime("%m%d_%H:%M")+".txt"
        with open(file_name,"w") as f:
            f.writelines("\n")
        while True:
            print ('Task : %d' %(num_tasks))
            for website,url in targets.iteritems():
                test_download_socks(website,url,file_name)
            num_tasks = num_tasks +1
            time.sleep(20)
