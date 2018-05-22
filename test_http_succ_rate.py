#!/usr/bin/env python

import os
import sys
import subprocess
import time
from subprocess import PIPE


MAX_PROC_NUM = 20
JAIL_TIME = 92

GOODWORD = 'safeweb'
BADWORD = 'ultrasurf'

LOGFILENAME = "./results/http_succ_rslt.txt"

OUTTER_WEBSITES = {
    'multipath-tcp.org': 'http://multipath-tcp.org/',
    'amiusingmptcp.de': 'http://amiusingmptcp.de/',
    'ixit.cz': 'http://ixit.cz/',
    'technosrix.com': 'http://technosrix.com/',
    'watchy.in': 'http://watchy.in/',
    'hsh.link': 'http://hsh.link/',
    'tetaneutral.net': 'http://apt.tetaneutral.net/',
    'hchs.de': 'http://www.hchs.de/',
    'neurocode-ag.com': 'http://www.neurocode-ag.com/',
    'ip-mobilphone.net': 'http://www.ip-mobilphone.net/',
    'usenet-replayer.com': 'http://www.usenet-replayer.com/'
}


TARGETS = OUTTER_WEBSITES
KEYWORD = None

start_time = None


def start_tcpdump(sid):
    print("Starting tcpdump...")
    p = subprocess.Popen(["tcpdump", "-i", "any", "-w", "./results/pktdump.pcap.%d.%s" % (sid, start_time), "tcp port 80"])
    return p

def stop_tcpdump(p):
    print("Stopping tcpdump...")
    os.system("kill %d" % p.pid)

def is_alldone(test_count, round_num):
    for website in TARGETS:
        if website not in test_count:
            return False
        if test_count[website] < round_num:
            return False
    return True

def is_jailed(jail_time, website):
    if website not in jail_time:
        return False
    if time.time() - jail_time[website] > JAIL_TIME:
        del jail_time[website]
        return False
    return True

def test_websites(sid, rounds):
    global start_time
    start_time = time.strftime("%Y%m%d%H%M%S")
    p = start_tcpdump(sid)
    time.sleep(2)
    jail_time = {}
    testing = {}
    test_count = {}
    succ_cout = 0

    i = 0
    os.system("touch %s" % LOGFILENAME)
    with open(LOGFILENAME, 'w') as f:
        while not is_alldone(test_count, rounds):
            print("[Round %d]" % (i+1))
            for website, url in TARGETS.iteritems():
                if website not in test_count:
                    test_count[website] = 0

                if test_count[website] >= rounds:
                    # the website has been done
                    continue

                while len(testing) >= MAX_PROC_NUM:
                    # clean working set
                    websites = testing.keys()
                    for website in websites:
                        ret = testing[website].poll()
                        if ret is not None:
                            if ret == 4:
                                # connect reset by peer (reset by GFW?)
                                jail_time[website] = time.time()
                            del testing[website]
                    time.sleep(0.5)

                if is_jailed(jail_time, website):
                    # in jail, skip
                    print("%s in jail. %ds left. skip..." % (website, jail_time[website] + JAIL_TIME - time.time()))
                else:
                    if testing.get(website):
                        # testing, skip
                        ret = testing[website].poll()
                        if ret is not None:
                            if ret == 4:
                                # connect reset by peer (reset by GFW?)
                                jail_time[website] = time.time()
                            del testing[website]
                    else:
                        print("Testing website %s..." % website)
                        wget_rq_str = "wget -4 -O /dev/null --tries=1 --timeout=5 --max-redirect 0 " + url + KEYWORD
                        pwget = subprocess.Popen(wget_rq_str, stdout=PIPE, stderr=PIPE, shell=True)
                        wget_rslt = pwget.communicate()[1];
                        f.write(wget_rq_str + "\n")
                        f.write(wget_rslt)
                        if wget_rslt.find("reset") == -1:
                            succ_cout += 1
                        testing[website] = pwget
                        test_count[website] += 1

                time.sleep(0.1)
            i += 1
        f.write("Success count: %d" % succ_cout)

    time.sleep(5)
    stop_tcpdump(p)
    os.system("./stop.sh")
    time.sleep(0.5)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Needs root privilege.")
        sys.exit(0)
    import os.path
    if not os.path.isfile("mptcp_proxy"):
        print("Cannot find mptcp_proxy. Please try \"make\".")
        sys.exit(0)

    if len(sys.argv) != 3:
        print("Usage: %s <sid> <num of rounds>" % sys.argv[0])
    sid = int(sys.argv[1])
    rounds = int(sys.argv[2])
    if sid == 0:
        KEYWORD = GOODWORD
    else:
        KEYWORD = BADWORD
    os.system("mkdir results")
    os.system("chmod 777 results")
    print("Stopping mptcp_proxy.")
    os.system("./stop.sh")
    time.sleep(1)
    print("Restarting intang.")
    os.system("./run.sh")
    time.sleep(1)
    test_websites(sid, rounds)


