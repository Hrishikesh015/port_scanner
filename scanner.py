import random
from ipaddress import IPv4Network
from scapy.all import ICMP, IP, sr1, TCP
from multiprocessing.pool import ThreadPool as Pool
import threading
import socket
from tkinter import *
from functools import partial

common_services={20:'FTP Data Transfer',21:'FTP Command Transfer',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',119:'NNTP',123:'NTP',143:'IMAP',161:'SNMP',194:'IRC',443:'HTTPS'};

def scanner(dst_port):
    src_port=random.randint(1025,65534)
    resp=sr1(IP(dst=hostip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0,)
    #resp.show()
    if resp is None:
        if verb==1:
            #return(f"{host}:{dst_port} is filtered (silently dropped).")
            filtered_ports.append(dst_port)
        else:
            pass

    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            # Bye Bye connection, reset closes connection
            send_rst = sr1(
                IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                timeout=1,
                verbose=verb,
            )

            #open_ports.append(ds_port)
            if dst_port in common_services:
                print(dst_port,"commonly runs",common_services[dst_port])
            open_ports.append(dst_port)
            #return(f"{host}:{dst_port} is open.")

        elif (resp.getlayer(TCP).flags == 0x14 and verb):
            #closed_ports.append(dst_port)
            closed_ports.append(dst_port)
            #return(f"{host}:{dst_port} is closed.")
            

    elif(resp.haslayer(ICMP)):
        if(
            int(resp.getlayer(ICMP).type) == 3 and
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
        	filtered_ports.append(dst_port)
            #return(f"{host}:{dst_port} is filtered (silently dropped).")
# Send SYN with random Src Port for each Dst port

def scn(port_range,pool_size):
	with Pool(pool_size) as p:
		l=(p.map(scanner,port_range))
	for i in l :
	 if str(i)!="None":
	  print (i)
	
	





def run_prog():
        host=hostentry.get()
        verb=verbose.get()
        resp=sr1(IP(dst=host)/TCP(sport=1025,dport=80,flags="S"),timeout=1,verbose=0,)
        hostip=resp.src
        open_ports=[]
        closed_ports=[]
        filtered_ports = []
        print("Scanning.....")

                

        port_range1 = range(1,100)
        pool_size1=len(port_range1)

        port_range2 = range(100,200)
        pool_size2=len(port_range2)

        port_range3 = range(200,300)
        pool_size3=len(port_range3)

        port_range4 = range(300,400)
        pool_size4=len(port_range4)

        port_range5 = range(400,500)
        pool_size5=len(port_range5)

        port_range6 = range(500,600)
        pool_size6=len(port_range6)

        port_range7 = range(600,700)
        pool_size7=len(port_range7)

        port_range8 = range(700,800)
        pool_size8=len(port_range8)

        port_range9 = range(800,900)
        pool_size9=len(port_range9)

        port_range10 = range(900,1000)
        pool_size10=len(port_range10)




        t1=threading.Thread(target=scn(port_range1,pool_size1))
        t2=threading.Thread(target=scn(port_range2,pool_size2))
        t3=threading.Thread(target=scn(port_range3,pool_size3))
        t4=threading.Thread(target=scn(port_range4,pool_size4))
        t5=threading.Thread(target=scn(port_range5,pool_size5))
        t6=threading.Thread(target=scn(port_range6,pool_size6))
        t7=threading.Thread(target=scn(port_range7,pool_size7))
        t8=threading.Thread(target=scn(port_range8,pool_size8))
        t9=threading.Thread(target=scn(port_range9,pool_size9))
        t10=threading.Thread(target=scn(port_range10,pool_size10))




        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        ttl=int(resp.ttl)
        window=resp.window
        print("\n\n-------------OS Detection------------\n\n")
        if ttl==64 and window==5840:
                print("Linux Kernel 2.4 or 2.6")
        elif ttl==64 and window==5720:
                print("Google's customized linux")
        elif ttl==64 and window==65535:
                print("FreeBSD")
        elif ttl==128 and window==65535:
                print("Windows XP")
        elif ttl==128 and window==8192:
                print("Windows 7,Vista and Server 2008")
        elif ttl==255 and window==4128:
                print("Cisco Router(iOS 12.4)")
        else:
                print("Unknown")


        print("\n\n--------------FULLY QUALIFIED HOST NAME-----------\n\n")
        print(socket.getfqdn(host))
        print("\n\n--------------OPEN PORTS----------------")
        for i in open_ports:
                print(i)




def make_gui():
        global verbose
        root=Tk()
        root.title("TCP Port Scanner")
        root.geometry("250x450")
        root.configure(background="black")
        hostlabel = Label(root ,text = "Enter domain name:",bg="black",fg="#39ff14").grid(row = 0,column = 0)
        global hostentry
        verbose=IntVar()
        hostentry=Entry(root,bg="#1c1c1c",fg="#00FFFF")
        hostentry.grid(row = 0,column = 1)
        verboselabel=Label(root ,text = "Enable Verbose:",bg="black",fg="#39ff14").grid(row = 1,column = 0)
        verboseYes=Radiobutton(root,text="Yes",variable=verbose,value=1,bg="black",fg="#00FFFF",activebackground="black", activeforeground="#00FFFF",selectcolor="#1c1c1c").grid(row=2,column=0)
        verboseNo=Radiobutton(root,text="No",variable=verbose,value=0,bg="black",fg="#00FFFF",activebackground="black", activeforeground="#00FFFF",selectcolor="#1c1c1c").grid(row=2,column=1)
        go=Button(root,text="Start Scan",bg="#1c1c1c",fg="#39ff14",activebackground="#1c1c1c", activeforeground="#00FFFF",command=run_prog).grid(row=3,column=0)
        root.mainloop()
        

make_gui()
