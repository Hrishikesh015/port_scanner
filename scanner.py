import random
from ipaddress import IPv4Network
from sys import flags
from tabnanny import verbose
from scapy.all import ICMP, IP, sr1, TCP
from multiprocessing.pool import ThreadPool as Pool
import threading

# Define end host and TCP port range

host = input("Enter target IP address:")
ver = input("Do you want verbose scanning?:")
verb=0
if ver == 'y'or 'yes' or 'Y':
	verb=1
else:
	verb=0
open_ports=[]
closed_ports=[]
print("Scanning.....")
def scanner(dst_port):
    src_port=random.randint(1025,65534)
    resp=sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0,)
    if resp is None:
    	pass
        #return(f"{host}:{dst_port} is filtered (silently dropped).")

    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            # Send a gratuitous RST to close the connection
            send_rst = sr1(
                IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                timeout=1,
                verbose=verb,
            )
            #open_ports.append(ds_port)
            return(f"{host}:{dst_port} is open.")

        elif (resp.getlayer(TCP).flags == 0x14):
            #closed_ports.append(dst_port)
            return(f"{host}:{dst_port} is closed.")
            

    elif(resp.haslayer(ICMP)):
        if(
            int(resp.getlayer(ICMP).type) == 3 and
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
            return(f"{host}:{dst_port} is filtered (silently dropped).")
# Send SYN with random Src Port for each Dst port

def scn(port_range,pool_size):
	with Pool(pool_size) as p:
		l=(p.map(scanner,port_range))
	for i in l :
	 if str(i)!="None":
	  print (i)



#for dst_port in port_range:
 #   print("Scanning.....",dst_port)
  #  pool.apply_async(scanner,dst_port)

    # src_port = random.randint(1025,65534)
    # resp = sr1(
    #     IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
    #     verbose=0,
    # )

    # if resp is None:
    #     print(f"{host}:{dst_port} is filtered (silently dropped).")

    # elif(resp.haslayer(TCP)):
    #     if(resp.getlayer(TCP).flags == 0x12):
    #         # Send a gratuitous RST to close the connection
    #         send_rst = sr(
    #             IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
    #             timeout=1,
    #             verbose=0,
    #         )
    #         print(f"{host}:{dst_port} is open.")

    #     elif (resp.getlayer(TCP).flags == 0x14):
    #         print(f"{host}:{dst_port} is closed.")

    # elif(resp.haslayer(ICMP)):
    #     if(
    #         int(resp.getlayer(ICMP).type) == 3 and
    #         int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
    #     ):
    #         print(f"{host}:{dst_port} is filtered (silently dropped).")


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
