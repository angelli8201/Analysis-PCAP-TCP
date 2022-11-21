import dpkt
import socket

senderip = "130.245.145.12" #assignnent said we can hardcode the ip addresses
receiverip = "128.208.2.198"
srcports = [] # needed to store source and destination ports
dstports = []

totalFlows = 0 # measure flow data
flowbytes1=0 
flowbytes2=0 
flowbytes3=0 
timesFlow1 = []
timesFlow2 = []
timesFlow3 = []

transactionCounter1 = 0 #used for printing first 2 transactions after connection for each
transactionCounter2 = 0
transactionCounter3 = 0
display1 = 0 #used for printing part a 
display2 = 0
display3 = 0

sentOnce= []
sentTwice= []
sentThrice =[]

print("Part A:")
f = open('assignment2.pcap', 'rb') #open file and read pcap
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap: #look into every packet in pcap
    eth = dpkt.ethernet.Ethernet(buf) #ethernet frame
    if (eth.data.p != dpkt.ip.IP_PROTO_TCP): #only interested on TCP
        continue
    ip = eth.data #get data from ethernet frame
    packetSrc = socket.inet_ntoa(ip.src) #convert ip address
    packetDst = socket.inet_ntoa(ip.dst)
    tcp = ip.data 
    
    if(packetSrc == senderip and packetDst == receiverip):
        if(tcp.flags == 0x02): # flow starts with ACK
            #print("Flags:" + str(tcp.flags))
            totalFlows +=1
            if(tcp.sport not in srcports): # get source ports
                srcports.append(tcp.sport)
            else:
                continue
            if(tcp.dport not in dstports): # get destination ports
                dstports.append(tcp.dport)
            else:
                continue    
        else: 
            pass
        
#Output gives:
#[43498, 43500, 43502] for ports

    if(tcp.sport == 43498 and tcp.flags == 0x10): #found first port and looking at acks
        while (display1 <1):
            print("-------------------------------------- ")
            print("Source port: " + str(tcp.sport))
            print("Source IP Address: " + str(packetSrc))
            print("Destination Port " + str(tcp.dport))     
            print("Destination IP Adddress " + str(packetDst))
            print(" ")
            display1 +=1
        while(transactionCounter1 >=0 and transactionCounter1 <=1):
            print("Transaction: ")
            print("Sequence number: " + str(tcp.seq))
            print("Ack Number: " + str(tcp.ack))
            print("Window Size: " + str(tcp.win))
            transactionCounter1 +=1
            print (" ")


    if(tcp.sport == 43500 and tcp.flags == 0x10): #found second port and looking at acks
        while (display2 <1):
            print("-------------------------------------- ")
            print("Source port: " + str(tcp.sport))
            print("Source IP Address: " + str(packetSrc))
            print("Destination Port " + str(tcp.dport))     
            print("Destination IP Adddress " + str(packetDst))
            print(" ")
            display2 +=1
        if(transactionCounter2 >=0 and transactionCounter2 <=1):
            print("Transaction: ")
            print("Sequence number: " + str(tcp.seq))
            print("Ack Number: " + str(tcp.ack))
            print("Window Size: " + str(tcp.win))
            transactionCounter2 +=1
            print (" ")
       

    

    if(tcp.sport == 43502 and tcp.flags == 0x10): #found third port and looking at acks
        while (display3 <1):
            print("-------------------------------------- ")
            print("Source port: " + str(tcp.sport))
            print("Source IP Address: " + str(packetSrc))
            print("Destination Port " + str(tcp.dport))     
            print("Destination IP Adddress " + str(packetDst))
            print(" ")
            display3 +=1
        if(transactionCounter3 >=0 and transactionCounter3 <=1):
                print("Transaction: ")
                print("Sequence number: " + str(tcp.seq))
                print("Ack Number: " + str(tcp.ack))
                print("Window Size: " + str(tcp.win))
                transactionCounter3 +=1   
                print(" ") 
             
              
    if(tcp.sport == 43498 or tcp.dport == 43498): #used to find throughput at the 3 ports
        flowbytes1 += int(eth.data.len)
        timesFlow1.append(ts)
    if(tcp.sport == 43500 or tcp.dport == 43500):
        flowbytes2 += int(eth.data.len)
        timesFlow2.append(ts)
    if(tcp.sport == 43502 or tcp.dport == 43502):
        flowbytes3 += int(eth.data.len)
        timesFlow3.append(ts)
    
    if(tcp.dport == 43498):
        sentOnce.append(tcp.ack)
    if(tcp.dport ==43500):
        sentTwice.append(tcp.ack)
    if(tcp.dport ==43502):
        sentThrice.append(tcp.ack)
      
#Calculate RTT= time difference of packet first sent and first ack
RTT1=(timesFlow1[1]-timesFlow1[0])
RTT2=(timesFlow2[1]-timesFlow2[0])
RTT3=(timesFlow3[1]-timesFlow3[0])

packets1=0
packets11=0
packets111=0
i =2
i1=1
i11=1
sum = 0
sum1 = 0
sum11=0

for pk in timesFlow1: #congestion window for port 43498
    while (sum <RTT1):
        sum += (timesFlow1[i]-timesFlow1[i-1])
        packets1 +=1
        i+=1
for pk in timesFlow1:
    while (sum1 <RTT1):
        sum1 += (timesFlow1[i1+i]-timesFlow1[i1+i-1])
        packets11 +=1
        i1+=1
for pk in timesFlow1:
    while (sum11 <RTT1):
        sum11 += (timesFlow1[i11+i1+i]-timesFlow1[i11+i1+i-1])
        packets111 +=1
        i11+=1

sum2=0
sum22=0
sum222 =0
j=2
j1=1
j11=1
packets2=0
packets22=0
packets222=0

for pk in timesFlow2:
    while (sum2 <RTT2):
        sum2 += (timesFlow2[j]-timesFlow2[j-1])
        packets2 +=1
        j+=1
for pk in timesFlow2:
    while (sum22 <RTT2):
        sum22 += (timesFlow2[j1+j]-timesFlow2[j1+j-1])
        packets22 +=1
        j1+=1
for pk in timesFlow2:
    while (sum222 <RTT2):
        sum222 += (timesFlow2[j11+j1+j]-timesFlow2[j11+j1+j-1])
        packets222 +=1
        j11+=1

sum3 = 0
sum33 = 0
sum333 = 0
k=2
k1=1
k11=1
packets3 =0
packets33 =0
packets333 =0
for pk in timesFlow3:
    while (sum3 <RTT3):
        sum3+= (timesFlow3[k]-timesFlow3[k-1])
        packets3 +=1
        k+=1
for pk in timesFlow3:
    while (sum33 <RTT3):
        sum33 += (timesFlow3[k1+k]-timesFlow3[k1+k-1])
        packets33 +=1
        k1+=1
for pk in timesFlow3:
    while (sum333 <RTT3):
        sum333 += (timesFlow3[k11+k1+j]-timesFlow3[k11+k1+k-1])
        packets333 +=1
        k11+=1

throughputFlow1= flowbytes1 / (timesFlow1[-1] - timesFlow1[0])
throughputFlow2= flowbytes2 / (timesFlow2[-1] - timesFlow2[0])
throughputFlow3= flowbytes3 / (timesFlow3[-1] - timesFlow3[0]) 

print("-------------------------------------- ")   
print("There were a total of " + str(totalFlows) + " initiated from the sender.")
print("Sender throughput for Port 43498: " + str(throughputFlow1) + " Bytes Per Second")
print("Sender throughput for Port 43500: " + str(throughputFlow2) + " Bytes Per Second") 
print("Sender throughput for Port 43502: " + str(throughputFlow3) + " Bytes Per Second")         

print("\nPart B")
print("Congestion Window for Port 43498: ", packets1,packets11,packets111)
print("Congestion Window for Port 43500: ", packets2,packets22,packets222)
print("Congestion Window for Port 43502: ", packets3,packets33,packets333)     


sent1 = []
sent2 = []
sent3 = []

for num in sentOnce:
    if (sentOnce.count(num) ==3):
        sent1.append(num)
for num in sentTwice:
    if (sentTwice.count(num) ==3):
        sent2.append(num)
for num in sentThrice:
    if (sentThrice.count(num) ==3):
        sent3.append(num)

a = len(set(sent1))
b = len(set(sent2))
c = len(set(sent3))

print("\nNumber of retransmissions due to triple acks for Port 43498: ",a)
print("Number of retransmissions due to triple acks for Port 43500: ",b)
print("Number of retransmissions due to triple acks for Port 43502: ",c)

timeouts1=0
timeouts2=0
timeouts3=0
t1=1
t2=1
t3=1

for pk in timesFlow1:
    if (timesFlow1[t1]- timesFlow1[t1-1] > 2*RTT1):
        timeouts1 +=1  
        t1+=1
for pk in timesFlow2:
    if (timesFlow1[t2]- timesFlow1[t2-1] > 2*RTT2):
        timeouts2 +=1  
        t2+=1
for pk in timesFlow3:
    if (timesFlow1[t3]- timesFlow1[t3-1] > 2*RTT3):
        timeouts3 +=1  
        t3+=1


print("\nNumber of retransmissions due to timeouts for Port 43498: ",timeouts1)
print("Number of retransmissions due to timeouts for Port 43500: ",timeouts2)
print("Number of retransmissions due to timesouts for Port 43502: ",timeouts3)

   