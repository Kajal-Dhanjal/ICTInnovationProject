import random
from datetime import datetime, timedelta

idval = random.randint(1000, 2000) #this is defining the ID value and in the exfil_ufw_log function it is defined as a gloabl variable 

sr_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}" # this source IP was moved outside the function so that the source IP is changed everythime when it is executed, but remains the same until the end of the execution 

def exfil_ufw_log():
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 86400)) #this will create the time for the last 24 hours using seconds 
    #sr_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}" #this is the seource destination IP address 
    #sr_ip = f"192.168.12.2"
    des_ip = f"192.168.{random.randint(250, 250)}.{random.randint(166, 168)}" #this is the destination IP address, i have modified this so there is a smaller subnet gap then before
    proto = random.choice(["TCP"]) #this is for the TCP protocol, it should be mostly TCP and not UDP
    sour_port = random.randint(1024, 65535) #this is the range of the TCP ports
    #destin_port = random.choice([22, 80]) #this is the ssh, https, http port respectivly, destination port
    win = random.randint(200, 1000) #this is for the windows feild number 
    flag = random.choice(["SYN", "ACK"]) #this is the SYN and ACK TCP flags

  #  if random.random() < 0.01: #this is for 1%
   #     flag = random.choice(["SYN"])
  #  else:
   #     flag = random.choice(["ACK"])

    if random.random() < 0.95: #this will print out 95% of the time ssh ports, and 5% of the time http ports whihc is another indicator of the attack. 
        destin_port = 22
    else: 
        destin_port = 80


    #this will change the number of LEN or bytes size
    if random.random() < 0.1: #0.1 meand 10%
        length = random.randint(1250, 5000) # this is for the larger bytes 
    else: 
        length = random.randint(52, 350) # this is for the smaller bytes which will be produces 

    global idval #this is defining the gloabal value 
    #idval = random.randint(1000, 2000) #this will generate the ID number of the packet,    IN THIS YOU HAVE TO MAKE IT SO EACH ROW HAVE AN ID AND THE NEXT RWO HAS +1 FROM THE PREVIOUS ROW

    #generate the actual log with feild values                         #add more feilds to this 
    print_log = (f"{timestamp} ubuntu@user kernal: [UFW Audit] IN=eth0 OUT= SRC={sr_ip} DST={des_ip} LEN={length} TOS=0x10 TTL=64 PREC=0x00 PORTO={proto} ID={idval} SPT={sour_port} DPT={destin_port} WINDOW={win} RES=0x00 {flag}")

    idval += 1 #this will add +1 to each log entry

    return print_log
#idval = random.randint(1000, 2000)


#this loop below requests user input to allow the number of log entries to be generated
total_entries = input("Select the amout of volume of log entries to be generated: High or Moderate or Low? ")

if total_entries == "Low" or total_entries == "low":
    num = 100
elif total_entries == "Moderate" or total_entries == "moderate":
    num = 250 
elif total_entries == "High" or total_entries == "high":
    num = 500
else: 
    "Please select from the provided catagories above: "

print_log = [exfil_ufw_log() for _ in range(num)]
#this thing below specifies the number of entries that user wants to be generated
#print_log = [exfil_ufw_log() for _ in range(int(input("Enter the number of log entries you would like?")))] #this prints the log based on the number of log entries entered by the user
#this below actually prints the logs
for entry in print_log:
    print(entry)


    


    #end 1674, start 1425, this if for moderate
    #end 2063, start 1564, this is for high
