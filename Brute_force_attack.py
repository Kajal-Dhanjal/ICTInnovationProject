
import datetime
import random
import os

counter=1
counter2=1
start_time=0
ending_time=0
time=datetime.datetime.now()
class Randomization:
    def __init__(self, session_id,ip, sshd_port, port_number, uid, systemd_logind,user):
        self.session_id = session_id
        self.ip = ip
        self.sshd_port = sshd_port
        self.port_number = port_number
        self.uid = uid
        self.systemd_logind = systemd_logind
        self.user=user
log_entry_array=[]
users= ["user1","user2","user3","user4"]
Failed_Event_Outcomes= ["Authentication Failure", "Failed Password", "Message Repeated","Connection Closed"]

Successful_Disconnecion_Event_outcomes= ["Received Disconnect", "Disconnected", "Session Closed", "Session logged out", "Remove Session"]
ssh_connection=False #used to check if ssh connection exists then will randomly disconnect ssh connection
def log_generation():
    global time
    disconnection_check=False
    print("Please enter percentage of  Brute force attack attempts in intervals of 10")
    probability=int(input())
    while(int(probability)%10!=0 or int(probability)<=0):
        print("Please enter percentage of Brute force attack attempts in intervals of 10")
        probability=int(input()) 

    print("Please enter percentage of Successful Brute force attack attempts in intervals of 10")
    successful_brute_force_probability=int(input())
    while(int(successful_brute_force_probability)%10!=0 or int(successful_brute_force_probability)<=0):
        print("Please enter percentage of Successful Brute force attack attempts in intervals of 10")
        successful_brute_force_probability=int(input()) 
    
    print("Enter the number of logs events to generate")
    log_number=int(input())
    print("enter the starting time")
    global start_time
    start_time=int(input())
    print("enter the ending time")
    global ending_time
    ending_time=int(input())
    time.replace(hour=start_time)
    temp= int((probability/100)*log_number) #used to  determine probability of brute force attack
    brute_force_attack_logs= random.sample(range(log_number), temp)#sets unique number from range
    #print(brute_force_attack_logs)
    i=0
    while(i<log_number):
        if i in brute_force_attack_logs:
            failed_brute_force_attack(temp,successful_brute_force_probability)
        else:
            successful_log_events()
            disconnection_check=random.randint(0,1)
            if(disconnection_check):
                successful_disconnection_log_Events(random.randint(0,len(log_entry_array)-1))
                disconnection_check=0

        i+=1
def successful_log_events():
    file=open("auth.log.txt","a")
    global counter
    sshd_port=random.randint(4000, 4999)
    ip=str(random.randint(190, 194))+"."+str(random.randint(168, 172))+"."+str(random.randint(1, 255))+"."+str(random.randint(1, 255))
    port_number=random.randint(49152, 65535)
    uid=random.randint(10000,60000)
    systemd_logind=random.randint(1,32768)
    user_index=random.randint(0, len(users) - 1)
    temp=Randomization(counter,ip,sshd_port,port_number,uid,systemd_logind, users[user_index])
    log_entry_array.append(temp)
    print(datetime.datetime.now(),users[user_index] , f"sshd[{sshd_port}]:","Accepted Password","for user5 from ",ip," port", port_number)
    print(datetime.datetime.now(), users[user_index], f"sshd[{sshd_port}]:", f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    print(datetime.datetime.now(), users[user_index],f"systemd-logind[{systemd_logind}]: new session {counter} of user user5") 

    file.write(f"{datetime.datetime.now()} {users[user_index]} sshd[{sshd_port}]: "
        f"Accepted Password for user5 from {ip} port {port_number}\n"
        f"{datetime.datetime.now()} {users[user_index]} sshd[{sshd_port}]: "
        f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)\n"
        f"{datetime.datetime.now()} {users[user_index]} systemd-logind[{systemd_logind}]: "
        f"new session {counter} of user user5\n")
    
    counter+=1
    file.close()
def successful_log_events_brute_force_attack(sshd_port,ip,port_number,user_index):
    global counter
    file=open("auth.log.txt","a")
    uid=random.randint(10000,60000)
    systemd_logind=random.randint(1,32768)
    user_index=random.randint(0, len(users) - 1)
    temp=Randomization(counter,ip,sshd_port,port_number,uid,systemd_logind, users[user_index])
    log_entry_array.append(temp)
    print(datetime.datetime.now(),users[user_index] , f"sshd[{sshd_port}]:","Accepted Password","for user5 from ",ip," port", port_number)
    print(datetime.datetime.now(), users[user_index], f"sshd[{sshd_port}]:", f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    print(datetime.datetime.now(), users[user_index],f"systemd-logind[{systemd_logind}]: new session {counter} of user user5")   
   
    file.write(f"{datetime.datetime.now()} {users[user_index]} sshd[{sshd_port}]: "
        f"Accepted Password for user5 from {ip} port {port_number}\n"
        f"{datetime.datetime.now()} {users[user_index]} sshd[{sshd_port}]: "
        f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)\n"
        f"{datetime.datetime.now()} {users[user_index]} systemd-logind[{systemd_logind}]: "
        f"new session {counter} of user user5\n")  
    file.close()
    counter+=1
def successful_disconnection_log_Events(index):
     temp=random.randint(4000, 4999)
     file=open("auth.log.txt","a")
     print(datetime.datetime.now(),log_entry_array[index].user,f" sshd[{temp}]: Recieved disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user")
     print(datetime.datetime.now(),log_entry_array[index].user,f" sshd[{temp}]: Disconnected from user user5 {log_entry_array[index].ip}, port {log_entry_array[index].port_number}")
     print(datetime.datetime.now(),log_entry_array[index].user,f" sshd[{log_entry_array[index].sshd_port}]: pam_unix(sshd:session): session closed for user ubuntu5" )
     print(datetime.datetime.now(),log_entry_array[index].user,f"systemd-logind[{log_entry_array[index].systemd_logind}]: Session {log_entry_array[index].session_id} logged out. Waiting for process to exit")
     print(datetime.datetime.now(),log_entry_array[index].user,f"systemd-logind[{log_entry_array[index].systemd_logind}]: Removed Session {log_entry_array[index].session_id}")

     file.write(f"{datetime.datetime.now()} {log_entry_array[index].user} sshd[{temp}]: "
        f"Received disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user\n"
        f"{datetime.datetime.now()} {log_entry_array[index].user} sshd[{temp}]: "
        f"Disconnected from user user5 {log_entry_array[index].ip}, port {log_entry_array[index].port_number}\n"
        f"{datetime.datetime.now()} {log_entry_array[index].user} sshd[{log_entry_array[index].sshd_port}]: "
        f"pam_unix(sshd:session): session closed for user ubuntu5\n"
        f"{datetime.datetime.now()} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: "
        f"Session {log_entry_array[index].session_id} logged out. Waiting for process to exit\n"
        f"{datetime.datetime.now()} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: "
        f"Removed Session {log_entry_array[index].session_id}\n")
     
     file.close()
     log_entry_array.pop(index)

def failed_brute_force_attack(brute_force_events,successful_brute_force_probability):
    global counter2
    temp=int((successful_brute_force_probability/100)*brute_force_events)#used for checking proability of successful attacks
    file=open("auth.log.txt","a")
    user_index=random.randint(0, len(users) - 1)
    sshd_port=random.randint(4000, 4999)
    port_number=random.randint(49152, 65535)
    ip=str(random.randint(190, 194))+"."+str(random.randint(168, 172))+"."+str(random.randint(1, 255))+"."+str(random.randint(1, 255))
    print(datetime.datetime.now(),users[user_index] , f"sshd[{sshd_port}]:" f"pam_unix(sshd:auth): authentication failure: logname= uid=0  euid=0 tty=ssh ruser = rhost={ip} user=user5")
    file.write(f"{datetime.datetime.now()} {users[user_index]} sshd[{sshd_port}]: "
        f"pam_unix(sshd:auth): authentication failure: logname= uid=0 euid=0 tty=ssh "
        f"ruser = rhost={ip} user=user5\n")
    if(counter2<=temp):
        successful_log_events_brute_force_attack(sshd_port,ip,port_number,user_index)
        counter2+=1
    else:
        print(datetime.datetime.now(),users[user_index] , f"sshd[{sshd_port}]: Failed password for user5 from {ip} port {port_number} ssh2")
        file.write(f"{datetime.datetime.now()} {users[user_index]} sshd[{sshd_port}]: "
            f"Failed password for user5 from {ip} port {port_number} ssh2\n")
    file.close()
   
log_generation()


