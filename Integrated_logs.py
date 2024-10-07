
import random
import os
import time
from datetime import datetime, timedelta
#these two variable are for the time and 
base_time = datetime.now()
idval = random.randint(1000, 4000) 
counter=1 #global variable for brute force attack
counter2=1 # global variable for brute force attack
time=datetime.now() # global time variable for brtue force attack
log_entry_array=[]#global array for brtue froce attack
users= ["user1","user2","user3","user4"]#global array for users in brute froce attack
trusted_ips = ["192.168.1.2", "192.168.1.3", "10.0.0.1"]
untrusted_ips = ["203.0.113.5", "104.244.42.65", "198.51.100.22"]
ports = [22, 80, 443, 445, 8080, 3389, 53]
protocols = ["TCP", "UDP", "ICMP"]
attack_types = [
    {"attack": "Data Exfiltration", "description": "Outgoing connection to untrusted IP, sensitive data transfer"},
    {"attack": "Keylogging", "description": "Spyware capturing keystrokes, sending to remote server"},
    {"attack": "Unauthorized Screen Capturing", "description": "Trojan captures unauthorized screenshots"},
    {"attack": "Unwanted Monitoring", "description": "Spyware records video or audio via webcam or microphone"}
]

def Authentication_Logs():
    print("please select a option to view log files. Enter 1 for Brute Force logs, 2 for Privilege Escalation log, and 3 for Backdoor logs")
    option=int(input())
    while(option!=1 and option!=2 and option!=3):
        print("please select a option to view log files. Enter 1 for authentication logs ad 2 for firewall log types")
        option=int(input())
    if(option==1):
        Brute_Force_Attack_Logs()
    elif(option==2):
        Privilege_Escalation_Attack_Logs()
    else:
        Backdoor_Attack_Logs()
    
def Firewall_Logs():
    print("please select a option to view log files. Enter 1 for DDOS logs, 2 for Exfiltration logs, and 3 for Malware logs")
    option=int(input())
    while(option!=1 and option!=2 and option!=3):
        print("please select a option to view log files. Enter 1 for DDOS logs, 2 for Exfiltration logs, and 3 for Malware logs")
        option=int(input())
    if(option==1):
       DDOS_Attack_Logs()
    elif(option==2):
       Exfiltration_Attack_Logs()
    else:
       Malware_Attack_Logs()
    
def Brute_Force_Attack_Logs():
    log_generation() #using this to call brute force log genration function()

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
    start_time=int(input())
    time=time.replace(hour=start_time)
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

def successful_log_events():#function for successful logging of events in brute force attack
    global time
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
    print(time,users[user_index] , f"sshd[{sshd_port}]:","Accepted Password","for user5 from ",ip," port", port_number)
    file.write(f"{time} {users[user_index]} sshd{sshd_port}: , Accepted Password for user 5 from {ip} port {port_number} ")
    time=Time_Adjustment()
    print(time, users[user_index], f"sshd[{sshd_port}]:", f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    time=Time_Adjustment()
    print(time, users[user_index],f"systemd-logind[{systemd_logind}]: new session {counter} of user user5") 
    file.write(f"{time} {users[user_index]} systemd-logind[{systemd_logind}]: new session {counter} of user user 5")
    time=Time_Adjustment()
    counter+=1
    file.close()

def successful_log_events_brute_force_attack(sshd_port,ip,port_number,user_index):#using this to mimic successful login using brute force attack
    global counter
    global time
    file=open("auth.log.txt","a")
    uid=random.randint(10000,60000)
    systemd_logind=random.randint(1,32768)
    user_index=random.randint(0, len(users) - 1)
    temp=Randomization(counter,ip,sshd_port,port_number,uid,systemd_logind, users[user_index])
    log_entry_array.append(temp)
    print(time,users[user_index] , f"sshd[{sshd_port}]:","Accepted Password","for user5 from ",ip," port", port_number)
    file.write(f"{time} {users[user_index]} sshd{sshd_port}: , Accepted Password for user 5 from {ip} port {port_number} ")
    time=Time_Adjustment()
    print(time, users[user_index], f"sshd[{sshd_port}]:", f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    time=Time_Adjustment()
    print(time, users[user_index],f"systemd-logind[{systemd_logind}]: new session {counter} of user user5") 
    file.write(f"{time} {users[user_index]} systemd-logind[{systemd_logind}]: new session {counter} of user user 5")
    time=Time_Adjustment()  
    file.close()
    counter+=1
def successful_disconnection_log_Events(index):#using this to remove session of ssh
     temp=random.randint(4000, 4999)
     global time
     file=open("auth.log.txt","a")
     print(time,log_entry_array[index].user,f" sshd[{temp}]: Recieved disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user")
     file.write(f"{time} {log_entry_array[index].user} sshd[{temp}]: Received disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user")
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f" sshd[{temp}]: Disconnected from user user5 {log_entry_array[index].ip}, port {log_entry_array[index].port_number}")
     file.write(f"{time} {log_entry_array[index].user} sshd[{temp}]: Disconnected from user user 5 {log_entry_array[index].ip} port {log_entry_array[index].port_number}")
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f" sshd[{log_entry_array[index].sshd_port}]: pam_unix(sshd:session): session closed for user ubuntu5" )
     file.write(f"{time} {log_entry_array[index].user} sshd[{log_entry_array[index].sshd_port}]: pam_unix(sshd:session): session closed from user ubuntu5" )
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f"systemd-logind[{log_entry_array[index].systemd_logind}]: Session {log_entry_array[index].session_id} logged out. Waiting for process to exit")
     file.write(f"{time} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: Session {log_entry_array[index].session_id} logged out. Waiting for process to exit")
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f"systemd-logind[{log_entry_array[index].systemd_logind}]: Removed Session {log_entry_array[index].session_id}")
     file.write(f"{time} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: Removed Session {log_entry_array[index].session_id}")
     time=Time_Adjustment()
     file.close()
     log_entry_array.pop(index)

def failed_brute_force_attack(brute_force_events,successful_brute_force_probability):#using this function for generating brute force log events to mimic brute force events
    global counter2
    global time
    temp=int((successful_brute_force_probability/100)*brute_force_events)#used for checking proability of successful attacks
    file=open("auth.log.txt","a")
    user_index=random.randint(0, len(users) - 1)
    sshd_port=random.randint(4000, 4999)
    port_number=random.randint(49152, 65535)
    ip=str(random.randint(190, 194))+"."+str(random.randint(168, 172))+"."+str(random.randint(1, 255))+"."+str(random.randint(1, 255))
    print(time,users[user_index] , f"sshd[{sshd_port}]:" f"pam_unix(sshd:auth): authentication failure: logname= uid=0  euid=0 tty=ssh ruser = rhost={ip} user=user5")
    file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: "
        f"pam_unix(sshd:auth): authentication failure: logname= uid=0 euid=0 tty=ssh "
        f"ruser = rhost={ip} user=user5\n")
    time=Time_Adjustment()
    if(counter2<=temp):
        successful_log_events_brute_force_attack(sshd_port,ip,port_number,user_index)
        counter2+=1
    else:
        print(time,users[user_index] , f"sshd[{sshd_port}]: Failed password for user5 from {ip} port {port_number} ssh2")
        file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: "
            f"Failed password for user5 from {ip} port {port_number} ssh2\n")
        time=Time_Adjustment()
    file.close()
def Privilege_Escalation_Attack_Logs():
    if __name__ == "__main__":
        main()



def Backdoor_Attack_Logs():
    # Ask user for the number of log entries to generate
    num = int(input("How many log entries would you like to generate? "))
    # Generate log entries and save them to a file
    generate_log_file("simulated_auth_logs.txt", num)
    # Generate and print the specified number of log entries
    print_log = [generate_auth_log_entry() for _ in range(num)]
    for entry in print_log:
        print(entry)



def generate_auth_log_entry():
    # Current timestamp with a random offset for log realism
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    
    # Sample IP addresses and usernames
    ip_addresses = ["192.168.1.2", "192.168.1.3", "10.0.0.1"]
    usernames = ["ubuntu1", "ubuntu2", "root", "guest", "admin"]
    
    # Possible events
    events = [
        "session opened for user root",
        "session closed for user root",
        "session opened for user",
        "session closed for user"
    ]
    
    # Choosing random elements for logs
    ip_address = random.choice(ip_addresses)
    username = random.choice(usernames)
    event = random.choice(events)
    
    # Formatting the log entry similar to /var/log/auth.log pattern
    log_entry = f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]}+10:00 {ip_address} {event} ; USER={username}"
    return log_entry
    # Function to generate and write logs to a file
def generate_log_file(file_name, num_entries=100):
    with open(file_name, "w") as log_file:
        for _ in range(num_entries):
            log_entry = generate_auth_log_entry()
            log_file.write(log_entry + "\n")

def DDOS_Attack_Logs():
    # Run the main function
    if __name__ == "__main__":
        main_function()

# Function to generate log entry
def generate_log_entry(timestamp, src_ip, dst_ip, length, tos, ttl, packet_id, proto, src_port, dst_port, window, res, flags, action, log_type, color=None):
    # If color is specified (for HTML), add it to the span element
    if color:
        log_entry = f'<span style="color:{color};">{timestamp} ubuntu1-Virtual-Platform kernel: [{action}] ' \
                    f'SRC={src_ip} DST={dst_ip} LEN={length} TOS={tos} PREC=0x00 TTL={ttl} ID={packet_id} ' \
                    f'PROTO={proto} SPT={src_port} DPT={dst_port} WINDOW={window} RES={res} {flags} URGP=0  # {log_type}</span>'
    else:
        log_entry = f"{timestamp} ubuntu1-Virtual-Platform kernel: [{action}] " \
                    f"SRC={src_ip} DST={dst_ip} LEN={length} TOS={tos} PREC=0x00 TTL={ttl} ID={packet_id} " \
                    f"PROTO={proto} SPT={src_port} DPT={dst_port} WINDOW={window} RES={res} {flags} URGP=0  # {log_type}"
    return log_entry
# Function to generate timestamp
def generate_timestamp():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
# Function to generate SYN flood logs
def generate_syn_flood_logs(num_entries, packet_size):
    syn_flood_logs = []
    src_ips = [f"192.168.1.{i}" for i in range(101, 110)]
    for i in range(num_entries):
        timestamp = generate_timestamp()
        src_ip = random.choice(src_ips)
        dst_ip = "203.0.113.10"
        tos = "0x00"
        ttl = random.choice([64, 128])
        packet_id = random.randint(10000, 50000)
        proto = "TCP"
        src_port = random.randint(54000, 55000)
        dst_port = 80
        window = "65535"
        res = "0x00"
        flags = "SYN"
        action = "UFW BLOCK"
        log_entry = generate_log_entry(timestamp, src_ip, dst_ip, packet_size, tos, ttl, packet_id, proto, src_port, dst_port, window, res, flags, action, "SYN FLOOD ATTACK")
        syn_flood_logs.append(log_entry)
    return syn_flood_logs
# Function to generate normal TCP logs
def generate_normal_tcp_logs(num_entries):
    normal_tcp_logs = []
    for i in range(num_entries):
        timestamp = generate_timestamp()
        src_ip = "192.168.1.100"
        dst_ip = "203.0.113.10"
        tos = "0x00"
        ttl = "64"
        proto = "TCP"
        src_port = random.randint(54000, 55000)
        dst_port = 80
        window = "65535"
        res = "0x00"
        
        # SYN packet
        packet_id_syn = random.randint(10000, 50000)
        log_entry_syn = generate_log_entry(timestamp, src_ip, dst_ip, 60, tos, ttl, packet_id_syn, proto, src_port, dst_port, window, res, "SYN", "UFW ALLOW", "NORMAL TCP CONNECTION")
        normal_tcp_logs.append(log_entry_syn)
        
        # SYN-ACK packet
        packet_id_syn_ack = random.randint(50000, 60000)
        log_entry_syn_ack = generate_log_entry(timestamp, dst_ip, src_ip, 60, tos, ttl, packet_id_syn_ack, proto, dst_port, src_port, window, res, "SYN, ACK", "UFW ALLOW", "NORMAL TCP CONNECTION")
        normal_tcp_logs.append(log_entry_syn_ack)
        
        # ACK packet
        packet_id_ack = random.randint(60000, 70000)
        log_entry_ack = generate_log_entry(timestamp, src_ip, dst_ip, 60, tos, ttl, packet_id_ack, proto, src_port, dst_port, window, res, "ACK", "UFW ALLOW", "NORMAL TCP CONNECTION")
        normal_tcp_logs.append(log_entry_ack)

    return normal_tcp_logs
# Function to generate HTTP flood logs
def generate_http_flood_logs(num_entries, packet_size):
    http_flood_logs = []
    src_ips = [f"192.168.1.{i}" for i in range(101, 110)]
    for i in range(num_entries):
        timestamp = generate_timestamp()
        src_ip = random.choice(src_ips)
        dst_ip = "203.0.113.10"
        tos = "0x00"
        ttl = random.choice([64, 128])
        packet_id = random.randint(10000, 50000)
        proto = "TCP"
        src_port = random.randint(54000, 55000)
        dst_port = 80
        window = "65535"
        res = "0x00"
        flags = "PSH, ACK"
        action = "UFW ALLOW"
        log_entry = generate_log_entry(timestamp, src_ip, dst_ip, packet_size, tos, ttl, packet_id, proto, src_port, dst_port, window, res, flags, action, "HTTP FLOOD ATTACK")
        http_flood_logs.append(log_entry)
    return http_flood_logs
# Function to generate normal HTTP logs
def generate_normal_http_logs(num_entries):
    normal_http_logs = []
    for i in range(num_entries):
        timestamp = generate_timestamp()
        src_ip = "192.168.1.100"
        dst_ip = "203.0.113.10"
        tos = "0x00"
        ttl = "64"
        proto = "TCP"
        src_port = random.randint(54000, 55000)
        dst_port = 80
        window = "65535"
        res = "0x00"
        
        # SYN packet
        packet_id_syn = random.randint(10000, 50000)
        log_entry_syn = generate_log_entry(timestamp, src_ip, dst_ip, 60, tos, ttl, packet_id_syn, proto, src_port, dst_port, window, res, "SYN", "UFW ALLOW", "NORMAL HTTP CONNECTION")
        normal_http_logs.append(log_entry_syn)
        
        # SYN-ACK packet
        packet_id_syn_ack = random.randint(50000, 60000)
        log_entry_syn_ack = generate_log_entry(timestamp, dst_ip, src_ip, 60, tos, ttl, packet_id_syn_ack, proto, dst_port, src_port, window, res, "SYN, ACK", "UFW ALLOW", "NORMAL HTTP CONNECTION")
        normal_http_logs.append(log_entry_syn_ack)
        
        # ACK packet
        packet_id_ack = random.randint(60000, 70000)
        log_entry_ack = generate_log_entry(timestamp, src_ip, dst_ip, 60, tos, ttl, packet_id_ack, proto, src_port, dst_port, window, res, "ACK", "UFW ALLOW", "NORMAL HTTP CONNECTION")
        normal_http_logs.append(log_entry_ack)
        
        # HTTP GET request (PSH, ACK)
        packet_id_get = random.randint(70000, 80000)
        log_entry_get = generate_log_entry(timestamp, src_ip, dst_ip, 400, tos, ttl, packet_id_get, proto, src_port, dst_port, window, res, "PSH, ACK", "UFW ALLOW", "NORMAL HTTP CONNECTION")
        normal_http_logs.append(log_entry_get)
        
        # HTTP response from server
        packet_id_response = random.randint(80000, 90000)
        log_entry_response = generate_log_entry(timestamp, dst_ip, src_ip, 1500, tos, ttl, packet_id_response, proto, dst_port, src_port, window, res, "PSH, ACK", "UFW ALLOW", "NORMAL HTTP CONNECTION")
        normal_http_logs.append(log_entry_response)
        
        # FIN packet to close connection
        packet_id_fin = random.randint(90000, 100000)
        log_entry_fin = generate_log_entry(timestamp, src_ip, dst_ip, 60, tos, ttl, packet_id_fin, proto, src_port, dst_port, window, res, "FIN, ACK", "UFW ALLOW", "NORMAL HTTP CONNECTION")
        normal_http_logs.append(log_entry_fin)

    return normal_http_logs
# Function to write logs to text file
def write_logs_to_txt_file(filename, logs):
    with open(filename, 'w') as file:
        for log in logs:
            file.write(log + "\n")

# Function to write logs to HTML file
def write_logs_to_html_file(filename, logs, attack_type):
    with open(filename, 'w') as file:
        file.write('<html><body style="font-family: monospace;">\n')
        for log in logs:
            # Apply color based on attack type
            color = "blue" if "NORMAL" in log else "red"
            file.write(f'<span style="color:{color};">{log}</span><br>\n')
        file.write('</body></html>')

# Main function
def main_function():
    # Ask user for attack type and file type
    attack_type = input("Select attack type (syn flood/http flood): ").strip().lower()
    file_type = input("Select file type (text/html): ").strip().lower()
    
    # Set the appropriate example for packet size
    if attack_type == "syn flood":
        packet_size_example = "(e.g., 1024, 2048 for SYN flood)"
    elif attack_type == "http flood":
        packet_size_example = "(e.g., 400 for HTTP flood)"
    else:
        print("Invalid attack type selected.")
        return
    
    # Ask user for additional inputs
    num_normal_connections = int(input("Enter the number of normal connections: "))
    num_attack_entries = int(input(f"Enter the number of {attack_type} attack entries: "))
    packet_size = int(input(f"Enter the packet size for the {attack_type} {packet_size_example}: "))
    
    # Generate logs based on the attack type
    if attack_type == "syn flood":
        normal_logs = generate_normal_tcp_logs(num_normal_connections)
        attack_logs = generate_syn_flood_logs(num_attack_entries, packet_size)
    elif attack_type == "http flood":
        normal_logs = generate_normal_http_logs(num_normal_connections)
        attack_logs = generate_http_flood_logs(num_attack_entries, packet_size)
    else:
        print("Invalid attack type selected.")
        return
    
    # Combine and shuffle logs
    all_logs = normal_logs + attack_logs
    random.shuffle(all_logs)
    
    # Write logs to file based on file type
    if file_type == "text":
        write_logs_to_txt_file("firewall_log.txt", all_logs)
        print(f"Firewall text log file generated with {num_normal_connections} normal connections and {num_attack_entries} {attack_type} entries.")
    elif file_type == "html":
        write_logs_to_html_file("firewall_log.html", all_logs, attack_type)
        print(f"Firewall HTML log file generated with {num_normal_connections} normal connections and {num_attack_entries} {attack_type} entries.")
    else:
        print("Invalid file type selected.")





def Exfiltration_Attack_Logs():
    if __name__ == "__main__":
        main_func()
def normal_log():
    global idval, base_time

    time_increment = timedelta(seconds=random.uniform(0.5,3))
    base_time += time_increment
    des_ip = f"192.168.{random.randint(250, 250)}.{random.randint(166, 168)}"
    sr_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
    proto = random.choice(["TCP"])
    sour_port = random.randint(1024, 65535)
    destin_port = 22
    win = random.randint(200, 1000)
    flag = random.choice(["SYN", "ACK"]) 
    len = random.randint(52, 350)
    idval += 1
    ttl = random.randint(64, 124)
     
    print_log = (f"{base_time} ubuntu@user kernal: [UFW Audit] IN=eth0 OUT= SRC={sr_ip} DST={des_ip} LEN={len} TOS=0x10 TTL={ttl} PREC=0x00 PORTO={proto} ID={idval} SPT={sour_port} DPT={destin_port} WINDOW={win} RES=0x00 {flag}")

    return print_log

def exfil_log(): #this is for the malicious log
    global idval, base_time

    time_increment = timedelta(seconds=random.uniform(0.5, 3))
    base_time += time_increment
    des_ip = f"192.168.{random.randint(250, 250)}.{random.randint(166, 170)}"
    sr_ip = f"192.168.{random.randint(202, 202)}.{random.randint(137, 137)}"
    proto = random.choice(["TCP"])
    sour_port = random.randint(1024, 65535)
    destin_port = 80
    win = random.randint(200, 1000)
    flag = random.choice(["SYN", "ACK"])
    len = random.randint(1250, 5000)
    idval += 1
    ttl = random.randint(64, 124)

    print_log = (f"{base_time} ubuntu@user kernal: [UFW Audit] IN=eth0 OUT= SRC={sr_ip} DST={des_ip} LEN={len} TOS=0x10 TTL={ttl} PREC=0x00 PORTO={proto} ID={idval} SPT={sour_port} DPT={destin_port} WINDOW={win} RES=0x00 {flag}")
   
    return print_log
#this function will print the log based on the user's input
def print_log(num_entries, normalp, exfilp):
    for _ in range(num_entries):
      log_type = random.choices( 
        [normal_log, exfil_log], #this will list the functions
        [normalp, exfilp]
      )[0]

      log_entry = log_type()
      print(log_entry)
def main_func():
    try: 
       num_entries = int(input("ENTER THE TOTAL NUMBER OF LOG ENTRIES TO BE GENERATED: "))
       normalp = int(input("Enter the percentage of normal log entries to be generated, e.g 90 for 90%: "))
       exfilp = 100 - normalp

       if normalp < 0 or normalp > 100:
          print("Please enter number between 1-100: ")
          return
       
       print_log(num_entries, normalp, exfilp)

    except ValueError:
        print("Error enter again")
       



# Function to generate a random timestamp
def generate_timestamp():
    now = datetime.now()  # Get the current datetime
    random_time = now - timedelta(seconds=random.randint(0, 86400))  # Use timedelta directly
    return random_time.strftime("%m/%d/%Y %I:%M:%S %p")  # Format the datetime
# Function to generate random Event ID
def generate_event_id(success):
    if success:
        return "4672"  # Special privileges assigned (successful privilege escalation)
    else:
        return "4673"  # Sensitive privilege use (failed privilege escalation)
# Function to generate log data
def generate_log(privilege, process, admin_requested, success):
    timestamp = generate_timestamp()
    event_id = generate_event_id(success)
    event_type = "Audit Success" if success else "Audit Failure"
    
    log = f"""
Date: {timestamp}
Event Type: {event_type}
Event ID: {event_id}
Source: Microsoft-Windows-Security-Auditing
Task Category: Sensitive Privilege Use
Privilege: {privilege}
Process Used: {process}
Admin Access Requested: {admin_requested}
Description: 
    A privileged service was attempted using the {privilege} privilege.
    Process involved: {process}
    Administrative access requested: {admin_requested}
"""
    return log
# Function to generate multiple logs
def generate_logs(log_count, success_count, privilege, process, admin_requested):
    logs = []
    
    for i in range(log_count):
        success = i < success_count
        log = generate_log(privilege, process, admin_requested, success)
        logs.append(log)
        
    return logs
# Main function to get user input and generate logs
def main():
    print("Privilege Escalation Log Generator")
    
    # Request parameters from user
    log_count = int(input("Enter the number of log files to generate: "))
    success_count = int(input("Enter the number of successful attack logs: "))
    privilege = input("Enter the type of privilege being escalated (e.g., SeDebugPrivilege): ")
    process = input("Enter the process used for the attack (e.g., cmd.exe, powershell.exe): ")
    admin_requested = input("Was administrative access requested? (Yes/No): ")
    
    # Generate logs
    logs = generate_logs(log_count, success_count, privilege, process, admin_requested)
    
    # Save logs to a file
    with open("privilege_escalation_logs.txt", "w") as f:
        for log in logs:
            f.write(log)
            f.write("\n" + "="*80 + "\n")
    
    print(f"Generated {log_count} logs with {success_count} successful attack logs. Saved to 'privilege_escalation_logs.txt'.")
   

def Malware_Attack_Logs():
    
    # Generate log entries and print them to the terminal
    print_logs_to_terminal()



# Function to generate a random log entry based on user input
def generate_firewall_log_entry(attack, src_ip, dst_ip, is_successful=True):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Current timestamp
    port = random.choice(ports)
    protocol = random.choice(protocols)

    status = "ALERT" if is_successful else "INFO"
    event_type = "EVENT" if is_successful else "ATTEMPT"
    access_status = "ACCESS GRANTED" if is_successful else "ACCESS DENIED"
    
    # Log file structure with compact formatting
    log_entry = f"{timestamp} {status} FIREWALL src_ip={src_ip} dst_ip={dst_ip} port={port} protocol={protocol} {event_type}: {attack['attack']} DESCRIPTION: {attack['description']} {access_status}"
    return log_entry
# Generate and print log entries to the terminal based on user input
def print_logs_to_terminal():
    # Prompt the user for input
    attack_choice = input("Enter the type of attack (Data Exfiltration, Keylogging, Unauthorized Screen Capturing, Unwanted Monitoring): ")
    percentage_successful = float(input("Enter the percentage of successful attacks for untrusted IPs (e.g., 50): "))
    """Generate firewall log entries and print them to the terminal."""
    num_entries = 100

    # Find the attack type based on user input or fallback if not found
    attack = next((a for a in attack_types if a["attack"].lower() == attack_choice.lower()), None)
    if attack is None:
        print(f"Invalid attack type entered. Please use one of the following: {[a['attack'] for a in attack_types]}")
        return

    for _ in range(num_entries):
        # Choose a random source and destination IP
        src_ip = random.choice(untrusted_ips + trusted_ips)
        dst_ip = random.choice(trusted_ips)

        # Determine if the attack is successful or unsuccessful
        if src_ip in trusted_ips:
            # All trusted IPs are successful
            is_successful = True
        else:
            # Untrusted IPs follow the success/failure percentage
            is_successful = random.uniform(0, 100) < percentage_successful

        # Generate and print the log entry
        log_entry = generate_firewall_log_entry(attack, src_ip, dst_ip, is_successful)
        print(log_entry)



class Randomization: #using class for stroing detils for brute froce attack
    def __init__(self, session_id,ip, sshd_port, port_number, uid, systemd_logind,user):
        self.session_id = session_id
        self.ip = ip
        self.sshd_port = sshd_port
        self.port_number = port_number
        self.uid = uid
        self.systemd_logind = systemd_logind
        self.user=user
def Time_Adjustment(): # frunction for randomizing time for brute force attack
    global time
    time+=timedelta(seconds=random.randint(1,30))
    return time 
    
def start():
    print("please select a option to view log files. Enter 1 for authentication logs ad 2 for firewall log types and 3 to quit")
    option=int(input())
    while(option!= 1 and option!= 2 and option!=3):
        print("please select a option to view log files. Enter 1 for authentication logs ad 2 for firewall log types and 3 to quit")
        option=int(input())
    while(True):
        if(option==1):
            Authentication_Logs()
        elif(option==2):
            Firewall_Logs()
        elif(option==3):
            print("\n\n------Exited Program Successfully:-------")
            break
        print("\n\nplease select a option to view log files. Enter 1 for authentication logs ad 2 for firewall log types and 3 to quit")
        option=int(input())
        while(option!= 1 and option!= 2 and option!=3):
            print("please select a option to view log files. Enter 1 for authentication logs ad 2 for firewall log types and 3 to quit")
            option=int(input())
    

start()
