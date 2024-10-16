from tkinter import *
from PIL import ImageTk,Image
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
root= Tk()
print("Loading icon from:", os.path.abspath('Images/log.ico'))
print("Loading background from:", os.path.abspath('Images/background.jpg'))
root.title("Log Generation")
root.iconbitmap('Images/log.ico')
def background():
    global BG_img
    BG_img=ImageTk.PhotoImage(Image.open("Images/background.jpg"))
    label_BG=Label(image=BG_img).place(x=0,y=0)
    image_size=Image.open("Images/background.jpg")
    img_width,img_height=image_size.size
    root.geometry(f"{img_width}x{img_height}")
    root.resizable(False,False)
def clear_page():
    for widget in root.winfo_children():
        if isinstance(widget, Toplevel):
            # If it's a Toplevel window, destroy it
            widget.destroy()
        else:
            # Otherwise, forget the widget from the main window
            widget.place_forget()
    background()

text_display=Text(root,wrap='word', height=800, width=500)
def create_log_window():
    new_window = Toplevel(root)  # Create a new Toplevel window
    new_window.title("Log Output")
    # Create a Text widget to display logs
    log_display = Text(new_window, wrap='word', height=800, width=500)#using wrap as word so it takes word that does not et the end of line to new line
    content = text_display.get("1.0", END)  # Get all text from the global Text widget
    log_display.insert(END, content)  # Insert the content into the new Text widget
    log_display.pack()

    return log_display  # Return the Text widget

def start_menu():
    clear_page()
    text_display.delete("1.0", END)#removing any text in textbox
    Authentication_Button=Button(root,text="Authentication Logs", bg="Purple", width=15, command=Clicked_Authentication_Logs)
    Authentication_Button.place(x=950,y=150)
    Firewall_Button=Button(root,text="Firewall logs", width=15, command=Clicked_Firewall_Logs)
    Firewall_Button.place(x=950,y=200)
    buttuon_quit=Button(root,text="Exit Program", command=root.quit)
    buttuon_quit.place(x=950,y=250, width=170)


def Clicked_Authentication_Logs():
    clear_page()
    Brute_force_Attack_Button=Button(root,text="Brute Force Attack", bg="Purple", width=15, command=Clicked_Brute_Force_attack)
    Brute_force_Attack_Button.place(x=950,y=150)
    Backdoor_Button=Button(root,text="Backdoor Attack", width=15,command=Clicked_Backdoor_attack)
    Backdoor_Button.place(x=950,y=200)
    Privilege_Escalation_Button=Button(root,text="Privilege Escalation", width=15,command=Clicked_Privilege_Escalation_Attack)
    Privilege_Escalation_Button.place(x=950,y=250)
    buttuon_quit=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_quit.place(x=950,y=300)
def Clicked_Firewall_Logs():
    clear_page()
    Exfiltration_Attack_Button=Button(root,text="Exfiltration", bg="Purple", width=15,command=Clicked_Exfiltration_attack)
    Exfiltration_Attack_Button.place(x=950,y=150)
    DDoS_Attack_Button=Button(root,text="DDoS Attack", width=15,command=Clicked_DDoS_Attack)
    DDoS_Attack_Button.place(x=950,y=200)
    Malware_Attack_Button=Button(root,text="Malware", width=15,command=Clicked_Malware_Attack)
    Malware_Attack_Button.place(x=950,y=250)
    buttuon_quit=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_quit.place(x=950,y=300)
#-------------Brute-Force ttack------------
class Randomization: #using class for stroing detils for brute froce attack
    def __init__(self, session_id,ip, sshd_port, port_number, uid, systemd_logind,user):
        self.session_id = session_id
        self.ip = ip
        self.sshd_port = sshd_port
        self.port_number = port_number
        self.uid = uid
        self.systemd_logind = systemd_logind
        self.user=user
def Clicked_Brute_Force_attack():
    clear_page()
    text_display.delete("1.0", END)#removing any text in text box
    label1=Label(root,text="Proability of Brute force Events")
    label1.place(x=650,y=150)
    probability=Entry(root, width=15)
    probability.place(x=950,y=150)
    label2=Label(root,text="Probability of Successful events")
    label2.place(x=650, y=200)
    successful_brute_force_probability=Entry(root,width=15)
    successful_brute_force_probability.place(x=950,y=200)
    label3=Label(root,text="Number of logs to generate:")
    label3.place(x=650,y=250)
    log_number=Entry(root, width=15)
    log_number.place(x=950,y=250)
    label4=Label(root,text="Enter the starting time:")
    label4.place(x=650,y=300)
    start_time=Entry(root,width=15)
    start_time.place(x=950,y=300) 
    Enter=Button(root,text="Enter", width=15,command=lambda:log_generation(int(probability.get()),int(successful_brute_force_probability.get() ),int(log_number.get() ),int(start_time.get()) ))
    Enter.place(x=800,y=350)
def log_generation(var1,var2,var3,var4):
    clear_page()
    Go_Back_Brute_Force_Button=Button(root,text="Go Back",width=15,command=Clicked_Brute_Force_attack)
    Go_Back_Brute_Force_Button.place(x=950,y=150)
    buttuon_Main_Menu=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_Main_Menu.place(x=950,y=200)
    global time
    disconnection_check=False
    probability=var1
    successful_brute_force_probability=var2 
    
    log_number=var3
    start_time=var4
    time=time.replace(hour=start_time)
    temp= int((probability/100)*log_number) #used to  determine probability of brute force attack
    brute_force_attack_logs= random.sample(range(log_number), temp)#sets unique number from range
    #print(brute_force_attack_logs)
    global text_display
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
    create_log_window()
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
    message=f"{time} {users[user_index]} sshd[{sshd_port}]: Accepted Password for user 5 from {ip} port {port_number}\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    print(time, users[user_index], f"sshd[{sshd_port}]:", f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    message=f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    print(time, users[user_index],f"systemd-logind[{systemd_logind}]: new session {counter} of user user5") 
    file.write(f"{time} {users[user_index]} systemd-logind[{systemd_logind}]: new session {counter} of user user 5")
    message=f"{time} {users[user_index]} systemd-logind[{systemd_logind}]: new session {counter} of user user 5\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    counter+=1
    file.close()
def successful_log_events_brute_force_attack(sshd_port,ip,port_number,user_index):#using this to mimic successful login using brute force attack
    global counter
    global text_display
    global time
    file=open("auth.log.txt","a")
    uid=random.randint(10000,60000)
    systemd_logind=random.randint(1,32768)
    user_index=random.randint(0, len(users) - 1)
    temp=Randomization(counter,ip,sshd_port,port_number,uid,systemd_logind, users[user_index])
    log_entry_array.append(temp)
    print(time,users[user_index] , f"sshd[{sshd_port}]:","Accepted Password","for user5 from ",ip," port", port_number)
    file.write(f"{time} {users[user_index]} sshd{sshd_port}: , Accepted Password for user 5 from {ip} port {port_number} ")
    message=f"{time} {users[user_index]} sshd[{sshd_port}]: Accepted Password for user 5 from {ip} port {port_number}\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    print(time, users[user_index], f"sshd[{sshd_port}]:", f"pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)")
    message=f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:session): session opened for user ubuntu5(uid={uid}) by ubuntu5(uid=0)\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    print(time, users[user_index],f"systemd-logind[{systemd_logind}]: new session {counter} of user user5") 
    file.write(f"{time} {users[user_index]} systemd-logind[{systemd_logind}]: new session {counter} of user user 5")
    message=f"{time} {users[user_index]} systemd-logind[{systemd_logind}]: new session {counter} of user user 5\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    counter+=1
def successful_disconnection_log_Events(index):#using this to remove session of ssh
     temp=random.randint(4000, 4999)
     global time
     global text_display
     file=open("auth.log.txt","a")
     print(time,log_entry_array[index].user,f" sshd[{temp}]: Recieved disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user")
     file.write(f"{time} {log_entry_array[index].user} sshd[{temp}]: Received disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user")
     message=f"{time} {log_entry_array[index].user} sshd[{temp}]: Received disconnect from {log_entry_array[index].ip} port {log_entry_array[index].port_number}:11: disconnected by user\n"
     text_display.insert(END,message)
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f" sshd[{temp}]: Disconnected from user user5 {log_entry_array[index].ip}, port {log_entry_array[index].port_number}")
     file.write(f"{time} {log_entry_array[index].user} sshd[{temp}]: Disconnected from user user 5 {log_entry_array[index].ip} port {log_entry_array[index].port_number}")
     message=f"{time} {log_entry_array[index].user} sshd[{temp}]: Disconnected from user user 5 {log_entry_array[index].ip} port {log_entry_array[index].port_number}\n"
     text_display.insert(END,message)
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f" sshd[{log_entry_array[index].sshd_port}]: pam_unix(sshd:session): session closed for user ubuntu5" )
     file.write(f"{time} {log_entry_array[index].user} sshd[{log_entry_array[index].sshd_port}]: pam_unix(sshd:session): session closed from user ubuntu5" )
     message=f"{time} {log_entry_array[index].user} sshd[{log_entry_array[index].sshd_port}]: pam_unix(sshd:session): session closed from user ubuntu5\n"
     text_display.insert(END,message)
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f"systemd-logind[{log_entry_array[index].systemd_logind}]: Session {log_entry_array[index].session_id} logged out. Waiting for process to exit")
     file.write(f"{time} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: Session {log_entry_array[index].session_id} logged out. Waiting for process to exit")
     message=f"{time} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: Session {log_entry_array[index].session_id} logged out. Waiting for process to exit\n"
     text_display.insert(END,message)
     time=Time_Adjustment()
     print(time,log_entry_array[index].user,f"systemd-logind[{log_entry_array[index].systemd_logind}]: Removed Session {log_entry_array[index].session_id}")
     file.write(f"{time} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: Removed Session {log_entry_array[index].session_id}")
     message=f"{time} {log_entry_array[index].user} systemd-logind[{log_entry_array[index].systemd_logind}]: Removed Session {log_entry_array[index].session_id}\n"
     text_display.insert(END,message)
     time=Time_Adjustment()
     file.close()
     log_entry_array.pop(index)
def failed_brute_force_attack(brute_force_events,successful_brute_force_probability):#using this function for generating brute force log events to mimic brute force events
    global counter2
    global time
    global text_display
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
    message=f"{time} {users[user_index]} sshd[{sshd_port}]: pam_unix(sshd:auth): authentication failure: logname= uid=0 euid=0 tty=ssh ruser = rhost={ip} user=user5\n"
    text_display.insert(END,message)
    time=Time_Adjustment()
    if(counter2<=temp):
        successful_log_events_brute_force_attack(sshd_port,ip,port_number,user_index)
        counter2+=1
    else:
        print(time,users[user_index] , f"sshd[{sshd_port}]: Failed password for user5 from {ip} port {port_number} ssh2")
        file.write(f"{time} {users[user_index]} sshd[{sshd_port}]: "
            f"Failed password for user5 from {ip} port {port_number} ssh2\n")
        message=f"{time} {users[user_index]} sshd[{sshd_port}]: Failed password for user5 from {ip} port {port_number} ssh2\n"
        text_display.insert(END,message)
        time=Time_Adjustment()
    file.close()
def Time_Adjustment(): # frunction for randomizing time for brute force attack
    global time
    time+=timedelta(seconds=random.randint(1,30))
    return time 
#--------------Backdoor-Attack-------------------
def Clicked_Backdoor_attack():
    clear_page()
    label1=Label(root,text="Please Enter the number of logs to Generate:")
    label1.place(x=650,y=150)
    num=Entry(root,width=15)
    num.place(x=950,y=150)
    Enter=Button(root,text="Enter", width=15,command=lambda:(Number_of_logs_to_Generate(int(num.get()))))
    Enter.place(x=800,y=200)
    

def Number_of_logs_to_Generate(num):
    clear_page()
    Go_Back_Backdoor_Button=Button(root,text="Go Back",width=15,command=Clicked_Backdoor_attack)
    Go_Back_Backdoor_Button.place(x=950,y=150)
    buttuon_Main_Menu=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_Main_Menu.place(x=950,y=200)
    # Generate log entries and save them to a file
    generate_log_file("simulated_auth_logs.txt", num)
    # Generate and print the specified number of log entries
    print_log = [generate_auth_log_entry() for _ in range(num)]
    for entry in print_log:
        print(entry)
    
    
    
# Function to generate log entries mimicking authentication logs
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
    global text_display
    # Formatting the log entry similar to /var/log/auth.log pattern
    log_entry = f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]}+10:00 {ip_address} {event} ; USER={username}"
    text_display.insert(END,f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]}+10:00 {ip_address} {event} ; USER={username}\n") #stroing the otput in text widget which will later be passed to new windoww function to display log outputs on interface
    return log_entry

# Function to generate and write logs to a file
def generate_log_file(file_name, num_entries=100):
    with open(file_name, "w") as log_file:
        for _ in range(num_entries):
            log_entry = generate_auth_log_entry()
            log_file.write(log_entry + "\n")
    create_log_window()





#-----------------------Privilege_Escalation_Attack----------------------
def Clicked_Privilege_Escalation_Attack():
    clear_page()
    text_display.delete("1.0", END)#removing any text in text box
    label0=Label(root,text="Privilege Escalation Log Generator")
    label0.place(x=470,y=50)
    label1=Label(root,text="Enter the number of log files to generate: ")
    label1.place(x=540,y=150)
    log_count=Entry(root,width=15)
    log_count.place(x=950,y=150)
    label2=Label(root,text="Enter the number of successful attack logs:")
    label2.place(x=540,y=200)
    success_count=Entry(root,width=15)
    success_count.place(x=950,y=200)
    label3=Label(root,text="Enter the type of privilege being escalated (e.g., SeDebugPrivilege): ")
    label3.place(x=440,y=250)
    privilege=Entry(root,width=15)
    privilege.place(x=950,y=250)
    label4=Label(root,text="Enter the process used for the attack (e.g., cmd.exe, powershell.exe): ")
    label4.place(x=440,y=300)
    process=Entry(root,width=15)
    process.place(x=950,y=300)
    label5=Label(root,text="Was administrative access requested? (Yes/No): ")
    label5.place(x=540,y=350)
    admin_requested=Entry(root,width=15)
    admin_requested.place(x=950,y=350)
    label6=Button(root,text="Enter",width=15,command=lambda:Privilege_Escalation_Main(int(log_count.get()), int(success_count.get()), str(privilege.get()), str(process.get()), str(admin_requested.get())))
    label6.place(x=850,y=400)
    
def generate_timestamp():
    now = datetime.now()
    random_time = now - timedelta(seconds=random.randint(0, 86400))
    return random_time.strftime("%m/%d/%Y %I:%M:%S %p")

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
def Privilege_Escalation_Main(log_count,success_count,privilege,process,admin_requested):
    # Generate logs
    logs = generate_logs(log_count, success_count, privilege, process, admin_requested)
    clear_page()
    Go_Back_Privilege_Attack_Button=Button(root,text="Go Back",width=15,command=Clicked_Privilege_Escalation_Attack)
    Go_Back_Privilege_Attack_Button.place(x=950,y=150)
    buttuon_Main_Menu=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_Main_Menu.place(x=950,y=200)
    # Save logs to a file
    with open("privilege_escalation_logs.txt", "w") as f:
        for log in logs:
            f.write(log)
            text_display.insert(END,log)
            f.write("\n" + "="*80 + "\n")
            text_display.insert(END,"\n" + "="*80 + "\n")
    
    
    print(f"Generated {log_count} logs with {success_count} successful attack logs. Saved to 'privilege_escalation_logs.txt'.")
    text_display.insert(END,f"Generated {log_count} logs with {success_count} successful attack logs. Saved to 'privilege_escalation_logs.txt'.\n")
    create_log_window()


#-----------------------------------------GUI for Firewall logs based Attacks----------------------------------------


def Clicked_Exfiltration_attack():
    clear_page()
    text_display.delete("1.0", END)#removing any text in textbox
    label1=Label(root,text="ENTER THE TOTAL NUMBER OF LOG ENTRIES TO BE GENERATED:")
    label1.place(x=450,y=150)
    num_entries=Entry(root,width=15)
    num_entries.place(x=950,y=150)
    label2=Label(root,text="Enter the percentage of normal log entries to be generated, e.g 90 for 90%:")
    label2.place(x=400,y=200)
    normalp=Entry(root,width=15)
    normalp.place(x=950,y=200)
    button=Button(root,text="Enter",width=15,command=lambda:Exfiltration_Attack_main(int(num_entries.get()),int(normalp.get())))
    button.place(x=850,y=250)


def normal_log():
    global idval, base_time

    time_increment = timedelta(seconds=random.uniform(0.5,3))
    base_time += time_increment
    des_ip = f"192.168.{random.randint(250, 250)}.{random.randint(166, 168)}"
    sr_ip = f"192.168.{random.randint(202, 202)}.{random.randint(137, 137)}"
    proto = random.choice(["TCP"])
    sour_port = random.randint(1024, 65535)
    destin_port = 22
    win = random.randint(200, 1000)
    flag = random.choice(["SYN", "ACK"]) 
    len = random.randint(52, 350)
    idval += 1
    ttl = random.randint(64, 124)
     
    print_log = (f"{base_time} ubuntu@user kernal: [UFW Audit] IN=eth0 OUT= SRC={sr_ip} DST={des_ip} LEN={len} TOS=0x10 TTL={ttl} PREC=0x00 PORTO={proto} ID={idval} SPT={sour_port} DPT={destin_port} WINDOW={win} RES=0x00 {flag}")
    text_display.insert(END,f"{base_time} ubuntu@user kernal: [UFW Audit] IN=eth0 OUT= SRC={sr_ip} DST={des_ip} LEN={len} TOS=0x10 TTL={ttl} PREC=0x00 PORTO={proto} ID={idval} SPT={sour_port} DPT={destin_port} WINDOW={win} RES=0x00 {flag}\n")
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
    text_display.insert(END,f"{base_time} ubuntu@user kernal: [UFW Audit] IN=eth0 OUT= SRC={sr_ip} DST={des_ip} LEN={len} TOS=0x10 TTL={ttl} PREC=0x00 PORTO={proto} ID={idval} SPT={sour_port} DPT={destin_port} WINDOW={win} RES=0x00 {flag}\n")
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

def Exfiltration_Attack_main(num_entries,normalp):
    clear_page()
    Go_Back_Exfiltration_Attack_Button=Button(root,text="Go Back",width=15,command=Clicked_Exfiltration_attack)
    Go_Back_Exfiltration_Attack_Button.place(x=950,y=150)
    buttuon_Main_Menu=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_Main_Menu.place(x=950,y=200)
    try: 
       #num_entries = int(input("ENTER THE TOTAL NUMBER OF LOG ENTRIES TO BE GENERATED: "))
       #normalp = int(input("Enter the percentage of normal log entries to be generated, e.g 90 for 90%: "))
       exfilp = 100 - normalp

       '''if normalp < 0 or normalp > 100:
          print("Please enter number between 1-100: ")
          return'''
       
       print_log(num_entries, normalp, exfilp)

    except ValueError:
        print("Error enter again")
    create_log_window()
       





#-------------------------------DDoS Attack------------------------

def Clicked_DDoS_Attack():
    clear_page()
    packet_size_example=0
    text_display.delete("1.0", END)#removing any text in textbox
    label1=Label(root,text="Select attack type (syn flood/http flood):")
    label1.place(x=570,y=150)
    attack_type=Entry(root,width=15)
    attack_type.place(x=950,y=150)
    label2=Label(root,text="Select file type (text/html): ")
    label2.place(x=650,y=200)
    file_type=Entry(root,width=15)
    file_type.place(x=950,y=200)
    button=Button(root,text="Enter",width=15,command=lambda:DDoS_Input_First_Part(str(attack_type.get()),str(file_type.get())))
    button.place(x=800,y=250)

def DDoS_Input_First_Part(attack_type,file_type):
    clear_page()
    if str(attack_type) == "syn flood":
        packet_size_example = "(e.g., 1024, 2048 for SYN flood)"
    elif str(attack_type) == "http flood":
        packet_size_example = "(e.g., 400 for HTTP flood)"
    else:
        print("Invalid attack type selected.")
        Clicked_DDoS_Attack()
        return
    label3=Label(root,text="Enter the number of normal connections: ")
    label3.place(x=560,y=150)
    num_normal_connections=Entry(root,width=15)
    num_normal_connections.place(x=950,y=150)
    label4=Label(root,text=f"Enter the number of {attack_type} attack entries: ")
    label4.place(x=540,y=200)
    num_attack_entries=Entry(root,width=15)
    num_attack_entries.place(x=950,y=200)
    label5=Label(root,text=f"Enter the packet size for the {attack_type} {packet_size_example}: ")
    label5.place(x=500,y=250)
    packet_size=Entry(root,width=15)
    packet_size.place(x=950,y=250)
    button=Button(root,text="Enter",command=lambda:DDOS_Attack_main(attack_type,file_type,int(num_normal_connections.get()),int(num_attack_entries.get()),int(packet_size.get())))
    button.place(x=800,y=300,)


    
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
            text_display.insert(END,log + "\n")

# Function to write logs to HTML file
def write_logs_to_html_file(filename, logs, attack_type):
    with open(filename, 'w') as file:
        file.write('<html><body style="font-family: monospace;">\n')
        text_display.insert(END,'<html><body style="font-family: monospace;">\n')
        for log in logs:
            # Apply color based on attack type
            color = "blue" if "NORMAL" in log else "red"
            file.write(f'<span style="color:{color};">{log}</span><br>\n')
            #text_display.insert(END,f'<span style="color:{color};">{log}</span><br>\n,')
        file.write('</body></html>')
        #text_display.insert(END,'</body></html>')

# Main function
def DDOS_Attack_main(attack_type,file_type,num_normal_connections,num_attack_entries,packet_size):
    # Ask user for attack type and file type
    #attack_type = input("Select attack type (syn flood/http flood): ").strip().lower()
    #file_type = input("Select file type (text/html): ").strip().lower()
    clear_page()
    Go_Back_DDoS_Attack_Button=Button(root,text="Go Back",width=15,command=Clicked_DDoS_Attack)
    Go_Back_DDoS_Attack_Button.place(x=950,y=150)
    buttuon_Main_Menu=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_Main_Menu.place(x=950,y=200)
    # Set the appropriate example for packet size
    '''if attack_type == "syn flood":
        packet_size_example = "(e.g., 1024, 2048 for SYN flood)"
    elif attack_type == "http flood":
        packet_size_example = "(e.g., 400 for HTTP flood)"
    else:
        print("Invalid attack type selected.")
        return
    '''
    # Ask user for additional inputs
    #num_normal_connections = int(input("Enter the number of normal connections: "))
    #num_attack_entries = int(input(f"Enter the number of {attack_type} attack entries: "))
    #packet_size = int(input(f"Enter the packet size for the {attack_type} {packet_size_example}: "))
    
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
        text_display.insert(END,f"Firewall text log file generated with {num_normal_connections} normal connections and {num_attack_entries} {attack_type} entries.")

    elif file_type == "html":
        write_logs_to_html_file("firewall_log.html", all_logs, attack_type)
        print(f"Firewall HTML log file generated with {num_normal_connections} normal connections and {num_attack_entries} {attack_type} entries.")
        text_display.insert(END,f"Firewall HTML log file generated with {num_normal_connections} normal connections and {num_attack_entries} {attack_type} entries.")

    else:
        print("Invalid file type selected.")
        
    create_log_window()




#-----------------------Malware -----------------




def Clicked_Malware_Attack():
    clear_page()
    text_display.delete("1.0", END)#removing any text in textbox
    label1=Label(root,text="Enter the type of attack (Data Exfiltration, Keylogging, Unauthorized Screen Capturing, Unwanted Monitoring): ")
    label1.place(x=200,y=150)
    attack_choice=Entry(root,width=15)
    attack_choice.place(x=950,y=150)
    label2=Label(root,text="Enter the percentage of successful attacks for untrusted IPs (e.g., 50): ")
    label2.place(x=400,y=200)
    percentage_successful=Entry(root,width=15)
    percentage_successful.place(x=950,y=200)
    button=Button(root,text="Enter",width=15,command=lambda: print_logs_to_terminal(str(attack_choice.get()),int(percentage_successful.get())))
    button.place(x=800,y=250)

#attack_choice = input("Enter the type of attack (Data Exfiltration, Keylogging, Unauthorized Screen Capturing, Unwanted Monitoring): ")
#percentage_successful = float(input("Enter the percentage of successful attacks for untrusted IPs (e.g., 50): "))

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
    text_display.insert(END,f"{timestamp} {status} FIREWALL src_ip={src_ip} dst_ip={dst_ip} port={port} protocol={protocol} {event_type}: {attack['attack']} DESCRIPTION: {attack['description']} {access_status}")
    return log_entry

# Generate and print log entries to the terminal based on user input
def print_logs_to_terminal(attack_choice,percentage_successful):
    """Generate firewall log entries and print them to the terminal."""
    clear_page()
    Go_Back_Malware_Attack_Button=Button(root,text="Go Back",width=15,command=Clicked_Malware_Attack)
    Go_Back_Malware_Attack_Button.place(x=950,y=150)
    buttuon_Main_Menu=Button(root,text="Main Menu", command=start_menu,width=15 )
    buttuon_Main_Menu.place(x=950,y=200)
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
        
    create_log_window()



start_menu()


root.mainloop()