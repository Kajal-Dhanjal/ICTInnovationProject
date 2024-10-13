import random
from datetime import datetime, timedelta

#these two variable are for the time and 
base_time = datetime.now()
idval = random.randint(1000, 4000) 

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

def main():
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
       
if __name__ == "__main__":
   main()
