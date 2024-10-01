import random
from datetime import datetime, timedelta

# Function to generate log entries mimicking authentication logs, including privilege escalation attack
def generate_auth_log_entry():
    # Current timestamp with a random offset for log realism
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    
    # Sample IP addresses and usernames
    ip_addresses = ["192.168.1.2", "192.168.1.3", "10.0.0.1", "192.168.100.20", "172.16.0.5"]
    usernames = ["ubuntu1", "ubuntu2", "root", "guest", "admin", "unauthorized_user"]
    
    # Normal and suspicious events
    normal_events = [
        "session opened for user root",
        "session closed for user root",
        "session opened for user",
        "session closed for user",
        "password accepted for user",
        "password failed for user",
    ]
    
    escalation_events = [
        "sudo command executed",
        "failed sudo command attempt",
        "privilege escalation detected",
        "attempted access to restricted files",
        "user added to sudo group",
        "attempt to execute root command"
    ]
    
    # Choosing random elements for logs
    ip_address = random.choice(ip_addresses)
    username = random.choice(usernames)
    
    # Introducing privilege escalation behavior
    if username == "unauthorized_user" or random.random() < 0.1:  # 10% chance of privilege escalation or attack logs
        event = random.choice(escalation_events)
    else:
        event = random.choice(normal_events)
    
    # Formatting the log entry similar to /var/log/auth.log pattern
    log_entry = f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]}+10:00 {ip_address} {event} ; USER={username}"
    return log_entry

# Function to generate and write logs to a file
def generate_log_file(file_name, num_entries=100):
    with open(file_name, "w") as log_file:
        for _ in range(num_entries):
            log_entry = generate_auth_log_entry()
            log_file.write(log_entry + "\n")

# Generate 100 log entries and save them to a file
generate_log_file("simulated_auth_logs_privilege_escalation.txt", 100)

# Optionally print some log entries
print_log = [generate_auth_log_entry() for _ in range(100)]
for entry in print_log:
    print(entry)
