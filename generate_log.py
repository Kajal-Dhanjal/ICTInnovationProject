import random 
from datetime import datetime, timedelta

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
    
    # Formatting the log entry similar to /var/log/auth.log pattern
    log_entry = f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]}+10:00 {ip_address} {event} ; USER={username}"
    return log_entry

# Function to generate and write logs to a file
def generate_log_file(file_name, num_entries=100):
    with open(file_name, "w") as log_file:
        for _ in range(num_entries):
            log_entry = generate_auth_log_entry()
            log_file.write(log_entry + "\n")

# Ask user for the number of log entries to generate
num = int(input("How many log entries would you like to generate? "))

# Generate log entries and save them to a file
generate_log_file("simulated_auth_logs.txt", num)

# Generate and print the specified number of log entries
print_log = [generate_auth_log_entry() for _ in range(num)]
for entry in print_log:
    print(entry)
