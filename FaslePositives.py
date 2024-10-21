import random
from datetime import datetime

# Define sample IP addresses, ports, protocols, and attack types
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

# Prompt the user for input
attack_choice = input("Enter the type of attack (Data Exfiltration, Keylogging, Unauthorized Screen Capturing, Unwanted Monitoring): ")
percentage_successful = float(input("Enter the percentage of successful attacks for untrusted IPs (e.g., 50): "))

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

# Generate log entries and print them to the terminal
print_logs_to_terminal()
