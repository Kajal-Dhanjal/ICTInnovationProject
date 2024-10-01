import random
from datetime import datetime

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
def main():
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

# Run the main function
if __name__ == "__main__":
    main()
