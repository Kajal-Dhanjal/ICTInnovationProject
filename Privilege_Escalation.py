import random
import datetime

# Function to generate a random timestamp
def generate_timestamp():
    now = datetime.datetime.now()
    random_time = now - datetime.timedelta(seconds=random.randint(0, 86400))
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

# Run the script
if __name__ == "__main__":
    main()
