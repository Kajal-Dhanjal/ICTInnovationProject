import unittest
from unittest.mock import patch, mock_open
from datetime import datetime, timedelta
from Integrated_logs import Time_Adjustment, successful_log_events, successful_disconnection_log_Events, failed_brute_force_attack, Randomization, generate_auth_log_entry, generate_log_file, generate_logs, generate_log, main, generate_event_id, generate_timestamp,normal_log, exfil_log, print_log, main_Function, main_func, write_logs_to_html_file,  write_logs_to_txt_file, generate_normal_http_logs,generate_http_flood_logs,generate_normal_tcp_logs,generate_syn_flood_logs,generate_log_entry, generate_firewall_log_entry
import re
import random

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
class TestLTLogs(unittest.TestCase):

    def test_time_adjustment(self):
        """Test the Time_Adjustment function by ensuring time gets adjusted."""
        global time
        time = datetime(2024, 1, 1, 12, 0, 0)  # Reset time before test

        result = Time_Adjustment()
        # Just ensure the time is modified (we don't check specific values since random is involved)
        self.assertNotEqual(result, datetime(2024, 1, 1, 12, 0, 0))

    @patch('builtins.open', new_callable=mock_open)  # Mock file writing
    def test_successful_log_events(self, mock_file):
        """Test the successful_log_events function without checking random values."""
        global time, counter, log_entry_array, users
        time = datetime(2024, 1, 1, 12, 0, 0)  # Set a fixed starting time
        counter = 1
        log_entry_array = []
        users = ["user1", "user2", "user3", "user4"]  # Ensure users list is initialized

        # Call the function
        successful_log_events()

        # Ensure that log entries were written
        self.assertTrue(mock_file().write.called, "Log file writing should have been called.")

    @patch('builtins.open', new_callable=mock_open)
    def test_successful_disconnection_log_Events(self, mock_file):
        """Test the successful_disconnection_log_Events function without checking random values."""
        global time, log_entry_array
        time = datetime(2024, 1, 1, 12, 0, 0)  # Set fixed starting time

        # Add a valid log entry to avoid IndexError
        log_entry_array = [
            Randomization(1, '192.168.2.192', 4001, 50000, 1000, 32768, 'user1')
        ]

        # Before disconnection, log_entry_array should have one entry
        self.assertEqual(len(log_entry_array), 1)

        # Call the function
        successful_disconnection_log_Events(0)


    @patch('builtins.open', new_callable=mock_open)  # Mock file writing
    def test_failed_brute_force_attack(self, mock_file):
        """Test the failed_brute_force_attack function without checking random values."""
        global time, counter2, users
        time = datetime(2024, 1, 1, 12, 0, 0)
        counter2 = 1
        users = ["user1", "user2", "user3", "user4"]  # Ensure users list is initialized

        # Call the function
        failed_brute_force_attack(10, 50)  # 50% probability for success

        # Ensure that log entries were written
        self.assertTrue(mock_file().write.called, "Log file writing should have been called.")

class TestAuthLogFunctions(unittest.TestCase):

    @patch('IT_Logs.random.choice', side_effect=["192.168.1.2", "ubuntu1", "session opened for user"])
    @patch('IT_Logs.random.randint', return_value=3600)  # Mock random.randint to control randomness
    @patch('IT_Logs.datetime')  # Mock datetime to control time-based output
    def test_generate_auth_log_entry(self, mock_datetime, mock_randint, mock_choice):
        # Mock the datetime to return a fixed value
        mock_datetime.now.return_value = datetime(2024, 10, 13, 12, 0, 0)
        
        # Call the function being tested
        log_entry = generate_auth_log_entry()

        # Expected log entry based on mocked values
        expected_timestamp = '2024-10-13T11:00:00.000+10:00'
        expected_log_entry = f"{expected_timestamp} 192.168.1.2 session opened for user ; USER=ubuntu1"

        # Verify the generated log entry matches the expected format
        self.assertEqual(log_entry, expected_log_entry)

    @patch('builtins.open', new_callable=mock_open)
    @patch('IT_Logs.generate_auth_log_entry')
    def test_generate_log_file(self, mock_generate_auth_log_entry, mock_file):
        # Mocking generate_auth_log_entry to return a specific value
        mock_generate_auth_log_entry.return_value = "Test Log Entry"

        # Call the function being tested
        generate_log_file("test_log_file.txt", 2)

        # Ensure that open was called correctly
        mock_file.assert_called_once_with("test_log_file.txt", "w")

        # Ensure that the file was written to twice (as num_entries=2)
        mock_file().write.assert_any_call("Test Log Entry\n")
        self.assertEqual(mock_file().write.call_count, 2)



class TestLogGenerationFunctions(unittest.TestCase):

   # Test Privilege Escalation Logs (mocking datetime.now and matching a pattern)
    @patch('random.randint', return_value=0)  # Mock random.randint
    @patch('datetime.datetime')  # Mock the entire datetime.datetime class
    def test_privilege_escalation_logs(self, mock_datetime, mock_randint):
        # Mock the current time to a fixed date and time
        mock_datetime.now.return_value = datetime(2024, 10, 13, 12, 0, 0)

        # Assuming generate_timestamp is called somewhere in the integrated code,
        timestamp = generate_timestamp()

        # Define the regex pattern to match the timestamp format
        pattern = r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M"

        # Assert the generated timestamp matches the expected pattern
        self.assertRegex(timestamp, pattern)


    def test_generate_event_id(self):
        self.assertEqual(generate_event_id(True), "4672")
        self.assertEqual(generate_event_id(False), "4673")

    @patch('IT_Logs.generate_timestamp', return_value="10/12/2024 12:00:00 PM")
    def test_generate_log(self, mock_timestamp):
        privilege = "SeDebugPrivilege"
        process = "cmd.exe"
        admin_requested = "Yes"
        success = True

        log = generate_log(privilege, process, admin_requested, success)

        expected_log = f"""
Date: 10/12/2024 12:00:00 PM
Event Type: Audit Success
Event ID: 4672
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

        self.assertEqual(log.strip(), expected_log.strip())  # Strip whitespace for comparison

    @patch('IT_Logs.generate_log', return_value="Test Log Entry")
    def test_generate_logs(self, mock_generate_log):
        logs = generate_logs(5, 3, "SeDebugPrivilege", "cmd.exe", "Yes")

        self.assertEqual(len(logs), 5)
        self.assertEqual(logs[0], "Test Log Entry")

    @patch('builtins.open', new_callable=mock_open)
    @patch('IT_Logs.generate_logs', return_value=["Test Log Entry", "Test Log Entry"])
    def test_main(self, mock_generate_logs, mock_file):
        # Mock user input
        with patch('builtins.input', side_effect=["2", "1", "SeDebugPrivilege", "cmd.exe", "Yes"]):
            main()
class TestExfiltrationLogFunctions(unittest.TestCase):

    @patch('IT_Logs.random.uniform', return_value=1)  # Control time increment
    @patch('IT_Logs.random.randint', side_effect=[250, 166, 0, 255, 1024, 65535, 200, 1000, 1250, 5000])
    def test_normal_log(self, mock_randint, mock_uniform):
        # Set a fixed datetime for testing
        fixed_datetime = datetime(2024, 10, 13, 12, 0, 0)
        with patch('IT_Logs.base_time', new=fixed_datetime):
            log_entry = normal_log()

            # Check that the log entry matches the expected format
            self.assertRegex(log_entry, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*\sSRC=192\.168\.0\.\d+\sDST=192\.168\.250\.166.*$")

    @patch('IT_Logs.random.uniform', return_value=1)  # Control time increment
    @patch('IT_Logs.random.randint', side_effect=[250, 170, 202, 137, 1024, 65535, 200, 1000])
    def test_exfil_log(self, mock_randint, mock_uniform):
        # Set a fixed datetime for testing
        fixed_datetime = datetime(2024, 10, 13, 12, 0, 0)
        with patch('IT_Logs.base_time', new=fixed_datetime):
            log_entry = exfil_log()

            # Check that the log entry matches the expected format
            self.assertRegex(log_entry, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*\sSRC=192\.168\.202\.137\sDST=192\.168\.250\.170.*$")

    @patch('builtins.print')  # Mock the print function to prevent actual printing
    def test_print_log(self, mock_print):
        # Call print_log with known parameters
        print_log(5, 90, 10)  # 90% normal logs, 10% exfil logs
        
        # Ensure print was called for log entries
        self.assertGreater(mock_print.call_count, 0)  # Check if print was called

    @patch('builtins.input', side_effect=["5", "90"])  # Mock inputs
    @patch('builtins.open', new_callable=mock_open)  # Mock file writing
    def test_main(self, mock_file, mock_input):
        main_func()
class TestDDoSLogFunctions(unittest.TestCase):

    @patch('IT_Logs.generate_timestamp', return_value='2024-10-13T12:00:00.000')
    def test_generate_syn_flood_logs(self, mock_timestamp):
        # Generate SYN flood logs with a specific number
        logs = generate_syn_flood_logs(5, 1024)
        self.assertEqual(len(logs), 5)
        for log in logs:
            print(log)  # Debugging: Print each log to check the format
            self.assertRegex(log, r"^2024-10-13T12:00:00.000 ubuntu1-Virtual-Platform kernel: \[UFW BLOCK\] "
                                  r"SRC=192\.168\.1\.\d{1,3} DST=203\.0\.113\.10 LEN=1024 TOS=0x00 "
                                  r"PREC=0x00 TTL=\d+ ID=\d+ PROTO=TCP SPT=\d+ DPT=80 "
                                  r"WINDOW=65535 RES=0x00 SYN URGP=0  # SYN FLOOD ATTACK$")

    @patch('IT_Logs.generate_timestamp', return_value='2024-10-13T12:00:00.000')
    def test_generate_normal_http_logs(self, mock_timestamp):
        logs = generate_normal_http_logs(3)
        self.assertEqual(len(logs), 18)
        for log in logs:
            print(log)  # Debugging: Print each log to check the format
class TestMalwareDetection(unittest.TestCase):

    @patch('random.choice')
    @patch('random.uniform', return_value=25)  # Mocking percentage for testing
    def test_generate_firewall_log_entry_success(self, mock_uniform, mock_choice):
        mock_choice.side_effect = [80, "TCP"]  # Mock port and protocol
        attack = attack_types[0]  # Choosing the first attack type
        src_ip = "203.0.113.5"
        dst_ip = "192.168.1.2"

        log_entry = generate_firewall_log_entry(attack, src_ip, dst_ip, is_successful=True)
        
        # Check if the log entry matches the expected pattern
        self.assertRegex(log_entry, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ALERT FIREWALL src_ip=203\.0\.113\.5 dst_ip=192\.168\.1\.2 port=\d+ protocol=TCP EVENT: Data Exfiltration DESCRIPTION: Outgoing connection to untrusted IP, sensitive data transfer ACCESS GRANTED$")

    @patch('random.choice')
    @patch('random.uniform', return_value=75)  # Mocking percentage for testing
    def test_generate_firewall_log_entry_failure(self, mock_uniform, mock_choice):
        mock_choice.side_effect = [80, "TCP"]  # Mock port and protocol
        attack = attack_types[0]  # Choosing the first attack type
        src_ip = "203.0.113.5"
        dst_ip = "192.168.1.2"

        log_entry = generate_firewall_log_entry(attack, src_ip, dst_ip, is_successful=False)

        # Check if the log entry matches the expected pattern
        self.assertRegex(log_entry, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} INFO FIREWALL src_ip=203\.0\.113\.5 dst_ip=192\.168\.1\.2 port=\d+ protocol=TCP ATTEMPT: Data Exfiltration DESCRIPTION: Outgoing connection to untrusted IP, sensitive data transfer ACCESS DENIED$")           

# Running all tests
if __name__ == '__main__':
    unittest.main()
