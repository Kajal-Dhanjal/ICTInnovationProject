import unittest
from unittest.mock import patch
from datetime import datetime
from integrated import (
    generate_firewall_log_entry, 
    generate_syn_flood_logs, 
    generate_logs, 
    exfil_log, 
    failed_brute_force_attack, 
    attack_types
)

class TestMalwareDetectionFunctionality(unittest.TestCase):
    """Functional test for the malware detection function."""

    @patch('random.choice')
    @patch('random.uniform', return_value=25)  # Mocking success probability
    def test_malware_detection_success(self, mock_uniform, mock_choice):
        """Test firewall log entry for successful malware attack."""
        mock_choice.side_effect = [80, "TCP"]  # Mock port and protocol
        attack = attack_types[0]  # Use the first attack type
        src_ip = "203.0.113.5"
        dst_ip = "192.168.1.2"

        log_entry = generate_firewall_log_entry(attack, src_ip, dst_ip, is_successful=True)
        
        self.assertRegex(
            log_entry,
            r"ALERT FIREWALL .* EVENT: Data Exfiltration .* ACCESS GRANTED",
            "The log should indicate a successful malware detection event."
        )

    @patch('random.choice')
    @patch('random.uniform', return_value=75)  # Mocking failure probability
    def test_malware_detection_failure(self, mock_uniform, mock_choice):
        """Test firewall log entry for failed malware attack."""
        mock_choice.side_effect = [80, "TCP"]  # Mock port and protocol
        attack = attack_types[0]  # Use the first attack type
        src_ip = "203.0.113.5"
        dst_ip = "192.168.1.2"

        log_entry = generate_firewall_log_entry(attack, src_ip, dst_ip, is_successful=False)
        
        self.assertRegex(
            log_entry,
            r"INFO FIREWALL .* ATTEMPT: Data Exfiltration .* ACCESS DENIED",
            "The log should indicate a failed malware detection event."
        )

class TestDDoSLogsFunctionality(unittest.TestCase):
    """Functional test for DDoS log generation."""

    @patch('integrated.generate_timestamp', return_value='2024-10-13T12:00:00.000')
    def test_ddos_syn_flood_logs(self, mock_timestamp):
        """Test SYN flood log generation."""
        logs = generate_syn_flood_logs(5, 1024)  # Generate 5 logs with packet size 1024
        self.assertEqual(len(logs), 5, "There should be 5 SYN flood logs generated.")
        for log in logs:
            self.assertRegex(
                log,
                r"SYN FLOOD ATTACK",
                "Each log should indicate a SYN flood attack."
            )

class TestExfiltrationLogsFunctionality(unittest.TestCase):
    """Functional test for exfiltration logs."""

    @patch('random.uniform', return_value=1)  # Control time increment
    @patch('random.randint', side_effect=[250, 170, 202, 137, 1024, 65535, 200, 1000])
    def test_exfiltration_log(self, mock_randint, mock_uniform):
        """Test exfiltration log generation."""
        fixed_datetime = datetime(2024, 10, 13, 12, 0, 0)
        with patch('integrated.base_time', new=fixed_datetime):
            log_entry = exfil_log()

            self.assertRegex(
                log_entry,
                r"SRC=192\.168\.202\.137.*DST=192\.168\.250\.170",
                "Exfiltration log should match expected source and destination IPs."
            )

class TestBruteForceAttackFunctionality(unittest.TestCase):
    """Functional test for brute force attack logs."""

    @patch('builtins.open', new_callable=unittest.mock.mock_open)  # Mock file writing
    def test_failed_brute_force_attack(self, mock_file):
        """Test failed brute force attack log generation."""
        global time, counter2, users
        time = datetime(2024, 1, 1, 12, 0, 0)  # Set fixed time
        counter2 = 1
        users = ["user1", "user2", "user3", "user4"]  # Initialize users

        failed_brute_force_attack(10, 50)  # Test with 50% success chance

        self.assertTrue(mock_file().write.called, "Log file writing should have been called for brute force attack logs.")
        

# Running all functional tests
if __name__ == '__main__':
    unittest.main()
