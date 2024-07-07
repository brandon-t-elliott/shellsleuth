import unittest
from unittest.mock import patch, mock_open
from shellsleuth import (
    get_local_ip_addresses,
    get_ppid, 
    identify_suspicious_connections,
    get_listening_ports,
    get_established_connections,
    log,
    check_for_reverse_shells
)
from datetime import datetime

class TestShellSleuth(unittest.TestCase):
    
    @patch('subprocess.run')
    def test_get_listening_ports(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = """
        State     Recv-Q    Send-Q       Local Address:Port         Peer Address:Port    Process
        LISTEN    0         128                  *:22                      *:*        users:(("sshd",pid=1234,fd=3))
        LISTEN    0         128          192.168.1.100:80                   *:*        users:(("httpd",pid=5678,fd=4))
        LISTEN    0         128             [::1]:631                   [::]:*        users:(("cupsd",pid=9101,fd=5))
        """
        
        expected_output = [22, 80]
        
        result = get_listening_ports("/usr/bin/ss")
        self.assertEqual(result, expected_output)
    
    @patch('subprocess.run')
    def test_get_listening_ports_with_no_ports(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = """
        State     Recv-Q    Send-Q       Local Address:Port         Peer Address:Port    Process
        """
        
        expected_output = []
        
        result = get_listening_ports("/usr/bin/ss")
        self.assertEqual(result, expected_output)
    
    @patch('subprocess.run')
    def test_get_listening_ports_with_error(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 1
        mock_subprocess_run.return_value.stderr = "Error running ss"
        
        result = get_listening_ports("/usr/bin/ss")
        self.assertEqual(result, [])
    
    @patch('subprocess.run')
    def test_get_local_ip_addresses(self, mock_subprocess_run):
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = """
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
            inet 192.168.1.101/24 brd 192.168.1.255 scope global dynamic eth0
               valid_lft 86395sec preferred_lft 86395sec
            inet6 fe80::f816:3eff:fe4e:4c8a/64 scope link 
               valid_lft forever preferred_lft forever
        """
        
        expected_output = {"0.0.0.0", "[::]", "192.168.1.101", "fe80::f816:3eff:fe4e:4c8a"}
        
        result = set(get_local_ip_addresses('/usr/bin/ip'))
        self.assertEqual(result, expected_output)
    
    @patch('builtins.open', new_callable=mock_open, read_data="Name:\tsshd\nPid:\t1234\nPPid:\t5678\n")
    def test_get_ppid(self, mock_open_file):
        expected_ppid = 5678
        result = get_ppid(1234)
        self.assertEqual(result, expected_ppid)
    
    def test_get_ppid_file_not_found(self):
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = get_ppid(9999)
            self.assertIsNone(result)
    
    @patch('subprocess.run')
    def test_get_established_connections(self, mock_subprocess_run):
        # Mock the output of the ss command
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = """
        State     Recv-Q    Send-Q       Local Address:Port         Peer Address:Port    Process
        ESTAB     0         0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))
        ESTAB     0         0           192.168.1.101:80           192.168.1.103:55801  users:(("httpd",pid=5678,fd=4))
        """
        
        expected_output = [
            'ESTAB     0         0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB     0         0           192.168.1.101:80           192.168.1.103:55801  users:(("httpd",pid=5678,fd=4))'
        ]
        
        result = [line.strip() for line in get_established_connections("/usr/bin/ss")]
        self.assertEqual(result, expected_output)
    
    def test_identify_suspicious_connections(self):
        established_connections = [
            'ESTAB     0         0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3),("sshd",pid=1235,fd=3),("sshd",pid=1236,fd=3))',
            'ESTAB     0         0           192.168.1.101:80           192.168.1.103:55801  users:(("httpd",pid=5678,fd=4),("httpd",pid=5678,fd=4))',
            'ESTAB     0         0           192.168.1.101:80           192.168.1.104:55802  users:(("nc",pid=9101,fd=5),("nc",pid=9100,fd=5))'
        ]
        local_ips = ['192.168.1.101']
        listening_ports = [22, 80]
        strict = False
        
        expected_suspicious_connections = []
        expected_suspicious_ips = set()
        expected_suspicious_pid_info = {}
        
        suspicious_connections, suspicious_ips, suspicious_pid_info = identify_suspicious_connections(listening_ports, established_connections, local_ips, strict, [""])
        
        self.assertEqual(suspicious_connections, expected_suspicious_connections)
        self.assertEqual(suspicious_ips, expected_suspicious_ips)
        self.assertEqual(suspicious_pid_info, expected_suspicious_pid_info)

    @patch('shellsleuth.open', new_callable=mock_open)
    @patch('shellsleuth.print')
    @patch('shellsleuth.datetime')
    def test_log(self, mock_datetime, mock_print, mock_open_file):
        fixed_datetime = datetime(2024, 6, 14, 23, 7, 17, 883584)
        mock_datetime.now.return_value = fixed_datetime
        
        log("Test log message")
        expected_message = "2024-06-14T23:07:17.883584 - Test log message"
        mock_print.assert_called_with(expected_message)
        mock_open_file().write.assert_called_with(expected_message + "\n")

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_1(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:65111        192.168.1.104:9999   users:(("sh",pid=26997,fd=2),("sh",pid=26997,fd=1),("sh",pid=26997,fd=0))',
            'ESTAB      0        0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB      0        0           192.168.1.101:80           192.168.1.104:55803  users:(("httpd",pid=5678,fd=4))',
        ]

        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = False
        log_only = True
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.1.104")
        mock_log.assert_any_call('Connection info: ESTAB      0        0           192.168.1.101:65111        192.168.1.104:9999   users:(("sh",pid=26997,fd=2),("sh",pid=26997,fd=1),("sh",pid=26997,fd=0))')

        self.assertEqual(mock_kill_process.call_count, 0)
        
    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    @patch('shellsleuth.check_last_logged')
    def test_check_for_reverse_shells_2(self, mock_check_last_logged, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB      0        0           192.168.1.101:80           192.168.1.104:55803  users:(("httpd",pid=5678,fd=4))',
            'ESTAB      0        0           192.168.1.101:65111        192.168.1.104:9999   users:(("sh",pid=26997,fd=2),("sh",pid=26997,fd=1),("sh",pid=26997,fd=0))',
        ]

        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        mock_check_last_logged.return_value = False

        strict = False
        log_only = True
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.1.104")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 26997")
        mock_log.assert_any_call('Connection info: ESTAB      0        0           192.168.1.101:65111        192.168.1.104:9999   users:(("sh",pid=26997,fd=2),("sh",pid=26997,fd=1),("sh",pid=26997,fd=0))')

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_3(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 443, 3389]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB      0        0           192.168.1.101:443          192.168.1.104:55803  users:(("httpd",pid=5678,fd=4))',
            'ESTAB      0        0           192.168.1.101:45678        192.168.1.104:3389   users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = True
        log_only = False
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.1.104")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 67890")
        mock_log.assert_any_call("Terminated PID: 26997")
        mock_log.assert_any_call('Connection info: ESTAB      0        0           192.168.1.101:45678        192.168.1.104:3389   users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))')

        self.assertEqual(mock_kill_process.call_count, 3)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_4(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 3389]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB      0        0           192.168.1.101:443          192.168.1.104:55803  users:(("httpd",pid=5678,fd=4))',
            'ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = True
        log_only = False
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.1.104")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 67890")
        mock_log.assert_any_call("Terminated PID: 26997")
        mock_log.assert_any_call('Connection info: ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))')

        self.assertEqual(mock_kill_process.call_count, 3)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_5(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 3389]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB      0        0           192.168.1.101:443          192.168.1.104:55803  users:(("httpd",pid=5678,fd=4))',
            'ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = False
        log_only = False
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        assert not any(call == (("Reverse shell detected from IP: 192.168.1.104",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 26997",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_6(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 3389]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))',
            'ESTAB      0        0           192.168.1.101:22           192.168.1.102:55800  users:(("sshd",pid=1234,fd=3))',
            'ESTAB      0        0           192.168.1.101:443          192.168.1.104:55803  users:(("httpd",pid=5678,fd=4))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = False
        log_only = False
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        assert not any(call == (("Reverse shell detected from IP: 192.168.1.104",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 26997",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("xfreerdp",pid=26997,fd=2),("xfreerdp",pid=26997,fd=1),("xfreerdp",pid=26997,fd=0))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_7(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80, 443]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("python3",pid=26997,fd=2),("python3",pid=26997,fd=1),("python3",pid=26997,fd=0))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = False
        log_only = False
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        assert not any(call == (("Reverse shell detected from IP: 192.168.1.104",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 26997",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB      0        0           192.168.1.101:45678        192.168.1.104:80     users:(("python3",pid=26997,fd=2),("python3",pid=26997,fd=1),("python3",pid=26997,fd=0))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_8(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.1.101"]
        
        mock_get_listening_ports.return_value = [22, 80, 443]
        
        mock_get_established_connections.return_value = [
            'ESTAB      0        0           192.168.1.101:45678        192.168.1.104:443     users:(("curl",pid=26997,fd=2),("curl",pid=26997,fd=1),("curl",pid=26997,fd=0))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 67890} if pid == 26997 else set()

        strict = True
        log_only = False
        
        check_for_reverse_shells(["192.168.1.101"], strict, log_only, "/usr/bin/ss", [""])
        
        assert not any(call == (("Reverse shell detected from IP: 192.168.1.104",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 26997",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB      0        0           192.168.1.101:45678        192.168.1.104:443     users:(("curl",pid=26997,fd=2),("curl",pid=26997,fd=1),("curl",pid=26997,fd=0))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_9(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB           0               0                         192.168.102.128:51132                     192.168.102.132:9999            users:(("sh",pid=437032,fd=2),("sh",pid=437032,fd=1),("sh",pid=437032,fd=0))',
            'ESTAB           0               0                         192.168.102.128:45510                        192.168.1.5:443             users:(("code",pid=4226,fd=24))',
            'ESTAB           0               0                         192.168.102.128:5000                      192.168.102.132:41554           users:(("python3",pid=436525,fd=5))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437031} if pid == 437032 else set()

        strict = True
        log_only = False
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 437031")
        mock_log.assert_any_call("Terminated PID: 437032")
        mock_log.assert_any_call('Connection info: ESTAB           0               0                         192.168.102.128:51132                     192.168.102.132:9999            users:(("sh",pid=437032,fd=2),("sh",pid=437032,fd=1),("sh",pid=437032,fd=0))')

        self.assertEqual(mock_kill_process.call_count, 3)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_10(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("nc",pid=437146,fd=3))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        strict = False
        log_only = False
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 437145")
        mock_log.assert_any_call("Terminated PID: 437146")
        mock_log.assert_any_call('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("nc",pid=437146,fd=3))')

        self.assertEqual(mock_kill_process.call_count, 3)
        
    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_11(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("nc",pid=437146,fd=3),("nc",pid=437146,fd=0),("nc",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        strict = False
        log_only = False
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 437145")
        mock_log.assert_any_call("Terminated PID: 437146")
        mock_log.assert_any_call('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("nc",pid=437146,fd=3),("nc",pid=437146,fd=0),("nc",pid=437146,fd=1))')

        self.assertEqual(mock_kill_process.call_count, 3)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_12(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("nc",pid=437146,fd=3),("nc",pid=437146,fd=0),("nc",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        strict = True
        log_only = False
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 437145")
        mock_log.assert_any_call("Terminated PID: 437146")
        mock_log.assert_any_call('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("nc",pid=437146,fd=3),("nc",pid=437146,fd=0),("nc",pid=437146,fd=1))')

        self.assertEqual(mock_kill_process.call_count, 3)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_13(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        strict = True
        log_only = False
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Terminated PID: 12345")
        mock_log.assert_any_call("Terminated PID: 437145")
        mock_log.assert_any_call("Terminated PID: 437146")
        mock_log.assert_any_call('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))')

        self.assertEqual(mock_kill_process.call_count, 3)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_14(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: True

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        strict = False
        log_only = False
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        assert not any(call == (("Reverse shell detected from IP: 192.168.102.132",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 12345",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 437145",),) for call in mock_log.call_args_list)
        assert not any(call == (("Terminated PID: 437146",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    def test_check_for_reverse_shells_15(self, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        strict = True
        log_only = True
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 12345")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 437145")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 437146")
        mock_log.assert_any_call('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))')

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    @patch('shellsleuth.check_last_logged')
    def test_check_for_reverse_shells_16(self, mock_check_last_logged, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        mock_check_last_logged.return_value = True

        strict = True
        log_only = True
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])
        
        assert not any(call == (("Reverse shell detected from IP: 192.168.102.132",),) for call in mock_log.call_args_list)
        assert not any(call == (("Didn't terminate PID because shellsleuth is in --log-only mode: 12345",),) for call in mock_log.call_args_list)
        assert not any(call == (("Didn't terminate PID because shellsleuth is in --log-only mode: 437145",),) for call in mock_log.call_args_list)
        assert not any(call == (("Didn't terminate PID because shellsleuth is in --log-only mode: 437146",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

    @patch('shellsleuth.get_local_ip_addresses')
    @patch('shellsleuth.get_listening_ports')
    @patch('shellsleuth.get_established_connections')
    @patch('shellsleuth.search_parent_pids')
    @patch('shellsleuth.get_parent_pids')
    @patch('shellsleuth.log')
    @patch('shellsleuth.kill_process')
    @patch('shellsleuth.check_last_logged')
    def test_check_for_reverse_shells_17(self, mock_check_last_logged, mock_kill_process, mock_log, mock_get_parent_pids, mock_search_parent_pids, mock_get_established_connections, mock_get_listening_ports, mock_get_local_ip_addresses):
        mock_get_local_ip_addresses.return_value = ["192.168.102.128"]
        
        mock_get_listening_ports.return_value = [22, 80, 443, 5000]
        
        mock_get_established_connections.return_value = [
            'ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',
            'ESTAB     0      0      192.168.102.128:5000   192.168.102.132:45206  users:(("python3",pid=437136,fd=5))',
            'ESTAB     0      0      192.168.102.128:45510     192.168.1.5:443    users:(("code",pid=4226,fd=24))',
        ]
        
        mock_search_parent_pids.side_effect = lambda pid, pids: False

        mock_get_parent_pids.side_effect = lambda pid, pids: {12345, 437145} if pid == 437146 else set()

        mock_check_last_logged.return_value = False

        strict = True
        log_only = True
        
        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])

        mock_log.assert_any_call("Reverse shell detected from IP: 192.168.102.132")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 12345")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 437145")
        mock_log.assert_any_call("Didn't terminate PID because shellsleuth is in --log-only mode: 437146")
        mock_log.assert_any_call('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))')

        mock_log.reset_mock()

        mock_check_last_logged.return_value = True

        strict = True
        log_only = True

        check_for_reverse_shells(["192.168.102.128"], strict, log_only, "/usr/bin/ss", [""])

        assert not any(call == (("Reverse shell detected from IP: 192.168.102.132",),) for call in mock_log.call_args_list)
        assert not any(call == (("Didn't terminate PID because shellsleuth is in --log-only mode: 12345",),) for call in mock_log.call_args_list)
        assert not any(call == (("Didn't terminate PID because shellsleuth is in --log-only mode: 437145",),) for call in mock_log.call_args_list)
        assert not any(call == (("Didn't terminate PID because shellsleuth is in --log-only mode: 437146",),) for call in mock_log.call_args_list)
        assert not any(call == (('Connection info: ESTAB     0      0      192.168.102.128:57848  192.168.102.132:9999   users:(("sshd",pid=437146,fd=3),("sshd",pid=437146,fd=0),("sshd",pid=437146,fd=1))',),) for call in mock_log.call_args_list)

        self.assertEqual(mock_kill_process.call_count, 0)

if __name__ == '__main__':
    unittest.main()