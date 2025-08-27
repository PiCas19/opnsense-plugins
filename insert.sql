-- Threat 1: SQL Injection da LAN
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '192.168.216.45', '172.16.216.20',
        'SQL Injection', 'high', 'Login bypass attempt', 0,
        "' OR '1'='1 --", 'POST');

-- Threat 2: XSS Attack da WAN
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '10.246.50.55', '172.16.216.30',
        'XSS Attack', 'medium', 'Injected JavaScript', 0,
        '<script>alert(1)</script>', 'GET');

-- Threat 3: Brute Force SSH
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '203.0.113.45', '192.168.216.10',
        'Brute Force', 'low', 'Multiple failed SSH logins', 0,
        'root:toor', 'POST');

-- Threat 4: Path Traversal
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '198.51.100.77', '172.16.216.40',
        'Path Traversal', 'medium', 'Directory traversal detected', 0,
        '../../../etc/passwd', 'GET');

-- Threat 5: Bot Activity
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '198.51.100.200', '172.16.216.50',
        'Bot Activity', 'low', 'Suspicious crawler', 0,
        'User-Agent: BadBot/1.0', 'GET');

-- Threat 6: Malware Upload
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '10.246.50.88', '172.16.216.60',
        'Malware Upload', 'high', 'Attempted file upload of malware sample', 0,
        'virus.exe', 'POST');

-- Threat 7: Command Injection
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '192.168.216.70', '172.16.216.22',
        'Command Injection', 'high', 'Command execution attempt', 0,
        'ls; cat /etc/shadow', 'GET');

-- Threat 8: Ransomware Traffic
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '203.0.113.200', '192.168.216.120',
        'Ransomware', 'critical', 'Suspicious encryption traffic detected', 0,
        'AES256 Key Exchange', 'POST');

-- Threat 9: Phishing Page
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '172.16.216.99', '10.246.50.10',
        'Phishing', 'medium', 'Fake login page hosted internally', 0,
        '<form action="fakebank.com">', 'GET');

-- Threat 10: Port Scan
INSERT INTO threats
(timestamp, source_ip, target, type, severity, description, false_positive, payload, method)
VALUES (strftime('%s','now'), '10.246.50.200', '192.168.216.80',
        'Port Scan', 'low', 'Multiple sequential ports probed', 0,
        'nmap -sS 192.168.216.80', 'TCP');
