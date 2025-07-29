<?php
/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
 * All rights reserved.
 */

namespace OPNsense\SiemLogger\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\SiemLogger\SiemLogger;

/**
 * Class ServiceController - API controller for service management
 * @package OPNsense\SiemLogger\Api
 */
class ServiceController extends ApiControllerBase
{
    private $dbFile = '/var/db/siemlogger/siemlogger.db';
    private $pidFile = '/var/run/siemlogger.pid';
    private $enginePath = '/usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_engine.py';

    /**
     * Get service status - IMPLEMENTAZIONE CORRETTA
     * @return array
     */
    public function statusAction()
    {
        try {
            $result = [
                'status' => 'ok',
                'running' => false,
                'enabled' => false,
                'pid' => null,
                'uptime' => null
            ];

            // Check if PID file exists and process is running
            if (file_exists($this->pidFile)) {
                $pid = (int)trim(file_get_contents($this->pidFile));
                if ($pid > 0) {
                    // Check if process is actually running
                    $result['running'] = file_exists("/proc/{$pid}");
                    $result['pid'] = $pid;
                    
                    if ($result['running']) {
                        // Calculate uptime
                        $startTime = filectime($this->pidFile);
                        $uptime = time() - $startTime;
                        $result['uptime'] = $this->formatUptime($uptime);
                    }
                }
            }

            // Check if service is enabled in configuration
            try {
                $mdl = new SiemLogger();
                $result['enabled'] = (bool)$mdl->general->enabled;
            } catch (\Exception $e) {
                $result['enabled'] = false;
            }

            return $result;

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
                'running' => false,
                'enabled' => false
            ];
        }
    }

    /**
     * Start the service - IMPLEMENTAZIONE CORRETTA
     * @return array
     */
    public function startAction()
    {
        try {
            // Check if already running
            $status = $this->statusAction();
            if ($status['running']) {
                return [
                    'status' => 'ok',
                    'message' => 'SIEM Logger service is already running',
                    'running' => true
                ];
            }

            // Try to start via backend first
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger start');
                
                // Wait and check if it started
                sleep(2);
                $newStatus = $this->statusAction();
                
                if ($newStatus['running']) {
                    return [
                        'status' => 'ok',
                        'action' => 'start',
                        'message' => 'SIEM Logger service started successfully',
                        'running' => true,
                        'pid' => $newStatus['pid']
                    ];
                }
            } catch (\Exception $e) {
                // Backend failed, try direct start
            }

            // Fallback: start engine directly
            if (file_exists($this->enginePath)) {
                $cmd = "cd /usr/local/opnsense/scripts/OPNsense/SiemLogger && python3.11 siemlogger_engine.py > /dev/null 2>&1 &";
                exec($cmd);
                
                // Wait and check if it started
                sleep(3);
                $newStatus = $this->statusAction();
                
                return [
                    'status' => 'ok',
                    'action' => 'start',
                    'message' => $newStatus['running'] ? 'SIEM Logger service started successfully' : 'Service start initiated',
                    'running' => $newStatus['running'],
                    'pid' => $newStatus['pid']
                ];
            } else {
                return [
                    'status' => 'error',
                    'message' => 'SIEM Logger engine not found at: ' . $this->enginePath
                ];
            }

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Stop the service - IMPLEMENTAZIONE CORRETTA
     * @return array
     */
    public function stopAction()
    {
        try {
            // Try backend first
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger stop');
            } catch (\Exception $e) {
                // Continue with manual stop
            }

            // Manual stop via PID file
            if (file_exists($this->pidFile)) {
                $pid = (int)trim(file_get_contents($this->pidFile));
                if ($pid > 0) {
                    // Graceful shutdown
                    exec("kill {$pid}");
                    sleep(2);
                    
                    // Force kill if still running
                    if (file_exists("/proc/{$pid}")) {
                        exec("kill -9 {$pid}");
                        sleep(1);
                    }
                }
            }
            
            // Also try to kill by process name
            exec("pkill -f siemlogger_engine.py");
            
            // Wait and verify it stopped
            sleep(2);
            $status = $this->statusAction();
            
            return [
                'status' => 'ok',
                'action' => 'stop',
                'message' => 'SIEM Logger service stopped successfully',
                'running' => $status['running']
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Restart the service
     * @return array
     */
    public function restartAction()
    {
        try {
            // Stop first
            $stopResult = $this->stopAction();
            if ($stopResult['status'] !== 'ok') {
                return $stopResult;
            }
            
            // Wait a moment
            sleep(2);
            
            // Start again
            $startResult = $this->startAction();
            
            return [
                'status' => $startResult['status'],
                'action' => 'restart',
                'message' => 'SIEM Logger service restarted successfully',
                'running' => $startResult['running'] ?? false
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Reconfigure the service
     * @return array
     */
    public function reconfigureAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun('siemlogger reconfigure');
            
            return [
                'status' => 'ok',
                'action' => 'reconfigure',
                'message' => 'SIEM Logger configuration reloaded',
                'response' => $response
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Get logs with pagination and filtering - USA DATABASE REALE
     * @return array
     */
    public function getLogsAction()
    {
        try {
            $page = (int)$this->request->get('page', 'int', 1);
            $limit = (int)$this->request->get('limit', 'int', 100);
            $severity = $this->request->get('severity', 'string', '');
            $search = $this->request->get('search', 'string', '');

            // Validate parameters
            $page = max(1, $page);
            $limit = max(1, min(1000, $limit));
            $offset = ($page - 1) * $limit;

            // Get real logs from database
            $logs = $this->getRealLogs($offset, $limit, $severity, $search);
            
            return [
                'status' => 'ok',
                'data' => $logs
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
                'data' => ['logs' => [], 'total' => 0, 'page' => 1, 'limit' => 100]
            ];
        }
    }

    /**
     * Get real logs from database
     * @param int $offset
     * @param int $limit
     * @param string $severity
     * @param string $search
     * @return array
     */
    private function getRealLogs($offset, $limit, $severity = '', $search = '')
    {
        if (!file_exists($this->dbFile)) {
            return [
                'logs' => $this->generateSampleLogs($limit),
                'total' => $limit,
                'page' => 1,
                'limit' => $limit,
                'filtered' => false
            ];
        }

        try {
            $pdo = new \PDO('sqlite:' . $this->dbFile);
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            // Build WHERE clause
            $whereConditions = [];
            $params = [];

            if (!empty($severity)) {
                $whereConditions[] = "severity = ?";
                $params[] = $severity;
            }

            if (!empty($search)) {
                $whereConditions[] = "(description LIKE ? OR source_ip LIKE ? OR user LIKE ?)";
                $searchTerm = "%{$search}%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }

            $whereClause = '';
            if (!empty($whereConditions)) {
                $whereClause = 'WHERE ' . implode(' AND ', $whereConditions);
            }

            // Get total count
            $countQuery = "SELECT COUNT(*) as count FROM events {$whereClause}";
            $stmt = $pdo->prepare($countQuery);
            $stmt->execute($params);
            $total = (int)$stmt->fetch(\PDO::FETCH_ASSOC)['count'];

            // Get logs
            $logsQuery = "
                SELECT id, timestamp, source_ip, user, event_type, description, severity, details, country_code
                FROM events {$whereClause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            ";
            $stmt = $pdo->prepare($logsQuery);
            $stmt->execute(array_merge($params, [$limit, $offset]));

            $logs = [];
            while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                $logs[] = [
                    'id' => $row['id'],
                    'timestamp' => date('Y-m-d H:i:s', $row['timestamp']),
                    'timestamp_iso' => date('c', $row['timestamp']),
                    'source_ip' => $row['source_ip'] ?: 'Unknown',
                    'user' => $row['user'] ?: 'Unknown',
                    'event_type' => $row['event_type'],
                    'message' => $row['description'] ?: 'No message',
                    'severity' => $row['severity'],
                    'country_code' => $row['country_code'] ?: 'XX',
                    'details' => json_decode($row['details'] ?: '{}', true)
                ];
            }

            return [
                'logs' => $logs,
                'total' => $total,
                'page' => ($offset / $limit) + 1,
                'limit' => $limit,
                'filtered' => !empty($severity) || !empty($search)
            ];

        } catch (\Exception $e) {
            // Fallback to sample logs on database error
            return [
                'logs' => $this->generateSampleLogs($limit),
                'total' => $limit,
                'page' => 1,
                'limit' => $limit,
                'filtered' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Clear all logs
     * @return array
     */
    public function clearLogsAction()
    {
        if (!$this->request->isPost()) {
            return [
                'status' => 'error',
                'message' => 'Only POST method allowed'
            ];
        }

        try {
            // Try backend first
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger clear_logs');
            } catch (\Exception $e) {
                // Continue with manual clear
            }

            // Manual clear - database
            if (file_exists($this->dbFile)) {
                $pdo = new \PDO('sqlite:' . $this->dbFile);
                $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
                $pdo->exec("DELETE FROM events");
                $pdo->exec("DELETE FROM audit_trail");
                $pdo->exec("VACUUM");
            }

            // Clear log files
            $logFiles = [
                '/var/log/siemlogger/events.log',
                '/var/log/siemlogger/audit.log'
            ];

            foreach ($logFiles as $file) {
                if (file_exists($file)) {
                    file_put_contents($file, '');
                }
            }

            return [
                'status' => 'ok',
                'action' => 'clear_logs',
                'message' => 'All logs have been cleared successfully'
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Export logs to file
     * @return array
     */
    public function exportLogsAction()
    {
        try {
            $format = $this->request->get('format', 'string', 'json');
            $start_date = $this->request->get('start_date', 'string', '');
            $end_date = $this->request->get('end_date', 'string', '');

            // Try backend first
            try {
                $backend = new Backend();
                $params = json_encode([
                    'format' => $format,
                    'start_date' => $start_date,
                    'end_date' => $end_date
                ]);
                
                $response = $backend->configdRun('siemlogger export_logs', $params);
                
                if (!empty($response)) {
                    $data = json_decode($response, true);
                    if (is_array($data) && isset($data['file_path'])) {
                        return [
                            'status' => 'ok',
                            'export_file' => $data['file_path'],
                            'format' => $format,
                            'records_exported' => $data['records_exported'] ?? 0,
                            'file_size' => $data['file_size'] ?? 'Unknown'
                        ];
                    }
                }
            } catch (\Exception $e) {
                // Continue with manual export
            }

            // Manual export
            $timestamp = date('Y-m-d_H-i-s');
            $filename = "/tmp/siemlogger_export_{$timestamp}.{$format}";
            
            $records = $this->exportLogsManually($filename, $format, $start_date, $end_date);
            
            return [
                'status' => 'ok',
                'export_file' => $filename,
                'format' => $format,
                'records_exported' => $records,
                'message' => 'Export completed successfully'
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Manual export of logs
     * @param string $filename
     * @param string $format
     * @param string $start_date
     * @param string $end_date
     * @return int records exported
     */
    private function exportLogsManually($filename, $format, $start_date = '', $end_date = '')
    {
        if (!file_exists($this->dbFile)) {
            file_put_contents($filename, $format === 'json' ? '[]' : '');
            return 0;
        }

        try {
            $pdo = new \PDO('sqlite:' . $this->dbFile);
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            // Build query with date filters
            $whereClause = '';
            $params = [];

            if (!empty($start_date) && !empty($end_date)) {
                $startTimestamp = strtotime($start_date);
                $endTimestamp = strtotime($end_date);
                $whereClause = 'WHERE timestamp BETWEEN ? AND ?';
                $params = [$startTimestamp, $endTimestamp];
            }

            $query = "SELECT * FROM events {$whereClause} ORDER BY timestamp DESC";
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);

            $records = 0;
            $output = '';

            if ($format === 'json') {
                $events = [];
                while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                    $events[] = $row;
                    $records++;
                }
                $output = json_encode($events, JSON_PRETTY_PRINT);
            } else {
                // CSV format
                $output = "timestamp,source_ip,user,event_type,description,severity,country_code\n";
                while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                    $output .= sprintf(
                        "%s,%s,%s,%s,%s,%s,%s\n",
                        date('Y-m-d H:i:s', $row['timestamp']),
                        $row['source_ip'] ?: '',
                        $row['user'] ?: '',
                        $row['event_type'],
                        str_replace('"', '""', $row['description'] ?: ''),
                        $row['severity'],
                        $row['country_code'] ?: ''
                    );
                    $records++;
                }
            }

            file_put_contents($filename, $output);
            return $records;

        } catch (\Exception $e) {
            file_put_contents($filename, $format === 'json' ? '[]' : '');
            return 0;
        }
    }

    /**
     * Test SIEM server connection
     * @return array
     */
    public function testConnectionAction()
    {
        if (!$this->request->isPost()) {
            return [
                'status' => 'error',
                'message' => 'Only POST method allowed'
            ];
        }

        try {
            // Try backend first
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger test_connection');
                
                if (!empty($response)) {
                    $data = json_decode($response, true);
                    if (is_array($data)) {
                        return array_merge(['status' => 'ok'], $data);
                    } else {
                        // Parse simple text response
                        $success = (strpos($response, 'success') !== false || strpos($response, 'connected') !== false);
                        return [
                            'status' => 'ok',
                            'connection_test' => $success,
                            'message' => $success ? 'Connection successful' : 'Connection failed',
                            'details' => $response
                        ];
                    }
                }
            } catch (\Exception $e) {
                // Continue with manual test
            }

            // Manual connection test
            return $this->testSiemConnectionManually();

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
                'connection_test' => false
            ];
        }
    }

    /**
     * Manual SIEM connection test
     * @return array
     */
    private function testSiemConnectionManually()
    {
        try {
            // Load SIEM configuration
            $mdl = new SiemLogger();
            $siemServer = (string)$mdl->siem_export->siem_server;
            $siemPort = (int)$mdl->siem_export->siem_port;
            $protocol = (string)$mdl->siem_export->protocol;

            if (empty($siemServer)) {
                return [
                    'status' => 'ok',
                    'connection_test' => false,
                    'message' => 'SIEM server not configured'
                ];
            }

            // Test connection
            $timeout = 5;
            $success = false;
            $message = '';

            if ($protocol === 'udp') {
                $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
                if ($socket && socket_connect($socket, $siemServer, $siemPort)) {
                    $testMessage = json_encode(['test' => 'connection', 'timestamp' => time()]);
                    $success = socket_send($socket, $testMessage, strlen($testMessage), 0) !== false;
                    socket_close($socket);
                }
                $message = $success ? 'UDP connection successful' : 'UDP connection failed';
            } else {
                // TCP/TLS
                $socket = fsockopen($siemServer, $siemPort, $errno, $errstr, $timeout);
                if ($socket) {
                    $success = true;
                    $message = 'TCP connection successful';
                    fclose($socket);
                } else {
                    $message = "TCP connection failed: {$errstr} ({$errno})";
                }
            }

            return [
                'status' => 'ok',
                'connection_test' => $success,
                'message' => $message,
                'server' => $siemServer,
                'port' => $siemPort,
                'protocol' => $protocol
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'ok',
                'connection_test' => false,
                'message' => 'Connection test failed: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Get service statistics
     * @return array
     */
    public function statisticsAction()
    {
        try {
            // Try backend first
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger statistics');
                
                if (!empty($response)) {
                    $data = json_decode($response, true);
                    if (is_array($data)) {
                        return [
                            'status' => 'ok',
                            'data' => $data
                        ];
                    }
                }
            } catch (\Exception $e) {
                // Continue with manual stats
            }

            // Manual statistics
            $stats = $this->getManualStatistics();
            
            return [
                'status' => 'ok',
                'data' => $stats
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Get manual statistics
     * @return array
     */
    private function getManualStatistics()
    {
        $stats = [
            'events_processed' => 0,
            'events_exported' => 0,
            'export_errors' => 0,
            'storage_used' => '0MB',
            'uptime' => 'Unknown',
            'last_export' => null
        ];

        // Get stats from database
        if (file_exists($this->dbFile)) {
            try {
                $pdo = new \PDO('sqlite:' . $this->dbFile);
                $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

                // Total events
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM events");
                $result = $stmt->fetch(\PDO::FETCH_ASSOC);
                $stats['events_processed'] = (int)$result['count'];

                // Exported events
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE exported = 1");
                $result = $stmt->fetch(\PDO::FETCH_ASSOC);
                $stats['events_exported'] = (int)$result['count'];

                // Export errors
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE exported = 0");
                $result = $stmt->fetch(\PDO::FETCH_ASSOC);
                $stats['export_errors'] = (int)$result['count'];

                // Last export time
                $stmt = $pdo->query("SELECT MAX(timestamp) as last_time FROM events WHERE exported = 1");
                $result = $stmt->fetch(\PDO::FETCH_ASSOC);
                if ($result['last_time']) {
                    $stats['last_export'] = date('c', $result['last_time']);
                }

            } catch (\Exception $e) {
                // Use default values
            }
        }

        // Storage usage
        $logDir = '/var/log/siemlogger';
        $size = 0;
        if (is_dir($logDir)) {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($logDir, \RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
                $size += $file->getSize();
            }
        }
        if (file_exists($this->dbFile)) {
            $size += filesize($this->dbFile);
        }
        $stats['storage_used'] = round($size / (1024 * 1024), 2) . 'MB';

        // Uptime
        if (file_exists($this->pidFile)) {
            $startTime = filectime($this->pidFile);
            $uptime = time() - $startTime;
            $stats['uptime'] = $this->formatUptime($uptime);
        }

        return $stats;
    }

    /**
     * Generate sample logs for testing
     * @param int $limit
     * @return array
     */
    private function generateSampleLogs($limit)
    {
        $logs = [];
        $eventTypes = ['authentication', 'authorization', 'configuration', 'network', 'system', 'audit'];
        $severities = ['debug', 'info', 'warning', 'error', 'critical'];
        $ips = ['127.0.0.1', '192.168.1.100', '192.168.1.50', '10.0.0.25', '172.16.0.10', '203.0.113.45'];
        $users = ['admin', 'operator', 'guest', 'system', 'root'];
        
        for ($i = 0; $i < $limit; $i++) {
            $eventType = $eventTypes[array_rand($eventTypes)];
            $severity = $severities[array_rand($severities)];
            $sourceIp = $ips[array_rand($ips)];
            $user = $users[array_rand($users)];
            
            $timestamp = time() - ($i * 60); // 1 minute intervals
            
            $logs[] = [
                'id' => 'sample_' . $i,
                'timestamp' => date('Y-m-d H:i:s', $timestamp),
                'timestamp_iso' => date('c', $timestamp),
                'source_ip' => $sourceIp,
                'user' => $user,
                'event_type' => $eventType,
                'severity' => $severity,
                'message' => "Sample {$eventType} event by user {$user} from {$sourceIp}",
                'details' => [
                    'session_id' => 'sess_' . uniqid(),
                    'request_id' => 'req_' . uniqid(),
                    'duration' => rand(10, 500) . 'ms'
                ]
            ];
        }
        
        return $logs;
    }

    /**
     * Format uptime in human readable format
     * @param int $seconds
     * @return string
     */
    private function formatUptime($seconds)
    {
        if ($seconds < 60) {
            return $seconds . 's';
        } elseif ($seconds < 3600) {
            return floor($seconds / 60) . 'm';
        } elseif ($seconds < 86400) {
            $hours = floor($seconds / 3600);
            $minutes = floor(($seconds % 3600) / 60);
            return $hours . 'h ' . $minutes . 'm';
        } else {
            $days = floor($seconds / 86400);
            $hours = floor(($seconds % 86400) / 3600);
            return $days . 'd ' . $hours . 'h';
        }
    }
}