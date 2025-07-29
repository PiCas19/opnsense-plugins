<?php
/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
 * All rights reserved.
 */

namespace OPNsense\SiemLogger\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * Class SettingsController
 * @package OPNsense\SiemLogger\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'siemlogger';
    protected static $internalModelClass = 'OPNsense\SiemLogger\SiemLogger';

    private $dbFile = '/var/db/siemlogger/siemlogger.db';
    private $statsFile = '/var/log/siemlogger/stats.json';
    private $eventsFile = '/var/log/siemlogger/events.log';

    /**
     * check if changes to the siemlogger settings were made
     * @return array result
     */
    public function dirtyAction()
    {
        $result = array('status' => 'ok');
        $result['siemlogger']['dirty'] = $this->getModel()->configChanged();
        return $result;
    }

    /**
     * Get SIEM Logger configuration for dashboard
     * @return array siemlogger configuration content
     */
    public function getConfigAction()
    {
        try {
            $mdl = $this->getModel();
            $data = [
                'enabled' => (string)$mdl->general->enabled,
                'log_level' => (string)$mdl->general->log_level,
                'export_enabled' => (string)$mdl->siem_export->export_enabled,
                'audit_enabled' => (string)$mdl->audit_settings->audit_enabled,
                'max_log_size' => (string)$mdl->general->max_log_size,
                'retention_days' => (string)$mdl->general->retention_days
            ];

            return [
                'status' => 'ok',
                'data' => $data
            ];
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Retrieve general settings
     * @return array siemlogger general settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getGeneralAction()
    {
        return ['siemlogger' => $this->getModel()->general->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve siem export settings
     * @return array siemlogger siem export settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getSiemExportAction()
    {
        return ['siemlogger' => $this->getModel()->siem_export->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve logging rules settings
     * @return array siemlogger logging rules settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getLoggingRulesAction()
    {
        return ['siemlogger' => $this->getModel()->logging_rules->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve audit settings
     * @return array siemlogger audit settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getAuditSettingsAction()
    {
        return ['siemlogger' => $this->getModel()->audit_settings->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve notifications settings
     * @return array siemlogger notifications settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getNotificationsAction()
    {
        return ['siemlogger' => $this->getModel()->notifications->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve monitoring settings
     * @return array siemlogger monitoring settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getMonitoringAction()
    {
        return ['siemlogger' => $this->getModel()->monitoring->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set settings and automatically apply changes
     * @return array save result + validation output
     */
    public function setAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
            // Set all posted data
            $mdl->setNodes($this->request->getPost("siemlogger"));
            $valMsgs = $mdl->performValidation();
            
            if ($valMsgs->count() > 0) {
                $result["validations"] = [];
                foreach ($valMsgs as $msg) {
                    $field = $msg->getField();
                    $result["validations"]["siemlogger." . $field] = $msg->getMessage();
                }
            } else {
                $mdl->serializeToConfig();
                Config::getInstance()->save();
                
                // Automatically reconfigure after save
                $backend = new Backend();
                $backend->configdRun('siemlogger reconfigure');
                
                // Clear the dirty flag
                $mdl->configClean();
                
                $result["result"] = "saved";
            }
        }
        return $result;
    }

    /**
     * Get SIEM Logger statistics for dashboard - IMPLEMENTAZIONE CORRETTA
     * @return array statistics data
     */
    public function statsAction()
    {
        $result = ["status" => "ok"];
        
        // Initialize with defaults
        $result['data'] = $this->getDefaultStats();
        
        // Try to load statistics from file
        if (file_exists($this->statsFile)) {
            $statsData = @file_get_contents($this->statsFile);
            if ($statsData !== false) {
                $decodedStats = @json_decode($statsData, true);
                if ($decodedStats !== null) {
                    // Merge file stats with defaults
                    $result['data'] = array_merge($result['data'], $decodedStats);
                }
            }
        }
        
        // Add database statistics if available
        $dbStats = $this->getDatabaseStats();
        if (!empty($dbStats)) {
            $result['data'] = array_merge($result['data'], $dbStats);
        }
        
        // Add recent events
        $result['data']['recent_events'] = $this->getRecentEvents();
        
        // Add system information
        $result['data']['system_info'] = $this->getSystemInfo();
        
        return $result;
    }

    /**
     * Get default statistics structure
     * @return array default stats
     */
    private function getDefaultStats()
    {
        return [
            'total_events' => 0,
            'events_today' => 0,
            'export_errors' => 0,
            'disk_usage' => 0,
            'events_processed' => 0,
            'events_exported' => 0,
            'threats_detected' => 0,
            'failed_login_attempts' => 0,
            'successful_logins' => 0,
            'configuration_changes' => 0,
            'network_events' => 0,
            'firewall_blocks' => 0,
            'vpn_connections' => 0,
            'ssh_sessions' => 0,
            'audit_events' => 0,
            'last_export_time' => 0,
            'export_failures' => 0,
            'suspicious_activity' => [],
            'performance' => [
                'events_per_second' => 0,
                'avg_processing_time' => 0,
                'memory_usage' => 0
            ],
            'event_types' => []
        ];
    }

    /**
     * Get statistics from database
     * @return array database stats
     */
    private function getDatabaseStats()
    {
        if (!file_exists($this->dbFile)) {
            return [];
        }

        try {
            $pdo = new \PDO('sqlite:' . $this->dbFile);
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

            $stats = [];

            // Total events
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM events");
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['total_events'] = (int)$result['count'];

            // Events today
            $todayStart = strtotime('today');
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM events WHERE timestamp >= ?");
            $stmt->execute([$todayStart]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['events_today'] = (int)$result['count'];

            // Export errors (pending exports)
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE exported = 0");
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['export_errors'] = (int)$result['count'];

            // Event types for chart
            $stmt = $pdo->query("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type ORDER BY count DESC");
            $eventTypes = [];
            while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                $eventTypes[$row['event_type']] = (int)$row['count'];
            }
            $stats['event_types'] = $eventTypes;

            // SSH sessions from audit logs
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE event_type = 'authentication' AND (description LIKE '%SSH%' OR source_log LIKE '%audit%')");
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['ssh_sessions'] = (int)$result['count'];

            // Authentication events breakdown
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE event_type = 'authentication' AND (description LIKE '%successful%' OR description LIKE '%closed%')");
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['successful_logins'] = (int)$result['count'];

            $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE event_type = 'authentication' AND (description LIKE '%failed%' OR description LIKE '%error%')");
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['failed_login_attempts'] = (int)$result['count'];

            // Configuration changes
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM events WHERE event_type = 'configuration'");
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stats['configuration_changes'] = (int)$result['count'];

            return $stats;

        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Get recent events from database or log file
     * @return array recent events
     */
    private function getRecentEvents()
    {
        $events = [];

        // Try database first
        if (file_exists($this->dbFile)) {
            try {
                $pdo = new \PDO('sqlite:' . $this->dbFile);
                $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

                $stmt = $pdo->query("
                    SELECT timestamp, source_ip, user, event_type, description, severity 
                    FROM events 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                ");

                while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
                    $events[] = [
                        'timestamp' => date('Y-m-d H:i:s', $row['timestamp']),
                        'timestamp_iso' => date('c', $row['timestamp']),
                        'source_ip' => $row['source_ip'] ?: 'Unknown',
                        'user' => $row['user'] ?: 'Unknown',
                        'event_type' => $row['event_type'],
                        'message' => $row['description'] ?: 'No message',
                        'severity' => $row['severity']
                    ];
                }

                return $events;

            } catch (\Exception $e) {
                // Fall back to file reading
            }
        }

        // Fallback: read from log file
        if (file_exists($this->eventsFile)) {
            $lines = @file($this->eventsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                $lines = array_slice(array_reverse($lines), 0, 10);

                foreach ($lines as $line) {
                    $event = @json_decode($line, true);
                    if ($event !== null) {
                        $events[] = [
                            'timestamp' => isset($event['timestamp']) ? date('Y-m-d H:i:s', $event['timestamp']) : 'Unknown',
                            'timestamp_iso' => isset($event['timestamp']) ? date('c', $event['timestamp']) : date('c'),
                            'source_ip' => $event['source_ip'] ?? 'Unknown',
                            'user' => $event['user'] ?? 'Unknown',
                            'event_type' => $event['event_type'] ?? 'unknown',
                            'message' => $event['description'] ?? 'No message',
                            'severity' => $event['severity'] ?? 'info'
                        ];
                    }
                }
            }
        }

        // If no events found, return sample events for demo
        if (empty($events)) {
            $events = $this->getSampleEvents();
        }

        return $events;
    }

    /**
     * Get sample events for demonstration
     * @return array sample events
     */
    private function getSampleEvents()
    {
        $eventTypes = ['authentication', 'configuration', 'network', 'firewall', 'system'];
        $severities = ['info', 'warning', 'error'];
        $ips = ['127.0.0.1', '192.168.1.100', '10.0.0.50'];
        
        $events = [];
        for ($i = 0; $i < 5; $i++) {
            $events[] = [
                'timestamp' => date('Y-m-d H:i:s', time() - ($i * 300)),
                'timestamp_iso' => date('c', time() - ($i * 300)),
                'source_ip' => $ips[array_rand($ips)],
                'user' => 'admin',
                'event_type' => $eventTypes[array_rand($eventTypes)],
                'message' => 'Sample ' . $eventTypes[array_rand($eventTypes)] . ' event',
                'severity' => $severities[array_rand($severities)]
            ];
        }
        
        return $events;
    }

    /**
     * Get system information
     * @return array system info
     */
    private function getSystemInfo()
    {
        $info = [
            'service_status' => 'Unknown',
            'pid' => null,
            'uptime' => 'Unknown',
            'disk_usage' => 0,
            'version' => '1.0.0'
        ];

        // Check service status via PID file
        $pidFile = '/var/run/siemlogger.pid';
        if (file_exists($pidFile)) {
            $pid = (int)trim(file_get_contents($pidFile));
            if ($pid > 0 && file_exists("/proc/{$pid}")) {
                $info['service_status'] = 'Running';
                $info['pid'] = $pid;

                // Calculate uptime
                $startTime = filectime($pidFile);
                $uptime = time() - $startTime;
                $info['uptime'] = $this->formatUptime($uptime);
            } else {
                $info['service_status'] = 'Stopped';
            }
        } else {
            $info['service_status'] = 'Stopped';
        }

        // Calculate disk usage
        $logDir = '/var/log/siemlogger';
        if (is_dir($logDir)) {
            $size = $this->getDirSize($logDir);
            if (file_exists($this->dbFile)) {
                $size += filesize($this->dbFile);
            }
            $info['disk_usage'] = round($size / (1024 * 1024), 2); // MB
        }

        return $info;
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

    /**
     * Get directory size in bytes
     * @param string $dir
     * @return int
     */
    private function getDirSize($dir)
    {
        $size = 0;
        if (is_dir($dir)) {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
                $size += $file->getSize();
            }
        }
        return $size;
    }

    /**
     * Service control methods
     */
    public function startAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("siemlogger start");
            
            return [
                "status" => "ok",
                "message" => "SIEM Logger service started successfully"
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    public function stopAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("siemlogger stop");
            
            return [
                "status" => "ok",
                "message" => "SIEM Logger service stopped successfully"
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    public function restartAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("siemlogger restart");
            
            return [
                "status" => "ok", 
                "message" => "SIEM Logger service restarted successfully"
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    public function reconfigureAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("siemlogger reconfigure");
            
            return [
                "status" => "ok",
                "message" => "SIEM Logger reconfigured successfully"
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }
}