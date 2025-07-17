<?php
namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class LogsController
 * @package OPNsense\DeepInspector
 */
class LogsController extends ApiControllerBase
{
    /**
     * Get logs list with filtering
     * @return array logs list
     */
    public function listAction()
    {
        $result = ["status" => "ok"];
        
        try {
            // Get filter parameters
            $levelFilter = $this->request->get('level', 'all');
            $sourceFilter = $this->request->get('source', 'all');
            $timeFilter = $this->request->get('timeRange', '24h');
            $searchFilter = $this->request->get('search', '');
            $page = intval($this->request->get('page', 1));
            $limit = intval($this->request->get('limit', 100));
            
            $engineLog = '/var/log/deepinspector/engine.log';
            $daemonLog = '/var/log/deepinspector/daemon.log';
            $detectionLog = '/var/log/deepinspector/detections.log';
            
            $logs = [];
            $statistics = [
                'trace' => 0,
                'debug' => 0,
                'info' => 0,
                'warning' => 0,
                'error' => 0,
                'critical' => 0
            ];
            
            // Calculate time limit
            $timeLimit = $this->calculateTimeLimit($timeFilter);
            
            // Read from different log files
            $logFiles = [
                'engine' => $engineLog,
                'daemon' => $daemonLog,
                'detection' => $detectionLog
            ];
            
            foreach ($logFiles as $source => $logFile) {
                if (file_exists($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    foreach ($lines as $line) {
                        $logEntry = $this->parseLogLine($line, $source);
                        if ($logEntry && $this->matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)) {
                            $logs[] = $logEntry;
                            
                            // Update statistics
                            $level = strtolower($logEntry['level']);
                            if (isset($statistics[$level])) {
                                $statistics[$level]++;
                            }
                        }
                    }
                }
            }
            
            // Sort by timestamp (newest first)
            usort($logs, function($a, $b) {
                return strtotime($b['timestamp']) - strtotime($a['timestamp']);
            });
            
            // Apply pagination
            $totalLogs = count($logs);
            $offset = ($page - 1) * $limit;
            $paginatedLogs = array_slice($logs, $offset, $limit);
            
            $result["data"] = $paginatedLogs;
            $result["statistics"] = $statistics;
            $result["info"] = [
                'count' => $totalLogs,
                'size' => $this->getTotalLogSize($logFiles),
                'lastUpdated' => $this->getLastLogUpdate($logFiles)
            ];
            
        } catch (Exception $e) {
            $result["status"] = "error";
            $result["message"] = "Error retrieving logs: " . $e->getMessage();
            $result["data"] = [];
            $result["statistics"] = [];
        }
        
        return $result;
    }
    
    /**
     * Get log entry details by ID
     * @param string $logId log identifier
     * @return array log details
     */
    public function detailsAction($logId)
    {
        $result = ["status" => "failed"];
        
        try {
            $logFiles = [
                '/var/log/deepinspector/engine.log',
                '/var/log/deepinspector/daemon.log',
                '/var/log/deepinspector/detections.log'
            ];
            
            foreach ($logFiles as $logFile) {
                if (file_exists($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    foreach ($lines as $line) {
                        $logEntry = $this->parseLogLine($line, 'engine');
                        if ($logEntry && $logEntry['id'] === $logId) {
                            $result["status"] = "ok";
                            $result["data"] = [
                                'id' => $logEntry['id'],
                                'timestamp' => $logEntry['timestamp'],
                                'level' => $logEntry['level'],
                                'source' => $logEntry['source'],
                                'message' => $logEntry['message'],
                                'details' => $logEntry['details'] ?? null,
                                'context' => $logEntry['context'] ?? null,
                                'thread' => $logEntry['thread'] ?? null,
                                'process' => $logEntry['process'] ?? 'deepinspector',
                                'module' => $logEntry['module'] ?? null,
                                'function' => $logEntry['function'] ?? null,
                                'line' => $logEntry['line'] ?? null,
                                'file' => $logEntry['file'] ?? null,
                                'stack_trace' => $logEntry['stack_trace'] ?? null
                            ];
                            break 2;
                        }
                    }
                }
            }
            
            if ($result["status"] === "failed") {
                $result["message"] = "Log entry not found";
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error retrieving log details: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Export logs
     * @return array export result
     */
    public function exportAction()
    {
        $result = ["status" => "failed"];
        
        try {
            // Get filter parameters
            $levelFilter = $this->request->get('level', 'all');
            $sourceFilter = $this->request->get('source', 'all');
            $timeFilter = $this->request->get('timeRange', '24h');
            $searchFilter = $this->request->get('search', '');
            $format = $this->request->get('format', 'txt');
            
            $logFiles = [
                'engine' => '/var/log/deepinspector/engine.log',
                'daemon' => '/var/log/deepinspector/daemon.log',
                'detection' => '/var/log/deepinspector/detections.log'
            ];
            
            $logs = [];
            $timeLimit = $this->calculateTimeLimit($timeFilter);
            
            foreach ($logFiles as $source => $logFile) {
                if (file_exists($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    foreach ($lines as $line) {
                        $logEntry = $this->parseLogLine($line, $source);
                        if ($logEntry && $this->matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)) {
                            $logs[] = $logEntry;
                        }
                    }
                }
            }
            
            // Sort by timestamp
            usort($logs, function($a, $b) {
                return strtotime($a['timestamp']) - strtotime($b['timestamp']);
            });
            
            if ($format === 'txt') {
                $exportData = $this->generateLogText($logs);
            } else {
                $exportData = json_encode($logs, JSON_PRETTY_PRINT);
            }
            
            $result["status"] = "ok";
            $result["data"] = $exportData;
            
        } catch (Exception $e) {
            $result["message"] = "Error exporting logs: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Clear logs
     * @return array result
     */
    public function clearAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $logFiles = [
                '/var/log/deepinspector/engine.log',
                '/var/log/deepinspector/daemon.log',
                '/var/log/deepinspector/detections.log'
            ];
            
            $clearedCount = 0;
            
            foreach ($logFiles as $logFile) {
                if (file_exists($logFile)) {
                    // Backup the file first
                    $backupFile = $logFile . '.backup.' . date('Y-m-d-H-i-s');
                    copy($logFile, $backupFile);
                    
                    // Clear the file
                    file_put_contents($logFile, '');
                    $clearedCount++;
                }
            }
            
            $result["status"] = "ok";
            $result["message"] = "Cleared $clearedCount log files";
            
        } catch (Exception $e) {
            $result["message"] = "Error clearing logs: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Parse a log line into structured data
     * @param string $line log line
     * @param string $source log source
     * @return array|null parsed log entry
     */
    private function parseLogLine($line, $source)
    {
        // Try to parse Python logging format: YYYY-MM-DD HH:MM:SS - LEVEL - MESSAGE
        $pattern = '/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),?\d* - (\w+) - (.+)$/';
        
        if (preg_match($pattern, $line, $matches)) {
            $timestamp = $matches[1];
            $level = strtolower($matches[2]);
            $message = $matches[3];
            
            return [
                'id' => md5($line . time() . rand()),
                'timestamp' => date('c', strtotime($timestamp)),
                'level' => $level,
                'source' => $source,
                'message' => $message,
                'context' => null,
                'details' => null
            ];
        }
        
        // Try to parse daemon log format: [YYYY-MM-DD HH:MM:SS] MESSAGE
        $daemonPattern = '/^\[([^\]]+)\] (.+)$/';
        if (preg_match($daemonPattern, $line, $matches)) {
            $timestamp = $matches[1];
            $message = $matches[2];
            
            // Determine level from message content
            $level = 'info';
            if (stripos($message, 'error') !== false) {
                $level = 'error';
            } elseif (stripos($message, 'warning') !== false || stripos($message, 'warn') !== false) {
                $level = 'warning';
            } elseif (stripos($message, 'critical') !== false || stripos($message, 'fatal') !== false) {
                $level = 'critical';
            } elseif (stripos($message, 'debug') !== false) {
                $level = 'debug';
            }
            
            return [
                'id' => md5($line . time() . rand()),
                'timestamp' => date('c', strtotime($timestamp)),
                'level' => $level,
                'source' => 'daemon',
                'message' => $message,
                'context' => null,
                'details' => null
            ];
        }
        
        // Fallback: treat as plain message
        if (!empty(trim($line))) {
            return [
                'id' => md5($line . time() . rand()),
                'timestamp' => date('c'),
                'level' => 'info',
                'source' => $source,
                'message' => $line,
                'context' => null,
                'details' => null
            ];
        }
        
        return null;
    }
    
    /**
     * Check if log entry matches filters
     * @param array $logEntry log entry
     * @param string $levelFilter level filter
     * @param string $sourceFilter source filter
     * @param string $searchFilter search filter
     * @param int $timeLimit time limit
     * @return bool true if matches
     */
    private function matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)
    {
        // Time filter
        if ($timeLimit > 0) {
            $logTime = strtotime($logEntry['timestamp']);
            if ($logTime < $timeLimit) {
                return false;
            }
        }
        
        // Level filter
        if ($levelFilter !== 'all') {
            if ($logEntry['level'] !== $levelFilter) {
                return false;
            }
        }
        
        // Source filter
        if ($sourceFilter !== 'all') {
            if ($logEntry['source'] !== $sourceFilter) {
                return false;
            }
        }
        
        // Search filter
        if (!empty($searchFilter)) {
            $message = strtolower($logEntry['message']);
            $search = strtolower($searchFilter);
            if (strpos($message, $search) === false) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Calculate time limit based on filter
     * @param string $timeFilter time filter
     * @return int timestamp limit
     */
    private function calculateTimeLimit($timeFilter)
    {
        $now = time();
        
        switch ($timeFilter) {
            case '1h':
                return $now - 3600;
            case '6h':
                return $now - 21600;
            case '24h':
                return $now - 86400;
            case '7d':
                return $now - 604800;
            case '30d':
                return $now - 2592000;
            default:
                return 0;
        }
    }
    
    /**
     * Get total size of log files
     * @param array $logFiles array of log file paths
     * @return int total size in bytes
     */
    private function getTotalLogSize($logFiles)
    {
        $totalSize = 0;
        
        foreach ($logFiles as $logFile) {
            if (file_exists($logFile)) {
                $totalSize += filesize($logFile);
            }
        }
        
        return $totalSize;
    }
    
    /**
     * Get last update time of log files
     * @param array $logFiles array of log file paths
     * @return string timestamp
     */
    private function getLastLogUpdate($logFiles)
    {
        $latestTime = 0;
        
        foreach ($logFiles as $logFile) {
            if (file_exists($logFile)) {
                $mtime = filemtime($logFile);
                if ($mtime > $latestTime) {
                    $latestTime = $mtime;
                }
            }
        }
        
        return $latestTime > 0 ? date('c', $latestTime) : date('c');
    }
    
    /**
     * Generate text format from logs
     * @param array $logs log entries
     * @return string formatted log text
     */
    private function generateLogText($logs)
    {
        $text = "Deep Packet Inspector - Log Export\n";
        $text .= "Generated: " . date('Y-m-d H:i:s') . "\n";
        $text .= "Total entries: " . count($logs) . "\n";
        $text .= str_repeat("=", 80) . "\n\n";
        
        foreach ($logs as $log) {
            $text .= sprintf("[%s] %s [%s:%s] %s\n",
                $log['timestamp'],
                strtoupper($log['level']),
                strtoupper($log['source']),
                $log['id'],
                $log['message']
            );
            
            if (!empty($log['context'])) {
                $text .= "  Context: " . $log['context'] . "\n";
            }
            
            if (!empty($log['details'])) {
                $text .= "  Details: " . $log['details'] . "\n";
            }
            
            $text .= "\n";
        }
        
        return $text;
    }
}