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
            // Get filter parameters with proper default values
            $levelFilter = $this->request->get('level', 'string', 'all');
            $sourceFilter = $this->request->get('source', 'string', 'all');
            $timeFilter = $this->request->get('timeRange', 'string', '24h');
            $searchFilter = $this->request->get('search', 'string', '');
            $page = intval($this->request->get('page', 'int', 1));
            $limit = intval($this->request->get('limit', 'int', 100));
            
            // Ensure page and limit are valid
            $page = max(1, $page);
            $limit = max(1, min(1000, $limit)); // Limit max to 1000
            
            // Define log file paths
            $logFiles = [
                'engine' => '/var/log/deepinspector/engine.log',
                'daemon' => '/var/log/deepinspector/daemon.log',
                'detection' => '/var/log/deepinspector/detections.log',
                'alerts' => '/var/log/deepinspector/alerts.log',
                'threats' => '/var/log/deepinspector/threats.log',
                'latency' => '/var/log/deepinspector/latency.log'
            ];
            
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
            foreach ($logFiles as $source => $logFile) {
                if (file_exists($logFile) && is_readable($logFile)) {
                    $fileSize = filesize($logFile);
                    
                    // Skip very large files to prevent memory issues
                    if ($fileSize > 50 * 1024 * 1024) { // 50MB limit
                        error_log("DeepInspector: Skipping large log file: $logFile ($fileSize bytes)");
                        continue;
                    }
                    
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    if ($lines !== false) {
                        // Process only the last 10000 lines to prevent memory issues
                        $lines = array_slice($lines, -10000);
                        
                        foreach ($lines as $lineNum => $line) {
                            try {
                                $logEntry = $this->parseLogLine($line, $source, $lineNum);
                                
                                if ($logEntry && $this->matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)) {
                                    $logs[] = $logEntry;
                                    
                                    // Update statistics
                                    $level = strtolower($logEntry['level']);
                                    if (isset($statistics[$level])) {
                                        $statistics[$level]++;
                                    }
                                }
                            } catch (Exception $e) {
                                // Log parsing error but continue processing
                                error_log("DeepInspector: Error parsing log line: " . $e->getMessage());
                                continue;
                            }
                        }
                    }
                }
            }
            
            // Sort by timestamp (newest first)
            usort($logs, function($a, $b) {
                $timeA = strtotime($a['timestamp']);
                $timeB = strtotime($b['timestamp']);
                return $timeB - $timeA;
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
                'lastUpdated' => $this->getLastLogUpdate($logFiles),
                'page' => $page,
                'limit' => $limit,
                'totalPages' => ceil($totalLogs / $limit)
            ];
            
        } catch (Exception $e) {
            $result["status"] = "error";
            $result["message"] = "Error retrieving logs: " . $e->getMessage();
            $result["data"] = [];
            $result["statistics"] = [];
            $result["info"] = [];
            
            // Log the error
            error_log("DeepInspector LogsController listAction error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Get log entry details by ID
     * @param string $logId log identifier
     * @return array log details
     */
    public function detailsAction($logId = null)
    {
        $result = ["status" => "failed"];
        
        try {
            if (empty($logId)) {
                $result["message"] = "Log ID is required";
                return $result;
            }
            
            $logFiles = [
                '/var/log/deepinspector/engine.log',
                '/var/log/deepinspector/daemon.log',
                '/var/log/deepinspector/detections.log',
                '/var/log/deepinspector/alerts.log',
                '/var/log/deepinspector/threats.log',
                '/var/log/deepinspector/latency.log'
            ];
            
            foreach ($logFiles as $logFile) {
                if (file_exists($logFile) && is_readable($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    if ($lines !== false) {
                        foreach ($lines as $lineNum => $line) {
                            try {
                                $logEntry = $this->parseLogLine($line, 'engine', $lineNum);
                                
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
                            } catch (Exception $e) {
                                continue;
                            }
                        }
                    }
                }
            }
            
            if ($result["status"] === "failed") {
                $result["message"] = "Log entry not found";
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error retrieving log details: " . $e->getMessage();
            error_log("DeepInspector LogsController detailsAction error: " . $e->getMessage());
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
            $levelFilter = $this->request->get('level', 'string', 'all');
            $sourceFilter = $this->request->get('source', 'string', 'all');
            $timeFilter = $this->request->get('timeRange', 'string', '24h');
            $searchFilter = $this->request->get('search', 'string', '');
            $format = $this->request->get('format', 'string', 'txt');
            
            $logFiles = [
                'engine' => '/var/log/deepinspector/engine.log',
                'daemon' => '/var/log/deepinspector/daemon.log',
                'detection' => '/var/log/deepinspector/detections.log',
                'alerts' => '/var/log/deepinspector/alerts.log',
                'threats' => '/var/log/deepinspector/threats.log'
            ];
            
            $logs = [];
            $timeLimit = $this->calculateTimeLimit($timeFilter);
            
            foreach ($logFiles as $source => $logFile) {
                if (file_exists($logFile) && is_readable($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    if ($lines !== false) {
                        foreach ($lines as $lineNum => $line) {
                            try {
                                $logEntry = $this->parseLogLine($line, $source, $lineNum);
                                
                                if ($logEntry && $this->matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)) {
                                    $logs[] = $logEntry;
                                }
                            } catch (Exception $e) {
                                continue;
                            }
                        }
                    }
                }
            }
            
            // Sort by timestamp
            usort($logs, function($a, $b) {
                $timeA = strtotime($a['timestamp']);
                $timeB = strtotime($b['timestamp']);
                return $timeA - $timeB;
            });
            
            if ($format === 'txt') {
                $exportData = $this->generateLogText($logs);
            } else {
                $exportData = json_encode($logs, JSON_PRETTY_PRINT);
            }
            
            $result["status"] = "ok";
            $result["data"] = $exportData;
            $result["filename"] = "deepinspector_logs_" . date('Y-m-d_H-i-s') . '.' . $format;
            
        } catch (Exception $e) {
            $result["message"] = "Error exporting logs: " . $e->getMessage();
            error_log("DeepInspector LogsController exportAction error: " . $e->getMessage());
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
                '/var/log/deepinspector/detections.log',
                '/var/log/deepinspector/alerts.log',
                '/var/log/deepinspector/threats.log',
                '/var/log/deepinspector/latency.log'
            ];
            
            $clearedCount = 0;
            $errors = [];
            
            foreach ($logFiles as $logFile) {
                if (file_exists($logFile)) {
                    try {
                        // Backup the file first
                        $backupFile = $logFile . '.backup.' . date('Y-m-d-H-i-s');
                        if (copy($logFile, $backupFile)) {
                            // Clear the file
                            if (file_put_contents($logFile, '') !== false) {
                                $clearedCount++;
                            } else {
                                $errors[] = "Failed to clear: " . basename($logFile);
                            }
                        } else {
                            $errors[] = "Failed to backup: " . basename($logFile);
                        }
                    } catch (Exception $e) {
                        $errors[] = "Error with " . basename($logFile) . ": " . $e->getMessage();
                    }
                }
            }
            
            if ($clearedCount > 0) {
                $result["status"] = "ok";
                $result["message"] = "Cleared $clearedCount log files";
                
                if (!empty($errors)) {
                    $result["warnings"] = $errors;
                }
            } else {
                $result["message"] = "No log files were cleared. Errors: " . implode(", ", $errors);
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error clearing logs: " . $e->getMessage();
            error_log("DeepInspector LogsController clearAction error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Parse a log line into structured data
     * @param string $line log line
     * @param string $source log source
     * @param int $lineNum line number
     * @return array|null parsed log entry
     */
    private function parseLogLine($line, $source, $lineNum = 0)
    {
        if (empty(trim($line))) {
            return null;
        }
        
        // Try to parse JSON log entries first (for detection, alerts, threats logs)
        if (($source === 'detection' || $source === 'alerts' || $source === 'threats') && 
            (strpos($line, '{') === 0)) {
            try {
                $jsonData = json_decode($line, true);
                if (json_last_error() === JSON_ERROR_NONE && is_array($jsonData)) {
                    return [
                        'id' => $jsonData['id'] ?? md5($line . $lineNum),
                        'timestamp' => $jsonData['timestamp'] ?? date('c'),
                        'level' => $this->determineLevelFromJson($jsonData),
                        'source' => $source,
                        'message' => $this->extractMessageFromJson($jsonData),
                        'context' => isset($jsonData['details']) ? json_encode($jsonData['details']) : null,
                        'details' => $jsonData
                    ];
                }
            } catch (Exception $e) {
                // Fall through to other parsing methods
            }
        }
        
        // Try to parse Python logging format: YYYY-MM-DD HH:MM:SS,mmm - LEVEL - MESSAGE
        $pattern = '/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),?\d* - (\w+) - (.+)$/';
        
        if (preg_match($pattern, $line, $matches)) {
            $timestamp = $matches[1];
            $level = strtolower($matches[2]);
            $message = $matches[3];
            
            return [
                'id' => md5($line . $lineNum),
                'timestamp' => $this->formatTimestamp($timestamp),
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
            $level = $this->determineLevelFromMessage($message);
            
            return [
                'id' => md5($line . $lineNum),
                'timestamp' => $this->formatTimestamp($timestamp),
                'level' => $level,
                'source' => 'daemon',
                'message' => $message,
                'context' => null,
                'details' => null
            ];
        }
        
        // Try to parse syslog format: MMM DD HH:MM:SS hostname program: message
        $syslogPattern = '/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\w+):\s*(.+)$/';
        if (preg_match($syslogPattern, $line, $matches)) {
            $timestamp = $matches[1];
            $program = $matches[2];
            $message = $matches[3];
            
            return [
                'id' => md5($line . $lineNum),
                'timestamp' => $this->formatTimestamp($timestamp),
                'level' => $this->determineLevelFromMessage($message),
                'source' => $program,
                'message' => $message,
                'context' => null,
                'details' => null
            ];
        }
        
        // Fallback: treat as plain message
        return [
            'id' => md5($line . $lineNum),
            'timestamp' => date('c'),
            'level' => 'info',
            'source' => $source,
            'message' => $line,
            'context' => null,
            'details' => null
        ];
    }
    
    /**
     * Determine log level from JSON data
     * @param array $jsonData
     * @return string
     */
    private function determineLevelFromJson($jsonData)
    {
        if (isset($jsonData['severity'])) {
            return strtolower($jsonData['severity']);
        }
        
        if (isset($jsonData['level'])) {
            return strtolower($jsonData['level']);
        }
        
        if (isset($jsonData['threat_type'])) {
            return 'warning';
        }
        
        return 'info';
    }
    
    /**
     * Extract message from JSON data
     * @param array $jsonData
     * @return string
     */
    private function extractMessageFromJson($jsonData)
    {
        if (isset($jsonData['description'])) {
            return $jsonData['description'];
        }
        
        if (isset($jsonData['message'])) {
            return $jsonData['message'];
        }
        
        if (isset($jsonData['threat_type'])) {
            return "Threat detected: " . $jsonData['threat_type'];
        }
        
        return "Log entry";
    }
    
    /**
     * Determine level from message content
     * @param string $message
     * @return string
     */
    private function determineLevelFromMessage($message)
    {
        $messageLower = strtolower($message);
        
        if (strpos($messageLower, 'critical') !== false || strpos($messageLower, 'fatal') !== false) {
            return 'critical';
        }
        
        if (strpos($messageLower, 'error') !== false || strpos($messageLower, 'fail') !== false) {
            return 'error';
        }
        
        if (strpos($messageLower, 'warning') !== false || strpos($messageLower, 'warn') !== false) {
            return 'warning';
        }
        
        if (strpos($messageLower, 'debug') !== false) {
            return 'debug';
        }
        
        if (strpos($messageLower, 'trace') !== false) {
            return 'trace';
        }
        
        return 'info';
    }
    
    /**
     * Format timestamp to ISO 8601
     * @param string $timestamp
     * @return string
     */
    private function formatTimestamp($timestamp)
    {
        try {
            $dateTime = new DateTime($timestamp);
            return $dateTime->format('c');
        } catch (Exception $e) {
            return date('c');
        }
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
                $text .= "  Details: " . (is_array($log['details']) ? json_encode($log['details']) : $log['details']) . "\n";
            }
            
            $text .= "\n";
        }
        
        return $text;
    }
}