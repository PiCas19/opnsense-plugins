<?php
/*
 * Copyright (C) 2025 OPNsense Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiControllerBase;

/**
 * Class LogsController
 *
 * Manages log retrieval, export, and clearing operations for the DeepInspector service
 * within the OPNsense framework. Provides API endpoints for listing logs with filtering,
 * retrieving log details by ID, exporting logs in various formats, and clearing log files.
 * Supports multiple log formats (JSON, Python logging, daemon, syslog) and handles pagination
 * and filtering for efficient log management.
 *
 * Key Features:
 * - Log listing with filters for level, source, time range, and search
 * - Detailed log entry retrieval by ID
 * - Log export in text or JSON format
 * - Log file clearing with backup functionality
 * - Robust error handling with logging of parsing errors
 *
 * @package OPNsense\DeepInspector\Api
 * @author Pierpaolo Casati
 */
class LogsController extends ApiControllerBase
{
    /**
     * Retrieve logs with filtering
     *
     * Fetches log entries from DeepInspector log files, applying filters for level, source,
     * time range, and search terms. Returns paginated results with statistics and metadata.
     * Handles multiple log file formats and ensures memory-efficient processing by limiting
     * the number of processed lines.
     *
     * @api GET /api/deepinspector/logs/list
     *
     * Request Parameters:
     * - level: Log level filter (trace, debug, info, warning, error, critical, all) [default: all]
     * - source: Log source filter (engine, daemon, detection, alerts, threats, latency, all) [default: all]
     * - timeRange: Time range filter (1h, 6h, 24h, 7d, 30d) [default: 24h]
     * - search: Search term for log messages [default: empty]
     * - page: Page number for pagination [default: 1]
     * - limit: Number of logs per page (1-1000) [default: 100]
     *
     * @return array{status: string, data?: array, statistics?: array, info?: array, message?: string} Filtered logs and metadata
     *
     * Response Format:
     * - status: "ok" for successful execution, "error" if an error occurs
     * - data: Array of log entries
     * - statistics: Counts of logs by level
     * - info: Metadata including count, size, last update, and pagination info
     * - message: Error message if the operation fails
     *
     * @example
     * GET /api/deepinspector/logs/list?level=error&source=alerts&timeRange=24h&page=1&limit=50
     * Response: {
     *   "status": "ok",
     *   "data": [
     *     {
     *       "id": "abc123",
     *       "timestamp": "2025-09-26T19:58:00+02:00",
     *       "level": "error",
     *       "source": "alerts",
     *       "message": "Threat detected"
     *     }
     *   ],
     *   "statistics": {
     *     "trace": 0,
     *     "debug": 0,
     *     "info": 0,
     *     "warning": 0,
     *     "error": 1,
     *     "critical": 0
     *   },
     *   "info": {
     *     "count": 1,
     *     "size": 123456,
     *     "lastUpdated": "2025-09-26T19:58:00+02:00",
     *     "page": 1,
     *     "limit": 50,
     *     "totalPages": 1
     *   }
     * }
     *
     * @example
     * GET /api/deepinspector/logs/list
     * Response: {
     *   "status": "error",
     *   "message": "Error retrieving logs: No log files found",
     *   "data": [],
     *   "statistics": {
     *     "trace": 0,
     *     "debug": 0,
     *     "info": 0,
     *     "warning": 0,
     *     "error": 0,
     *     "critical": 0
     *   },
     *   "info": {
     *     "count": 0,
     *     "size": 0,
     *     "lastUpdated": "2025-09-26T19:58:00+02:00",
     *     "page": 1,
     *     "limit": 100,
     *     "totalPages": 1
     *   }
     * }
     *
     * @security Ensure that log file paths are restricted to predefined locations to prevent unauthorized file access.
     */
    public function listAction()
    {
        $result = ["status" => "ok"];
        
        try {
            // Get filter parameters with proper default values
            $levelFilter = $this->request->get('level') ?: 'all';
            $sourceFilter = $this->request->get('source') ?: 'all';
            $timeFilter = $this->request->get('timeRange') ?: '24h';
            $searchFilter = $this->request->get('search') ?: '';
            $page = max(1, intval($this->request->get('page') ?: 1));
            $limit = max(1, min(1000, intval($this->request->get('limit') ?: 100)));
            
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
                    
                    // Handle empty files
                    if ($fileSize === 0) {
                        continue;
                    }
                    
                    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    if ($lines !== false && is_array($lines)) {
                        // Process only the last 1000 lines to prevent memory issues
                        $lines = array_slice($lines, -1000);
                        
                        foreach ($lines as $lineNum => $line) {
                            if (empty(trim($line))) {
                                continue;
                            }
                            
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
                            } catch (Throwable $e) {
                                // Log parsing error but continue processing
                                error_log("DeepInspector: Error parsing log line: " . $e->getMessage());
                                continue;
                            }
                        }
                    }
                }
            }
            
            // Sort by timestamp (newest first) with error handling
            usort($logs, function($a, $b) {
                try {
                    $timeA = strtotime($a['timestamp'] ?? '');
                    $timeB = strtotime($b['timestamp'] ?? '');
                    
                    if ($timeA === false) $timeA = 0;
                    if ($timeB === false) $timeB = 0;
                    
                    return $timeB - $timeA;
                } catch (Throwable $e) {
                    return 0;
                }
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
                'totalPages' => max(1, ceil($totalLogs / $limit))
            ];
            
        } catch (Throwable $e) {
            $result["status"] = "error";
            $result["message"] = "Error retrieving logs: " . $e->getMessage();
            $result["data"] = [];
            $result["statistics"] = [
                'trace' => 0,
                'debug' => 0,
                'info' => 0,
                'warning' => 0,
                'error' => 0,
                'critical' => 0
            ];
            $result["info"] = [
                'count' => 0,
                'size' => 0,
                'lastUpdated' => date('c'),
                'page' => 1,
                'limit' => 100,
                'totalPages' => 1
            ];
            
            // Log the error
            error_log("DeepInspector LogsController listAction error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Retrieve details of a specific log entry by ID
     *
     * Fetches detailed information about a log entry identified by its ID from the log files.
     * Searches through all specified log files to locate the matching entry.
     *
     * @api GET /api/deepinspector/logs/details/{logId}
     *
     * @param string $logId Log entry identifier
     * @return array{status: string, data?: array, message?: string} Log details
     *
     * Response Format:
     * - status: "ok" if the log entry is found, "failed" otherwise
     * - data: Detailed log entry information if found
     * - message: Descriptive message for failure cases
     *
     * @example
     * GET /api/deepinspector/logs/details/abc123
     * Response: {
     *   "status": "ok",
     *   "data": {
     *     "id": "abc123",
     *     "timestamp": "2025-09-26T19:58:00+02:00",
     *     "level": "error",
     *     "source": "alerts",
     *     "message": "Threat detected",
     *     "details": {"threat_type": "malware"},
     *     "context": "{\"threat_type\": \"malware\"}",
     *     "thread": null,
     *     "process": "deepinspector",
     *     "module": null,
     *     "function": null,
     *     "line": null,
     *     "stack_trace": null
     *   }
     * }
     *
     * @example
     * GET /api/deepinspector/logs/details/abc123
     * Response: {
     *   "status": "failed",
     *   "message": "Log entry not found"
     * }
     *
     * @security Ensure that logId is properly sanitized to prevent injection attacks.
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
                    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    if ($lines !== false && is_array($lines)) {
                        foreach ($lines as $lineNum => $line) {
                            try {
                                $logEntry = $this->parseLogLine($line, basename($logFile, '.log'), $lineNum);
                                
                                if ($logEntry && isset($logEntry['id']) && $logEntry['id'] === $logId) {
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
                            } catch (Throwable $e) {
                                continue;
                            }
                        }
                    }
                }
            }
            
            if ($result["status"] === "failed") {
                $result["message"] = "Log entry not found";
            }
            
        } catch (Throwable $e) {
            $result["message"] = "Error retrieving log details: " . $e->getMessage();
            error_log("DeepInspector LogsController detailsAction error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Export filtered logs in text or JSON format
     *
     * Exports log entries based on specified filters, in either text or JSON format.
     * Supports the same filters as listAction for consistency.
     *
     * @api GET /api/deepinspector/logs/export
     *
     * Request Parameters:
     * - level: Log level filter (trace, debug, info, warning, error, critical, all) [default: all]
     * - source: Log source filter (engine, daemon, detection, alerts, threats, all) [default: all]
     * - timeRange: Time range filter (1h, 6h, 24h, 7d, 30d) [default: 24h]
     * - search: Search term for log messages [default: empty]
     * - format: Export format (txt, json) [default: txt]
     *
     * @return array{status: string, data?: string, filename?: string, message?: string} Exported log data
     *
     * Response Format:
     * - status: "ok" if export is successful, "failed" otherwise
     * - data: Exported log data in the requested format
     * - filename: Suggested filename for the exported data
     * - message: Error message if the operation fails
     *
     * @example
     * GET /api/deepinspector/logs/export?format=json
     * Response: {
     *   "status": "ok",
     *   "data": "[{\"id\":\"abc123\",\"timestamp\":\"2025-09-26T19:58:00+02:00\",\"level\":\"error\",\"source\":\"alerts\",\"message\":\"Threat detected\"}]",
     *   "filename": "deepinspector_logs_2025-09-26_19-58-00.json"
     * }
     *
     * @example
     * GET /api/deepinspector/logs/export
     * Response: {
     *   "status": "failed",
     *   "message": "Error exporting logs: No log files found"
     * }
     *
     * @security Ensure that exported data is sanitized to prevent injection of malicious content.
     */
    public function exportAction()
    {
        $result = ["status" => "failed"];
        
        try {
            // Get filter parameters
            $levelFilter = $this->request->get('level') ?: 'all';
            $sourceFilter = $this->request->get('source') ?: 'all';
            $timeFilter = $this->request->get('timeRange') ?: '24h';
            $searchFilter = $this->request->get('search') ?: '';
            $format = $this->request->get('format') ?: 'txt';
            
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
                    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    
                    if ($lines !== false && is_array($lines)) {
                        foreach ($lines as $lineNum => $line) {
                            try {
                                $logEntry = $this->parseLogLine($line, $source, $lineNum);
                                
                                if ($logEntry && $this->matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)) {
                                    $logs[] = $logEntry;
                                }
                            } catch (Throwable $e) {
                                continue;
                            }
                        }
                    }
                }
            }
            
            // Sort by timestamp
            usort($logs, function($a, $b) {
                try {
                    $timeA = strtotime($a['timestamp'] ?? '');
                    $timeB = strtotime($b['timestamp'] ?? '');
                    
                    if ($timeA === false) $timeA = 0;
                    if ($timeB === false) $timeB = 0;
                    
                    return $timeA - $timeB;
                } catch (Throwable $e) {
                    return 0;
                }
            });
            
            if ($format === 'txt') {
                $exportData = $this->generateLogText($logs);
            } else {
                $exportData = json_encode($logs, JSON_PRETTY_PRINT);
            }
            
            $result["status"] = "ok";
            $result["data"] = $exportData;
            $result["filename"] = "deepinspector_logs_" . date('Y-m-d_H-i-s') . '.' . $format;
            
        } catch (Throwable $e) {
            $result["message"] = "Error exporting logs: " . $e->getMessage();
            error_log("DeepInspector LogsController exportAction error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Clear all DeepInspector log files
     *
     * Clears all specified log files after creating backups. Reports the number of cleared files
     * and any errors encountered during the process.
     *
     * @api POST /api/deepinspector/logs/clear
     *
     * @return array{status: string, message: string, warnings?: array} Clear operation result
     *
     * Response Format:
     * - status: "ok" if at least one log file was cleared, "failed" otherwise
     * - message: Descriptive message of the operation
     * - warnings: Array of warnings for individual file failures
     *
     * @example
     * POST /api/deepinspector/logs/clear
     * Response: {
     *   "status": "ok",
     *   "message": "Cleared 5 log files",
     *   "warnings": ["Failed to backup: engine.log"]
     * }
     *
     * @example
     * POST /api/deepinspector/logs/clear
     * Response: {
     *   "status": "failed",
     *   "message": "No log files were cleared. Errors: Failed to backup: engine.log"
     * }
     *
     * @security Ensure that only authorized users can clear log files to prevent data loss.
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
                        if (@copy($logFile, $backupFile)) {
                            // Clear the file
                            if (@file_put_contents($logFile, '') !== false) {
                                $clearedCount++;
                            } else {
                                $errors[] = "Failed to clear: " . basename($logFile);
                            }
                        } else {
                            $errors[] = "Failed to backup: " . basename($logFile);
                        }
                    } catch (Throwable $e) {
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
            
        } catch (Throwable $e) {
            $result["message"] = "Error clearing logs: " . $e->getMessage();
            error_log("DeepInspector LogsController clearAction error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Parse a log line into structured data
     *
     * Parses a log line based on its format (JSON, Python logging, daemon, syslog) and returns
     * a structured array. Returns null if parsing fails or if the line is empty.
     *
     * @param string $line Log line content
     * @param string $source Log source (e.g., engine, daemon)
     * @param int $lineNum Line number for ID generation
     * @return array|null Parsed log entry or null if parsing fails
     */
    private function parseLogLine($line, $source, $lineNum = 0)
    {
        try {
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
                } catch (Throwable $e) {
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
            
        } catch (Throwable $e) {
            error_log("DeepInspector: Error in parseLogLine: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Determine log level from JSON data
     *
     * Extracts the log level from JSON log data based on severity, level, or threat type.
     * Uses a fallback level of 'info' if no specific level is found.
     *
     * @param array $jsonData JSON log data
     * @return string Log level (trace, debug, info, warning, error, critical)
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
     *
     * Extracts the message content from JSON log data based on description, message, or threat type.
     * Uses a fallback message if none is found.
     *
     * @param array $jsonData JSON log data
     * @return string Log message
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
     * Determine log level from message content
     *
     * Infers the log level from the message content based on keywords.
     * Uses a fallback level of 'info' if no specific level is inferred.
     *
     * @param string $message Log message
     * @return string Log level (trace, debug, info, warning, error, critical)
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
     *
     * Converts a timestamp string to ISO 8601 format. Uses the current time as a fallback
     * if parsing fails.
     *
     * @param string $timestamp Timestamp string
     * @return string ISO 8601 formatted timestamp
     */
    private function formatTimestamp($timestamp)
    {
        try {
            $dateTime = new \DateTime($timestamp);
            return $dateTime->format('c');
        } catch (Throwable $e) {
            return date('c');
        }
    }
    
    /**
     * Check if a log entry matches the specified filters
     *
     * Verifies if a log entry satisfies the level, source, search, and time filters.
     * Returns false if any filter does not match or if an error occurs.
     *
     * @param array $logEntry Log entry data
     * @param string $levelFilter Level filter (trace, debug, info, warning, error, critical, all)
     * @param string $sourceFilter Source filter (engine, daemon, detection, alerts, threats, latency, all)
     * @param string $searchFilter Search term
     * @param int $timeLimit Timestamp limit for time range filter
     * @return bool True if the log entry matches all filters
     */
    private function matchesLogFilters($logEntry, $levelFilter, $sourceFilter, $searchFilter, $timeLimit)
    {
        try {
            // Time filter
            if ($timeLimit > 0) {
                $logTime = strtotime($logEntry['timestamp'] ?? '');
                if ($logTime === false || $logTime < $timeLimit) {
                    return false;
                }
            }
            
            // Level filter
            if ($levelFilter !== 'all') {
                if (($logEntry['level'] ?? '') !== $levelFilter) {
                    return false;
                }
            }
            
            // Source filter
            if ($sourceFilter !== 'all') {
                if (($logEntry['source'] ?? '') !== $sourceFilter) {
                    return false;
                }
            }
            
            // Search filter
            if (!empty($searchFilter)) {
                $message = strtolower($logEntry['message'] ?? '');
                $search = strtolower($searchFilter);
                if (strpos($message, $search) === false) {
                    return false;
                }
            }
            
            return true;
        } catch (Throwable $e) {
            return false;
        }
    }
    
    /**
     * Calculate the time limit for log filtering
     *
     * Converts a time range filter (e.g., 1h, 24h) to a Unix timestamp limit.
     * Returns 0 for invalid or unknown filters to include all logs.
     *
     * @param string $timeFilter Time range filter (1h, 6h, 24h, 7d, 30d)
     * @return int Unix timestamp limit
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
     * Calculate the total size of log files
     *
     * Sums the sizes of all specified log files in bytes. Ignores inaccessible files.
     *
     * @param array $logFiles Array of log file paths
     * @return int Total size in bytes
     */
    private function getTotalLogSize($logFiles)
    {
        $totalSize = 0;
        
        try {
            foreach ($logFiles as $logFile) {
                if (file_exists($logFile)) {
                    $size = filesize($logFile);
                    if ($size !== false) {
                        $totalSize += $size;
                    }
                }
            }
        } catch (Throwable $e) {
            error_log("DeepInspector: Error calculating log size: " . $e->getMessage());
        }
        
        return $totalSize;
    }
    
    /**
     * Get the last update time of log files
     *
     * Returns the most recent modification time of the specified log files in ISO 8601 format.
     * Uses the current time as a fallback if no files are available.
     *
     * @param array $logFiles Array of log file paths
     * @return string ISO 8601 formatted timestamp
     */
    private function getLastLogUpdate($logFiles)
    {
        $latestTime = 0;
        
        try {
            foreach ($logFiles as $logFile) {
                if (file_exists($logFile)) {
                    $mtime = filemtime($logFile);
                    if ($mtime !== false && $mtime > $latestTime) {
                        $latestTime = $mtime;
                    }
                }
            }
        } catch (Throwable $e) {
            error_log("DeepInspector: Error getting last update time: " . $e->getMessage());
        }
        
        return $latestTime > 0 ? date('c', $latestTime) : date('c');
    }
    
    /**
     * Generate text format from log entries
     *
     * Converts log entries into a formatted text string for export.
     * Includes a header with metadata and formatted log entries.
     *
     * @param array $logs Array of log entries
     * @return string Formatted text string
     */
    private function generateLogText($logs)
    {
        try {
            $text = "Deep Packet Inspector - Log Export\n";
            $text .= "Generated: " . date('Y-m-d H:i:s') . "\n";
            $text .= "Total entries: " . count($logs) . "\n";
            $text .= str_repeat("=", 80) . "\n\n";
            
            foreach ($logs as $log) {
                $text .= sprintf("[%s] %s [%s:%s] %s\n",
                    $log['timestamp'] ?? 'Unknown',
                    strtoupper($log['level'] ?? 'INFO'),
                    strtoupper($log['source'] ?? 'UNKNOWN'),
                    $log['id'] ?? 'NO-ID',
                    $log['message'] ?? 'No message'
                );
                
                if (!empty($log['context'])) {
                    $text .= "  Context: " . $log['context'] . "\n";
                }
                
                if (!empty($log['details'])) {
                    $details = is_array($log['details']) ? json_encode($log['details']) : $log['details'];
                    $text .= "  Details: " . $details . "\n";
                }
                
                $text .= "\n";
            }
            
            return $text;
        } catch (Throwable $e) {
            return "Error generating log text: " . $e->getMessage();
        }
    }
}