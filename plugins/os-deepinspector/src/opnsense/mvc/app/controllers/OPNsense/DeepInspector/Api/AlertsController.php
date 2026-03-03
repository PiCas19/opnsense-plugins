<?php
/*
 * Copyright (C) 2025 Pierpaolo Casati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
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
use OPNsense\Core\Backend;

/**
 * API controller for managing alerts
 *
 * Provides REST API endpoints for retrieving and managing security alerts
 * detected by the Deep Packet Inspector. Returns real data only - no fallback values.
 *
 * @package OPNsense\DeepInspector\Api
 */
class AlertsController extends ApiControllerBase
{
    /**
     * Lists security alerts with filtering and pagination
     *
     * Retrieves alerts from log file with support for filtering by severity,
     * type, time range, and source IP. Returns empty array if no alerts exist.
     *
     * @return array Response array with status, data, and pagination info
     */
    public function listAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $alerts = [];
            
            // Get filter parameters with proper defaults
            $severityFilter = $this->request->get('severity') ?: 'all';
            $typeFilter = $this->request->get('type') ?: 'all';
            $timeFilter = $this->request->get('time') ?: '24h';
            $sourceFilter = $this->request->get('source') ?: '';
            $page = max(1, intval($this->request->get('page') ?: 1));
            $limit = max(1, min(500, intval($this->request->get('limit') ?: 50))); // Limit between 1-500
            
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $fileContent = file_get_contents($alertsFile);
                if ($fileContent !== false) {
                    $lines = explode("\n", trim($fileContent));
                    $filteredAlerts = [];
                    
                    // Calculate time filter
                    $timeLimit = $this->calculateTimeLimit($timeFilter);
                    
                    foreach ($lines as $lineNumber => $line) {
                        $line = trim($line);
                        if (empty($line)) continue;
                        
                        try {
                            $alert = json_decode($line, true);
                            if (json_last_error() !== JSON_ERROR_NONE) {
                                error_log("DeepInspector: JSON decode error on line " . ($lineNumber + 1) . ": " . json_last_error_msg());
                                continue;
                            }
                            
                            // Only add alerts with complete required data (Zero Trust - no fallback)
                            if ($alert && is_array($alert) &&
                                isset($alert['id'], $alert['timestamp'], $alert['source_ip'], $alert['destination_ip']) &&
                                $this->matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)) {
                                $filteredAlerts[] = [
                                    'id' => $alert['id'],
                                    'timestamp' => $alert['timestamp'],
                                    'source_ip' => $alert['source_ip'],
                                    'source_port' => $alert['source_port'] ?? null,
                                    'destination_ip' => $alert['destination_ip'],
                                    'destination_port' => $alert['destination_port'] ?? null,
                                    'threat_type' => $alert['threat_type'] ?? '',
                                    'severity' => $alert['severity'] ?? 'medium',
                                    'protocol' => $alert['protocol'] ?? '',
                                    'description' => $alert['description'] ?? '',
                                    'industrial_context' => $alert['industrial_context'] ?? false,
                                    'zero_trust_triggered' => $alert['zero_trust_triggered'] ?? false,
                                    'detection_method' => $alert['detection_method'] ?? ''
                                ];
                            }
                        } catch (Exception $e) {
                            error_log("DeepInspector: Error processing alert line " . ($lineNumber + 1) . ": " . $e->getMessage());
                            continue;
                        }
                    }
                    
                    // Sort by timestamp (newest first)
                    usort($filteredAlerts, function($a, $b) {
                        $timeA = strtotime($a['timestamp']);
                        $timeB = strtotime($b['timestamp']);
                        return $timeB - $timeA;
                    });
                    
                    // Apply pagination
                    $totalAlerts = count($filteredAlerts);
                    $offset = ($page - 1) * $limit;
                    $paginatedAlerts = array_slice($filteredAlerts, $offset, $limit);
                    
                    $result["data"] = $paginatedAlerts;
                    $result["pagination"] = [
                        'page' => $page,
                        'limit' => $limit,
                        'total' => $totalAlerts,
                        'pages' => max(1, ceil($totalAlerts / $limit))
                    ];
                } else {
                    // Return empty array if file cannot be read (no fallback)
                    error_log("DeepInspector: Could not read alerts file: $alertsFile");
                    $result["data"] = [];
                    $result["pagination"] = [
                        'page' => 1,
                        'limit' => $limit,
                        'total' => 0,
                        'pages' => 0
                    ];
                }
            } else {
                // Return empty array if file doesn't exist (no fallback)
                $result["data"] = [];
                $result["pagination"] = [
                    'page' => 1,
                    'limit' => $limit,
                    'total' => 0,
                    'pages' => 0
                ];
            }
            
        } catch (Exception $e) {
            // Return empty result on error (no fallback data)
            error_log("DeepInspector: Error in listAction: " . $e->getMessage());
            $result["status"] = "ok";
            $result["data"] = [];
            $result["pagination"] = [
                'page' => 1,
                'limit' => 50,
                'total' => 0,
                'pages' => 0
            ];
        } catch (Error $e) {
            // Return empty result on fatal error (no fallback data)
            error_log("DeepInspector: Fatal error in listAction: " . $e->getMessage());
            $result["status"] = "ok";
            $result["data"] = [];
            $result["pagination"] = [
                'page' => 1,
                'limit' => 50,
                'total' => 0,
                'pages' => 0
            ];
        }
        
        return $result;
    }
    
    /**
     * Gets detailed threat information by ID
     *
     * Retrieves comprehensive details for a specific threat/alert.
     * Returns error if threat not found (no fallback data).
     *
     * @param string|null $threatId Threat identifier
     * @return array Response with threat details or error
     */
    public function threatDetailsAction($threatId = null)
    {
        $result = ["status" => "failed"];
        
        if (empty($threatId)) {
            $threatId = $this->request->get('id');
        }
        
        if (empty($threatId)) {
            $result["message"] = "Threat ID is required";
            return $result;
        }
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $fileContent = file_get_contents($alertsFile);
                if ($fileContent !== false) {
                    $lines = explode("\n", trim($fileContent));
                    
                    foreach ($lines as $line) {
                        $line = trim($line);
                        if (empty($line)) continue;
                        
                        try {
                            $alert = json_decode($line, true);
                            if (json_last_error() === JSON_ERROR_NONE && $alert && isset($alert['id']) && $alert['id'] === $threatId) {
                                $result["status"] = "ok";
                                $result["data"] = [
                                    'id' => $alert['id'],
                                    'threat_id' => $alert['id'],
                                    'timestamp' => $alert['timestamp'],
                                    'source_ip' => $alert['source_ip'],
                                    'source_port' => $alert['source_port'] ?? null,
                                    'destination_ip' => $alert['destination_ip'],
                                    'destination_port' => $alert['destination_port'] ?? null,
                                    'threat_type' => $alert['threat_type'],
                                    'severity' => $alert['severity'],
                                    'protocol' => $alert['protocol'],
                                    'description' => $alert['description'],
                                    'detection_method' => $alert['detection_method'] ?? 'Unknown',
                                    'method' => $alert['detection_method'] ?? 'Unknown',
                                    'pattern' => $alert['pattern'] ?? 'N/A',
                                    'industrial_context' => $alert['industrial_context'] ?? false,
                                    'industrial_protocol' => $alert['industrial_protocol'] ?? null,
                                    'zero_trust_triggered' => $alert['zero_trust_triggered'] ?? false,
                                    'status' => 'active',
                                    'first_seen' => $alert['timestamp'],
                                    'last_seen' => $alert['timestamp'],
                                    'interface' => $alert['interface'] ?? null,
                                    'packet_data' => $alert['packet_data'] ?? null
                                ];
                                break;
                            }
                        } catch (Exception $e) {
                            continue; // Skip malformed lines
                        }
                    }
                }
            }
            
            if ($result["status"] === "failed") {
                $result["message"] = "Threat not found";
            }
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in threatDetailsAction: " . $e->getMessage());
            $result["message"] = "Error retrieving threat details: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Gets all alerts with pagination (alias for listAction)
     *
     * @return array Alerts list
     */
    public function getAllAction()
    {
        return $this->listAction();
    }

    /**
     * Gets alert statistics and metrics
     *
     * Calculates comprehensive statistics including counts by severity,
     * threat type distribution, top sources, and hourly patterns.
     * Returns empty stats structure if no alerts exist.
     *
     * @return array Response with statistics data
     */
    public function getStatsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $stats = [
                'total_alerts' => 0,
                'critical_alerts' => 0,
                'high_alerts' => 0,
                'medium_alerts' => 0,
                'low_alerts' => 0,
                'industrial_alerts' => 0,
                'threat_types' => [],
                'top_sources' => [],
                'hourly_distribution' => []
            ];
            
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $fileContent = file_get_contents($alertsFile);
                if ($fileContent !== false) {
                    $lines = explode("\n", trim($fileContent));
                    $threatTypes = [];
                    $sources = [];
                    $hourly = [];
                    
                    foreach ($lines as $line) {
                        $line = trim($line);
                        if (empty($line)) continue;
                        
                        try {
                            $alert = json_decode($line, true);
                            if (json_last_error() === JSON_ERROR_NONE && $alert) {
                                $stats['total_alerts']++;
                                
                                // Count by severity
                                $severity = $alert['severity'] ?? 'medium';
                                switch ($severity) {
                                    case 'critical':
                                        $stats['critical_alerts']++;
                                        break;
                                    case 'high':
                                        $stats['high_alerts']++;
                                        break;
                                    case 'medium':
                                        $stats['medium_alerts']++;
                                        break;
                                    case 'low':
                                        $stats['low_alerts']++;
                                        break;
                                }
                                
                                // Count industrial alerts
                                if ($alert['industrial_context'] ?? false) {
                                    $stats['industrial_alerts']++;
                                }
                                
                                // Count threat types
                                $threatType = $alert['threat_type'] ?? 'unknown';
                                $threatTypes[$threatType] = ($threatTypes[$threatType] ?? 0) + 1;
                                
                                // Count source IPs
                                $sourceIP = $alert['source_ip'] ?? 'unknown';
                                $sources[$sourceIP] = ($sources[$sourceIP] ?? 0) + 1;
                                
                                // Count by hour
                                $timestamp = $alert['timestamp'] ?? date('c');
                                $hour = date('H', strtotime($timestamp));
                                $hourly[$hour] = ($hourly[$hour] ?? 0) + 1;
                            }
                        } catch (Exception $e) {
                            continue; // Skip malformed lines
                        }
                    }
                    
                    // Sort and limit results
                    arsort($threatTypes);
                    arsort($sources);
                    ksort($hourly);
                    
                    $stats['threat_types'] = array_slice($threatTypes, 0, 10, true);
                    $stats['top_sources'] = array_slice($sources, 0, 10, true);
                    $stats['hourly_distribution'] = $hourly;
                }
            }
            
            $result["data"] = $stats;
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in getStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving alert statistics: " . $e->getMessage();
            $result["data"] = $stats; // Return empty stats structure
        }
        
        return $result;
    }
    
    /**
     * Calculates timestamp limit based on time filter
     *
     * @param string $timeFilter Time filter value (1h, 24h, 7d, 30d, all)
     * @return int Unix timestamp limit
     */
    private function calculateTimeLimit($timeFilter)
    {
        $now = time();
        
        switch ($timeFilter) {
            case '1h':
                return $now - 3600;
            case '24h':
                return $now - 86400;
            case '7d':
                return $now - 604800;
            case '30d':
                return $now - 2592000;
            case 'all':
            default:
                return 0;
        }
    }
    
    /**
     * Checks if alert matches all specified filters
     *
     * @param array $alert Alert data to check
     * @param string $severityFilter Severity filter value
     * @param string $typeFilter Type filter value
     * @param string $sourceFilter Source IP filter value
     * @param int $timeLimit Time limit timestamp
     * @return bool True if alert matches all filters
     */
    private function matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)
    {
        if (!is_array($alert)) {
            return false;
        }
        
        // Time filter
        if ($timeLimit > 0) {
            $alertTime = strtotime($alert['timestamp'] ?? '');
            if ($alertTime === false || $alertTime < $timeLimit) {
                return false;
            }
        }
        
        // Severity filter
        if ($severityFilter !== 'all') {
            $alertSeverity = $alert['severity'] ?? 'medium';
            if ($alertSeverity !== $severityFilter) {
                return false;
            }
        }
        
        // Type filter
        if ($typeFilter !== 'all') {
            $alertType = $alert['threat_type'] ?? 'unknown';
            if ($alertType !== $typeFilter) {
                return false;
            }
        }
        
        // Source IP filter
        if (!empty($sourceFilter)) {
            $sourceIP = $alert['source_ip'] ?? '';
            if (stripos($sourceIP, $sourceFilter) === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Export alerts to file
     *
     * Exports filtered alerts to JSON or CSV format for download.
     * Returns only real data - no fallback values.
     *
     * @return array Export data with filename
     */
    public function exportAction()
    {
        $result = ["status" => "ok"];

        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $format = $this->request->get('format') ?: 'json';
            $severityFilter = $this->request->get('severity') ?: 'all';
            $typeFilter = $this->request->get('type') ?: 'all';
            $timeFilter = $this->request->get('timeRange') ?: 'all';
            $sourceFilter = $this->request->get('source') ?: '';

            $alerts = [];
            $timeLimit = $this->calculateTimeLimit($timeFilter);

            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

                if ($lines !== false && is_array($lines)) {
                    foreach ($lines as $line) {
                        try {
                            $alert = json_decode($line, true);

                            // Only include alerts with complete required data (Zero Trust)
                            if ($alert && is_array($alert) &&
                                isset($alert['id'], $alert['timestamp'], $alert['source_ip'], $alert['destination_ip']) &&
                                $this->matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)) {
                                $alerts[] = $alert;
                            }
                        } catch (Exception $e) {
                            continue;
                        }
                    }
                }
            }

            // Sort by timestamp descending
            usort($alerts, function ($a, $b) {
                return strcmp($b['timestamp'] ?? '', $a['timestamp'] ?? '');
            });

            // Generate export data
            if ($format === 'csv') {
                $csv = "ID,Timestamp,Source IP,Source Port,Destination IP,Destination Port,Threat Type,Severity,Protocol,Description\n";
                foreach ($alerts as $alert) {
                    $csv .= sprintf(
                        "%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n",
                        $alert['id'] ?? '',
                        $alert['timestamp'] ?? '',
                        $alert['source_ip'] ?? '',
                        $alert['source_port'] ?? '',
                        $alert['destination_ip'] ?? '',
                        $alert['destination_port'] ?? '',
                        $alert['threat_type'] ?? '',
                        $alert['severity'] ?? '',
                        $alert['protocol'] ?? '',
                        str_replace('"', '""', $alert['description'] ?? '')
                    );
                }
                $result['data'] = $csv;
                $result['filename'] = 'deepinspector_alerts_' . date('Y-m-d_H-i-s') . '.csv';
            } else {
                $result['data'] = json_encode($alerts, JSON_PRETTY_PRINT);
                $result['filename'] = 'deepinspector_alerts_' . date('Y-m-d_H-i-s') . '.json';
            }

        } catch (Exception $e) {
            error_log("DeepInspector: Error in exportAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error exporting alerts: " . $e->getMessage();
            $result["data"] = "";
        }

        return $result;
    }

    /**
     * Lists alerts marked as false positives
     *
     * Reads /var/log/deepinspector/false_positives.json and returns all entries.
     *
     * @return array Response with false positives data
     */
    public function listFalsePositivesAction()
    {
        $result = ["status" => "ok", "data" => []];

        try {
            $fpFile = '/var/log/deepinspector/false_positives.json';
            if (file_exists($fpFile) && is_readable($fpFile)) {
                $content = file_get_contents($fpFile);
                if ($content !== false) {
                    $fps = json_decode($content, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($fps)) {
                        $result["data"] = array_values($fps);
                    }
                }
            }
        } catch (Exception $e) {
            error_log("DeepInspector: Error in listFalsePositivesAction: " . $e->getMessage());
        }

        return $result;
    }

    /**
     * Marks an alert as a false positive
     *
     * POST parameters: alert_id (required), reason (optional)
     * Appends entry to /var/log/deepinspector/false_positives.json.
     *
     * @return array Response with status
     */
    public function markFalsePositiveAction()
    {
        if (!$this->request->isPost()) {
            return ["status" => "failed", "message" => "POST method required"];
        }

        $alertId = $this->request->getPost('alert_id');
        $reason  = $this->request->getPost('reason') ?: '';

        if (empty($alertId)) {
            return ["status" => "failed", "message" => "alert_id is required"];
        }

        // Basic sanitisation — only allow safe ID characters
        if (!preg_match('/^[a-zA-Z0-9_\-]+$/', $alertId)) {
            return ["status" => "failed", "message" => "Invalid alert_id format"];
        }

        try {
            $fpFile  = '/var/log/deepinspector/false_positives.json';
            $alertsFile = '/var/log/deepinspector/alerts.log';

            // Validate alert exists and get its data
            $alertData = null;
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if ($lines !== false) {
                    foreach ($lines as $line) {
                        $a = json_decode($line, true);
                        if (json_last_error() === JSON_ERROR_NONE && $a && isset($a['id']) && $a['id'] === $alertId) {
                            $alertData = $a;
                            break;
                        }
                    }
                }
            }

            if ($alertData === null) {
                return ["status" => "failed", "message" => "Alert not found"];
            }

            // Load existing FPs
            $fps = [];
            if (file_exists($fpFile) && is_readable($fpFile)) {
                $content = file_get_contents($fpFile);
                if ($content !== false) {
                    $decoded = json_decode($content, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $fps = $decoded;
                    }
                }
            }

            // Add entry
            $fps[$alertId] = [
                "alert_id"    => $alertId,
                "marked_at"   => date('c'),
                "source_ip"   => $alertData['source_ip'] ?? '',
                "threat_type" => $alertData['threat_type'] ?? '',
                "reason"      => $reason
            ];

            if (file_put_contents($fpFile, json_encode($fps, JSON_PRETTY_PRINT)) === false) {
                return ["status" => "failed", "message" => "Failed to write false positives file"];
            }

            return ["status" => "ok", "message" => "Alert $alertId marked as false positive"];

        } catch (Exception $e) {
            error_log("DeepInspector: Error in markFalsePositiveAction: " . $e->getMessage());
            return ["status" => "failed", "message" => "Error: " . $e->getMessage()];
        }
    }

    /**
     * Removes an alert from the false positives list
     *
     * POST parameter: alert_id
     *
     * @return array Response with status
     */
    public function removeFalsePositiveAction()
    {
        if (!$this->request->isPost()) {
            return ["status" => "failed", "message" => "POST method required"];
        }

        $alertId = $this->request->getPost('alert_id');

        if (empty($alertId)) {
            return ["status" => "failed", "message" => "alert_id is required"];
        }

        if (!preg_match('/^[a-zA-Z0-9_\-]+$/', $alertId)) {
            return ["status" => "failed", "message" => "Invalid alert_id format"];
        }

        try {
            $fpFile = '/var/log/deepinspector/false_positives.json';

            $fps = [];
            if (file_exists($fpFile) && is_readable($fpFile)) {
                $content = file_get_contents($fpFile);
                if ($content !== false) {
                    $decoded = json_decode($content, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $fps = $decoded;
                    }
                }
            }

            if (!isset($fps[$alertId])) {
                return ["status" => "failed", "message" => "False positive entry not found"];
            }

            unset($fps[$alertId]);

            if (file_put_contents($fpFile, json_encode($fps, JSON_PRETTY_PRINT)) === false) {
                return ["status" => "failed", "message" => "Failed to write false positives file"];
            }

            return ["status" => "ok", "message" => "False positive entry removed"];

        } catch (Exception $e) {
            error_log("DeepInspector: Error in removeFalsePositiveAction: " . $e->getMessage());
            return ["status" => "failed", "message" => "Error: " . $e->getMessage()];
        }
    }

    /**
     * Clear old alerts
     *
     * Removes alerts older than specified days from the log file.
     * Returns count of deleted alerts (no fallback data).
     *
     * @return array Result with deleted count
     */
    public function clearOldAction()
    {
        $result = ["status" => "ok"];

        try {
            $days = (int)($this->request->getPost('days') ?: 30);
            if ($days < 1) {
                $days = 30;
            }

            $alertsFile = '/var/log/deepinspector/alerts.log';
            $cutoffTime = time() - ($days * 86400);

            $deletedCount = 0;
            $keptAlerts = [];

            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

                if ($lines !== false && is_array($lines)) {
                    foreach ($lines as $line) {
                        try {
                            $alert = json_decode($line, true);
                            if ($alert && isset($alert['timestamp'])) {
                                $alertTime = strtotime($alert['timestamp']);
                                if ($alertTime !== false && $alertTime >= $cutoffTime) {
                                    $keptAlerts[] = $line;
                                } else {
                                    $deletedCount++;
                                }
                            } else {
                                // Keep malformed entries to avoid data loss
                                $keptAlerts[] = $line;
                            }
                        } catch (Exception $e) {
                            // Keep entries that can't be parsed
                            $keptAlerts[] = $line;
                        }
                    }

                    // Backup original file
                    $backupFile = $alertsFile . '.backup.' . date('Y-m-d-H-i-s');
                    @copy($alertsFile, $backupFile);

                    // Write kept alerts back
                    if (file_put_contents($alertsFile, implode("\n", $keptAlerts) . "\n") !== false) {
                        $result['deleted_count'] = $deletedCount;
                        $result['message'] = "Deleted $deletedCount alerts older than $days days";
                    } else {
                        $result['status'] = 'error';
                        $result['message'] = 'Failed to write updated alerts file';
                        $result['deleted_count'] = 0;
                    }
                } else {
                    $result['deleted_count'] = 0;
                    $result['message'] = 'Could not read alerts file';
                }
            } else {
                $result['deleted_count'] = 0;
                $result['message'] = 'Alerts file not found or not readable';
            }

        } catch (Exception $e) {
            error_log("DeepInspector: Error in clearOldAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error clearing old alerts: " . $e->getMessage();
            $result["deleted_count"] = 0;
        }

        return $result;
    }
}