<?php
namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class AlertsController
 * @package OPNsense\DeepInspector
 */
class AlertsController extends ApiControllerBase
{
    /**
     * Get threat details by ID
     * @param string $threatId threat identifier
     * @return array threat details
     */
    public function threatDetailsAction($threatId)
    {
        $result = ["status" => "failed"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                
                foreach ($lines as $line) {
                    $alert = json_decode($line, true);
                    if ($alert && isset($alert['id']) && $alert['id'] === $threatId) {
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
                }
            }
            
            if ($result["status"] === "failed") {
                $result["message"] = "Threat not found";
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error retrieving threat details: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Get alerts list with filtering and pagination
     * @return array alerts list
     */
    public function listAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $alerts = [];
            
            // Get filter parameters
            $severityFilter = $this->request->get('severity', 'all');
            $typeFilter = $this->request->get('type', 'all');
            $timeFilter = $this->request->get('time', '24h');
            $sourceFilter = $this->request->get('source', '');
            $page = intval($this->request->get('page', 1));
            $limit = intval($this->request->get('limit', 50));
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                $filteredAlerts = [];
                
                // Calculate time filter
                $timeLimit = $this->calculateTimeLimit($timeFilter);
                
                foreach ($lines as $line) {
                    $alert = json_decode($line, true);
                    if ($alert && $this->matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)) {
                        $filteredAlerts[] = [
                            'id' => $alert['id'] ?? uniqid(),
                            'timestamp' => $alert['timestamp'] ?? date('c'),
                            'source_ip' => $alert['source_ip'] ?? 'Unknown',
                            'source_port' => $alert['source_port'] ?? null,
                            'destination_ip' => $alert['destination_ip'] ?? 'Unknown',
                            'destination_port' => $alert['destination_port'] ?? null,
                            'threat_type' => $alert['threat_type'] ?? 'Unknown',
                            'severity' => $alert['severity'] ?? 'medium',
                            'protocol' => $alert['protocol'] ?? 'Unknown',
                            'description' => $alert['description'] ?? 'No description',
                            'industrial_context' => $alert['industrial_context'] ?? false,
                            'detection_method' => $alert['detection_method'] ?? 'Unknown'
                        ];
                    }
                }
                
                // Sort by timestamp (newest first)
                usort($filteredAlerts, function($a, $b) {
                    return strtotime($b['timestamp']) - strtotime($a['timestamp']);
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
                    'pages' => ceil($totalAlerts / $limit)
                ];
            } else {
                $result["data"] = [];
                $result["pagination"] = [
                    'page' => 1,
                    'limit' => $limit,
                    'total' => 0,
                    'pages' => 0
                ];
            }
            
        } catch (Exception $e) {
            $result["status"] = "error";
            $result["message"] = "Error retrieving alerts: " . $e->getMessage();
            $result["data"] = [];
        }
        
        return $result;
    }
    
    /**
     * Get all alerts with pagination (alias for listAction)
     * @return array alerts list
     */
    public function getAllAction()
    {
        return $this->listAction();
    }
    
    /**
     * Export alerts to CSV
     * @return array export result
     */
    public function exportAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            
            // Get filter parameters
            $severityFilter = $this->request->get('severity', 'all');
            $typeFilter = $this->request->get('type', 'all');
            $timeFilter = $this->request->get('time', '24h');
            $sourceFilter = $this->request->get('source', '');
            $format = $this->request->get('format', 'csv');
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                $filteredAlerts = [];
                
                // Calculate time filter
                $timeLimit = $this->calculateTimeLimit($timeFilter);
                
                foreach ($lines as $line) {
                    $alert = json_decode($line, true);
                    if ($alert && $this->matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)) {
                        $filteredAlerts[] = $alert;
                    }
                }
                
                // Sort by timestamp (newest first)
                usort($filteredAlerts, function($a, $b) {
                    return strtotime($b['timestamp']) - strtotime($a['timestamp']);
                });
                
                if ($format === 'csv') {
                    $csvData = $this->generateCSV($filteredAlerts);
                    $result["status"] = "ok";
                    $result["data"] = $csvData;
                } else {
                    $result["status"] = "ok";
                    $result["data"] = json_encode($filteredAlerts, JSON_PRETTY_PRINT);
                }
            } else {
                $result["message"] = "Alerts file not found";
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error exporting alerts: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Clear old alerts
     * @return array result
     */
    public function clearOldAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $backupFile = $alertsFile . '.backup.' . date('Y-m-d');
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                $cutoffTime = time() - (30 * 24 * 60 * 60); // 30 days ago
                $newLines = [];
                $removedCount = 0;
                
                foreach ($lines as $line) {
                    $alert = json_decode($line, true);
                    if ($alert && isset($alert['timestamp'])) {
                        $alertTime = strtotime($alert['timestamp']);
                        if ($alertTime > $cutoffTime) {
                            $newLines[] = $line;
                        } else {
                            $removedCount++;
                        }
                    }
                }
                
                // Backup old file
                copy($alertsFile, $backupFile);
                
                // Write new file
                file_put_contents($alertsFile, implode("\n", $newLines) . "\n");
                
                $result["status"] = "ok";
                $result["message"] = "Removed $removedCount old alerts";
            } else {
                $result["message"] = "Alerts file not found";
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error clearing old alerts: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Get alert statistics
     * @return array alert statistics
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
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                $threatTypes = [];
                $sources = [];
                $hourly = [];
                
                foreach ($lines as $line) {
                    $alert = json_decode($line, true);
                    if ($alert) {
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
                }
                
                // Sort and limit results
                arsort($threatTypes);
                arsort($sources);
                ksort($hourly);
                
                $stats['threat_types'] = array_slice($threatTypes, 0, 10, true);
                $stats['top_sources'] = array_slice($sources, 0, 10, true);
                $stats['hourly_distribution'] = $hourly;
            }
            
            $result["data"] = $stats;
            
        } catch (Exception $e) {
            $result["status"] = "error";
            $result["message"] = "Error retrieving alert statistics: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Mark alert as resolved
     * @param string $alertId alert identifier
     * @return array result
     */
    public function resolveAction($alertId)
    {
        $result = ["status" => "failed"];
        
        try {
            // For now, just log the resolution
            $resolvedFile = '/var/log/deepinspector/resolved.log';
            $resolution = [
                'alert_id' => $alertId,
                'resolved_at' => date('c'),
                'resolved_by' => 'admin'
            ];
            
            file_put_contents($resolvedFile, json_encode($resolution) . "\n", FILE_APPEND | LOCK_EX);
            
            $result["status"] = "ok";
            $result["message"] = "Alert marked as resolved";
            
        } catch (Exception $e) {
            $result["message"] = "Error resolving alert: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Delete alert
     * @param string $alertId alert identifier
     * @return array result
     */
    public function deleteAction($alertId)
    {
        $result = ["status" => "failed"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $tempFile = $alertsFile . '.tmp';
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                $newLines = [];
                
                foreach ($lines as $line) {
                    $alert = json_decode($line, true);
                    if (!$alert || !isset($alert['id']) || $alert['id'] !== $alertId) {
                        $newLines[] = $line;
                    }
                }
                
                file_put_contents($tempFile, implode("\n", $newLines) . "\n");
                rename($tempFile, $alertsFile);
                
                $result["status"] = "ok";
                $result["message"] = "Alert deleted successfully";
            } else {
                $result["message"] = "Alerts file not found";
            }
            
        } catch (Exception $e) {
            $result["message"] = "Error deleting alert: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Helper method to calculate time limit based on filter
     * @param string $timeFilter time filter value
     * @return int timestamp limit
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
     * Helper method to check if alert matches filters
     * @param array $alert alert data
     * @param string $severityFilter severity filter
     * @param string $typeFilter type filter
     * @param string $sourceFilter source IP filter
     * @param int $timeLimit time limit timestamp
     * @return bool true if matches
     */
    private function matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)
    {
        // Time filter
        if ($timeLimit > 0) {
            $alertTime = strtotime($alert['timestamp'] ?? '');
            if ($alertTime < $timeLimit) {
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
     * Generate CSV from alerts data
     * @param array $alerts alerts data
     * @return string CSV content
     */
    private function generateCSV($alerts)
    {
        $csv = "Timestamp,Severity,Threat Type,Source IP,Source Port,Destination IP,Destination Port,Protocol,Description,Industrial Context,Detection Method\n";
        
        foreach ($alerts as $alert) {
            $csv .= sprintf('"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"' . "\n",
                $alert['timestamp'] ?? '',
                $alert['severity'] ?? 'medium',
                $alert['threat_type'] ?? 'unknown',
                $alert['source_ip'] ?? '',
                $alert['source_port'] ?? '',
                $alert['destination_ip'] ?? '',
                $alert['destination_port'] ?? '',
                $alert['protocol'] ?? '',
                str_replace('"', '""', $alert['description'] ?? ''),
                ($alert['industrial_context'] ?? false) ? 'Yes' : 'No',
                $alert['detection_method'] ?? 'Unknown'
            );
        }
        
        return $csv;
    }
}