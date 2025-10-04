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
     * Get alerts list with filtering and pagination
     * @return array alerts list
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
                            
                            if ($alert && is_array($alert) && $this->matchesFilters($alert, $severityFilter, $typeFilter, $sourceFilter, $timeLimit)) {
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
                                    'zero_trust_triggered' => $alert['zero_trust_triggered'] ?? false,
                                    'detection_method' => $alert['detection_method'] ?? 'Unknown'
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
                    error_log("DeepInspector: Could not read alerts file: $alertsFile");
                    $result["data"] = [];
                    $result["pagination"] = [
                        'page' => 1,
                        'limit' => $limit,
                        'total' => 0,
                        'pages' => 0
                    ];
                    $result["message"] = "Could not read alerts file";
                }
            } else {
                $result["data"] = [];
                $result["pagination"] = [
                    'page' => 1,
                    'limit' => $limit,
                    'total' => 0,
                    'pages' => 0
                ];
                if (!file_exists($alertsFile)) {
                    $result["message"] = "Alerts file does not exist";
                } else {
                    $result["message"] = "Alerts file is not readable";
                }
            }
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in listAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving alerts: " . $e->getMessage();
            $result["data"] = [];
            $result["pagination"] = [
                'page' => 1,
                'limit' => 50,
                'total' => 0,
                'pages' => 0
            ];
        } catch (Error $e) {
            error_log("DeepInspector: Fatal error in listAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Fatal error retrieving alerts";
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
     * Get threat details by ID
     * @param string $threatId threat identifier
     * @return array threat details
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
     * Get all alerts with pagination (alias for listAction)
     * @return array alerts list
     */
    public function getAllAction()
    {
        return $this->listAction();
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
}