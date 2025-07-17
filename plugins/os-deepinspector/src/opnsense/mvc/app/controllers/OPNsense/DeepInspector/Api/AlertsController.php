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
                            'threat_id' => $alert['id'],
                            'timestamp' => $alert['timestamp'],
                            'source_ip' => $alert['source_ip'],
                            'destination_ip' => $alert['destination_ip'],
                            'threat_type' => $alert['threat_type'],
                            'severity' => $alert['severity'],
                            'protocol' => $alert['protocol'],
                            'description' => $alert['description'],
                            'detection_method' => $alert['detection_method'] ?? 'Unknown',
                            'industrial_context' => $alert['industrial_context'] ?? false,
                            'industrial_protocol' => $alert['industrial_protocol'] ?? null,
                            'zero_trust_triggered' => $alert['zero_trust_triggered'] ?? false,
                            'status' => 'active',
                            'first_seen' => $alert['timestamp'],
                            'last_seen' => $alert['timestamp']
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
     * Get all alerts with pagination
     * @return array alerts list
     */
    public function getAllAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $alerts = [];
            
            if (file_exists($alertsFile)) {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                
                // Get pagination parameters
                $page = $this->request->get('page', 1);
                $limit = $this->request->get('limit', 50);
                $offset = ($page - 1) * $limit;
                
                // Reverse to get newest first
                $lines = array_reverse($lines);
                $totalLines = count($lines);
                
                // Apply pagination
                $paginatedLines = array_slice($lines, $offset, $limit);
                
                foreach ($paginatedLines as $line) {
                    $alert = json_decode($line, true);
                    if ($alert) {
                        $alerts[] = [
                            'id' => $alert['id'] ?? uniqid(),
                            'timestamp' => $alert['timestamp'] ?? date('c'),
                            'source_ip' => $alert['source_ip'] ?? 'Unknown',
                            'destination_ip' => $alert['destination_ip'] ?? 'Unknown',
                            'threat_type' => $alert['threat_type'] ?? 'Unknown',
                            'severity' => $alert['severity'] ?? 'medium',
                            'protocol' => $alert['protocol'] ?? 'Unknown',
                            'description' => $alert['description'] ?? 'No description',
                            'industrial_context' => $alert['industrial_context'] ?? false
                        ];
                    }
                }
                
                $result["data"] = [
                    'alerts' => $alerts,
                    'pagination' => [
                        'page' => $page,
                        'limit' => $limit,
                        'total' => $totalLines,
                        'pages' => ceil($totalLines / $limit)
                    ]
                ];
            } else {
                $result["data"] = [
                    'alerts' => [],
                    'pagination' => [
                        'page' => 1,
                        'limit' => $limit,
                        'total' => 0,
                        'pages' => 0
                    ]
                ];
            }
            
        } catch (Exception $e) {
            $result["status"] = "error";
            $result["message"] = "Error retrieving alerts: " . $e->getMessage();
            $result["data"] = ['alerts' => [], 'pagination' => []];
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
}