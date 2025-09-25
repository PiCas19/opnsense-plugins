<?php
namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class StatisticsController
 * @package OPNsense\DeepInspector\Api
 */
class StatisticsController extends ApiControllerBase
{
    /**
     * Get comprehensive security statistics
     * @return array statistics data
     */
    public function getSecurityStatsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $threatsFile = '/var/log/deepinspector/threats.log';
            $engineFile = '/var/log/deepinspector/engine.log';
            
            $securityStats = [
                'total_threats_detected' => 0,
                'threats_blocked' => 0,
                'threats_by_severity' => [
                    'critical' => 0,
                    'high' => 0,
                    'medium' => 0,
                    'low' => 0
                ],
                'threats_by_type' => [],
                'top_threat_sources' => [],
                'blocked_ips' => [],
                'malicious_patterns' => [],
                'industrial_threats' => 0,
                'zero_trust_violations' => 0,
                'false_positives' => 0,
                'detection_accuracy' => 0
            ];
            
            // Process alerts file
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $this->processAlertsForStats($alertsFile, $securityStats);
            }
            
            // Process threats file
            if (file_exists($threatsFile) && is_readable($threatsFile)) {
                $this->processThreatsForStats($threatsFile, $securityStats);
            }
            
            // Calculate detection accuracy
            $total_detections = $securityStats['total_threats_detected'] + $securityStats['false_positives'];
            if ($total_detections > 0) {
                $securityStats['detection_accuracy'] = round(
                    ($securityStats['total_threats_detected'] / $total_detections) * 100, 2
                );
            }
            
            $result['data'] = $securityStats;
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in getSecurityStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving security statistics";
            $result["data"] = $this->getEmptySecurityStats();
        }
        
        return $result;
    }
    
    /**
     * Get network traffic statistics
     * @return array traffic statistics
     */
    public function getTrafficStatsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $engineFile = '/var/log/deepinspector/engine.log';
            $latencyFile = '/var/log/deepinspector/latency.log';
            
            $trafficStats = [
                'total_packets_analyzed' => 0,
                'total_bytes_analyzed' => 0,
                'protocols_analyzed' => [],
                'traffic_by_hour' => [],
                'top_destinations' => [],
                'bandwidth_usage' => [],
                'packet_sizes' => [
                    'small' => 0,   // < 64 bytes
                    'medium' => 0,  // 64-1500 bytes
                    'large' => 0    // > 1500 bytes
                ],
                'connection_states' => [
                    'established' => 0,
                    'syn_sent' => 0,
                    'syn_recv' => 0,
                    'fin_wait' => 0,
                    'closed' => 0
                ]
            ];
            
            // Process engine log for traffic data
            if (file_exists($engineFile) && is_readable($engineFile)) {
                $this->processEngineLogForTraffic($engineFile, $trafficStats);
            }
            
            // Process latency data
            if (file_exists($latencyFile) && is_readable($latencyFile)) {
                $this->processLatencyData($latencyFile, $trafficStats);
            }
            
            $result['data'] = $trafficStats;
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in getTrafficStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving traffic statistics";
            $result["data"] = $this->getEmptyTrafficStats();
        }
        
        return $result;
    }
    
    /**
     * Get blocking statistics and actions taken
     * @return array blocking statistics
     */
    public function getBlockingStatsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $backend = new Backend();
            
            $blockingStats = [
                'total_ips_blocked' => 0,
                'total_connections_blocked' => 0,
                'blocking_reasons' => [],
                'blocked_by_timeframe' => [
                    'last_hour' => 0,
                    'last_6h' => 0,
                    'last_24h' => 0,
                    'last_7d' => 0
                ],
                'top_blocked_sources' => [],
                'blocking_effectiveness' => 0,
                'whitelist_bypasses' => 0,
                'auto_unblocked' => 0
            ];
            
            // Get blocked IPs list
            $blockedResponse = $backend->configdpRun("deepinspector", array("list_blocked"));
            $blockedIPs = array_filter(explode("\n", trim($blockedResponse)));
            $blockingStats['total_ips_blocked'] = count($blockedIPs);
            
            // Process blocking history from alerts
            $alertsFile = '/var/log/deepinspector/alerts.log';
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $this->processBlockingHistory($alertsFile, $blockingStats);
            }
            
            $result['data'] = $blockingStats;
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in getBlockingStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving blocking statistics";
            $result["data"] = $this->getEmptyBlockingStats();
        }
        
        return $result;
    }
    
    /**
     * Get industrial protocol statistics
     * @return array industrial statistics
     */
    public function getIndustrialStatsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $industrialStats = [
                'protocols_detected' => [
                    'modbus' => 0,
                    'dnp3' => 0,
                    'opcua' => 0,
                    'bacnet' => 0,
                    'ethernetip' => 0
                ],
                'industrial_threats' => 0,
                'scada_anomalies' => 0,
                'unauthorized_commands' => 0,
                'protocol_violations' => 0,
                'device_fingerprints' => [],
                'control_systems_identified' => [],
                'critical_operations_monitored' => 0
            ];
            
            // Process industrial-specific logs
            $alertsFile = '/var/log/deepinspector/alerts.log';
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $this->processIndustrialData($alertsFile, $industrialStats);
            }
            
            $result['data'] = $industrialStats;
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in getIndustrialStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving industrial statistics";
            $result["data"] = $this->getEmptyIndustrialStats();
        }
        
        return $result;
    }
    
    /**
     * Get suspicious packet analysis
     * @return array suspicious packets data
     */
    public function getSuspiciousPacketsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $timeFilter = $this->request->get('timeRange') ?: '24h';
            $severityFilter = $this->request->get('severity') ?: 'all';
            $limit = max(1, min(100, intval($this->request->get('limit') ?: 50)));
            
            $suspiciousPackets = [];
            $alertsFile = '/var/log/deepinspector/alerts.log';
            
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $timeLimit = $this->calculateTimeLimit($timeFilter);
                $suspiciousPackets = $this->extractSuspiciousPackets($alertsFile, $timeLimit, $severityFilter, $limit);
            }
            
            $result['data'] = [
                'packets' => $suspiciousPackets,
                'total_count' => count($suspiciousPackets),
                'high_risk_count' => count(array_filter($suspiciousPackets, function($p) {
                    return in_array($p['risk_level'], ['critical', 'high']);
                })),
                'patterns_detected' => $this->getDetectedPatterns($suspiciousPackets)
            ];
            
        } catch (Exception $e) {
            error_log("DeepInspector: Error in getSuspiciousPacketsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving suspicious packets";
            $result["data"] = ['packets' => [], 'total_count' => 0, 'high_risk_count' => 0, 'patterns_detected' => []];
        }
        
        return $result;
    }
    
    /**
     * Process alerts file for security statistics
     */
    private function processAlertsForStats($alertsFile, &$stats)
    {
        $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;
        
        $threatTypes = [];
        $threatSources = [];
        $blockedIPs = [];
        $patterns = [];
        
        foreach (array_slice($lines, -1000) as $line) {
            $alert = json_decode(trim($line), true);
            if (!$alert) continue;
            
            $stats['total_threats_detected']++;
            
            // Count by severity
            $severity = $alert['severity'] ?? 'medium';
            if (isset($stats['threats_by_severity'][$severity])) {
                $stats['threats_by_severity'][$severity]++;
            }
            
            // Count by type
            $threatType = $alert['threat_type'] ?? 'unknown';
            $threatTypes[$threatType] = ($threatTypes[$threatType] ?? 0) + 1;
            
            // Track sources
            $sourceIP = $alert['source_ip'] ?? 'unknown';
            $threatSources[$sourceIP] = ($threatSources[$sourceIP] ?? 0) + 1;
            
            // Industrial context
            if ($alert['industrial_context'] ?? false) {
                $stats['industrial_threats']++;
            }
            
            // Zero trust violations
            if ($alert['zero_trust_triggered'] ?? false) {
                $stats['zero_trust_violations']++;
            }
            
            // Pattern tracking
            if (isset($alert['pattern'])) {
                $patterns[$alert['pattern']] = ($patterns[$alert['pattern']] ?? 0) + 1;
            }
            
            // Check if blocked
            if (isset($alert['action']) && $alert['action'] === 'blocked') {
                $stats['threats_blocked']++;
                $blockedIPs[$sourceIP] = true;
            }
        }
        
        // Sort and limit results
        arsort($threatTypes);
        arsort($threatSources);
        arsort($patterns);
        
        $stats['threats_by_type'] = array_slice($threatTypes, 0, 10, true);
        $stats['top_threat_sources'] = array_slice($threatSources, 0, 10, true);
        $stats['blocked_ips'] = array_keys($blockedIPs);
        $stats['malicious_patterns'] = array_slice($patterns, 0, 10, true);
    }
    
    /**
     * Extract suspicious packets with details
     */
    private function extractSuspiciousPackets($alertsFile, $timeLimit, $severityFilter, $limit)
    {
        $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return [];
        
        $packets = [];
        
        foreach (array_reverse(array_slice($lines, -500)) as $line) {
            $alert = json_decode(trim($line), true);
            if (!$alert) continue;
            
            // Time filter
            if ($timeLimit > 0) {
                $alertTime = strtotime($alert['timestamp'] ?? '');
                if ($alertTime === false || $alertTime < $timeLimit) continue;
            }
            
            // Severity filter
            if ($severityFilter !== 'all') {
                $alertSeverity = $alert['severity'] ?? 'medium';
                if ($alertSeverity !== $severityFilter) continue;
            }
            
            $packets[] = [
                'id' => $alert['id'] ?? uniqid(),
                'timestamp' => $alert['timestamp'] ?? date('c'),
                'source_ip' => $alert['source_ip'] ?? 'Unknown',
                'source_port' => $alert['source_port'] ?? null,
                'destination_ip' => $alert['destination_ip'] ?? 'Unknown',
                'destination_port' => $alert['destination_port'] ?? null,
                'protocol' => $alert['protocol'] ?? 'Unknown',
                'threat_type' => $alert['threat_type'] ?? 'Unknown',
                'risk_level' => $alert['severity'] ?? 'medium',
                'pattern_matched' => $alert['pattern'] ?? 'N/A',
                'payload_size' => $alert['payload_size'] ?? 0,
                'flags' => $alert['flags'] ?? [],
                'industrial_context' => $alert['industrial_context'] ?? false,
                'description' => $alert['description'] ?? 'Suspicious packet detected',
                'action_taken' => $alert['action'] ?? 'logged',
                'confidence_score' => $alert['confidence'] ?? 75
            ];
            
            if (count($packets) >= $limit) break;
        }
        
        return $packets;
    }
    
    /**
     * Get detected patterns summary
     */
    private function getDetectedPatterns($packets)
    {
        $patterns = [];
        
        foreach ($packets as $packet) {
            $pattern = $packet['pattern_matched'];
            if ($pattern !== 'N/A') {
                $patterns[$pattern] = ($patterns[$pattern] ?? 0) + 1;
            }
        }
        
        arsort($patterns);
        return array_slice($patterns, 0, 5, true);
    }
    
    /**
     * Calculate time limit based on filter
     */
    private function calculateTimeLimit($timeFilter)
    {
        $now = time();
        
        switch ($timeFilter) {
            case '1h': return $now - 3600;
            case '6h': return $now - 21600;
            case '24h': return $now - 86400;
            case '7d': return $now - 604800;
            case '30d': return $now - 2592000;
            default: return 0;
        }
    }
    
    // Empty stats methods
    private function getEmptySecurityStats()
    {
        return [
            'total_threats_detected' => 0,
            'threats_blocked' => 0,
            'threats_by_severity' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
            'threats_by_type' => [],
            'top_threat_sources' => [],
            'blocked_ips' => [],
            'malicious_patterns' => [],
            'industrial_threats' => 0,
            'zero_trust_violations' => 0,
            'false_positives' => 0,
            'detection_accuracy' => 0
        ];
    }
    
    private function getEmptyTrafficStats()
    {
        return [
            'total_packets_analyzed' => 0,
            'total_bytes_analyzed' => 0,
            'protocols_analyzed' => [],
            'traffic_by_hour' => [],
            'top_destinations' => [],
            'bandwidth_usage' => [],
            'packet_sizes' => ['small' => 0, 'medium' => 0, 'large' => 0],
            'connection_states' => ['established' => 0, 'syn_sent' => 0, 'syn_recv' => 0, 'fin_wait' => 0, 'closed' => 0]
        ];
    }
    
    private function getEmptyBlockingStats()
    {
        return [
            'total_ips_blocked' => 0,
            'total_connections_blocked' => 0,
            'blocking_reasons' => [],
            'blocked_by_timeframe' => ['last_hour' => 0, 'last_6h' => 0, 'last_24h' => 0, 'last_7d' => 0],
            'top_blocked_sources' => [],
            'blocking_effectiveness' => 0,
            'whitelist_bypasses' => 0,
            'auto_unblocked' => 0
        ];
    }
    
    private function getEmptyIndustrialStats()
    {
        return [
            'protocols_detected' => ['modbus' => 0, 'dnp3' => 0, 'opcua' => 0, 'bacnet' => 0, 'ethernetip' => 0],
            'industrial_threats' => 0,
            'scada_anomalies' => 0,
            'unauthorized_commands' => 0,
            'protocol_violations' => 0,
            'device_fingerprints' => [],
            'control_systems_identified' => [],
            'critical_operations_monitored' => 0
        ];
    }
    
    // Placeholder methods for additional processing
    private function processThreatsForStats($threatsFile, &$stats) { /* Implementation */ }
    private function processEngineLogForTraffic($engineFile, &$stats) { /* Implementation */ }
    private function processLatencyData($latencyFile, &$stats) { /* Implementation */ }
    private function processBlockingHistory($alertsFile, &$stats) { /* Implementation */ }
    private function processIndustrialData($alertsFile, &$stats) { /* Implementation */ }
}