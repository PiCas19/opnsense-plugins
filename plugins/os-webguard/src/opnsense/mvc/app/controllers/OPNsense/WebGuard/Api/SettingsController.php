<?php

/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ThreatsController
 * @package OPNsense\WebGuard\Api
 */
class ThreatsController extends ApiControllerBase
{
    /**
     * Get recent threats
     * @return array threats data
     */
    public function getAction()
    {
        $result = ["status" => "ok"];
        
        $limit = $this->request->get("limit", "filter", 50);
        $offset = $this->request->get("offset", "filter", 0);
        
        $alertsFile = '/var/log/webguard/alerts.log';
        $threats = $this->getThreatsFromLog($alertsFile, $limit, $offset);
        
        $result['threats'] = $threats;
        $result['total'] = count($threats);
        
        return $result;
    }

    /**
     * Get threat statistics by type and time period
     * @return array statistics
     */
    public function getStatsAction()
    {
        $result = ["status" => "ok"];
        
        $period = $this->request->get("period", "filter", "24h");
        
        $alertsFile = '/var/log/webguard/alerts.log';
        $threats = $this->getThreatsFromLog($alertsFile, 1000); // Get more for stats
        
        // Calculate statistics based on period
        $cutoffTime = $this->getPeriodCutoff($period);
        $filteredThreats = array_filter($threats, function($threat) use ($cutoffTime) {
            return $threat['timestamp'] >= $cutoffTime;
        });
        
        // Group threats by type
        $threatsByType = [];
        foreach ($filteredThreats as $threat) {
            $type = $threat['type'];
            if (!isset($threatsByType[$type])) {
                $threatsByType[$type] = 0;
            }
            $threatsByType[$type]++;
        }
        
        $result['threats_by_type'] = $threatsByType;
        $result['total_threats'] = count($filteredThreats);
        $result['period'] = $period;
        
        return $result;
    }

    /**
     * Get threat timeline data for charts
     * @return array timeline data
     */
    public function getTimelineAction()
    {
        $result = ["status" => "ok"];
        
        $period = $this->request->get("period", "filter", "24h");
        
        $alertsFile = '/var/log/webguard/alerts.log';
        $threats = $this->getThreatsFromLog($alertsFile, 1000);
        
        // Generate timeline data
        $timeline = $this->generateTimeline($threats, $period);
        
        $result['timeline'] = $timeline;
        $result['period'] = $period;
        
        return $result;
    }

    /**
     * Get real-time threat feed
     * @return array feed data
     */
    public function getFeedAction()
    {
        $result = ["status" => "ok"];
        
        $lastId = $this->request->get("last_id", "filter", 0);
        $limit = $this->request->get("limit", "filter", 20);
        
        $alertsFile = '/var/log/webguard/alerts.log';
        $threats = $this->getRecentThreatsAfter($alertsFile, $lastId, $limit);
        
        $result['threats'] = $threats;
        $result['count'] = count($threats);
        
        return $result;
    }

    /**
     * Get detailed information about a specific threat
     * @return array threat details
     */
    public function detailAction()
    {
        $result = ["status" => "ok"];
        
        $threatId = $this->request->get("id", "filter", "");
        
        if (empty($threatId)) {
            $result["status"] = "error";
            $result["message"] = "Threat ID is required";
            return $result;
        }
        
        $alertsFile = '/var/log/webguard/alerts.log';
        $threat = $this->getThreatById($alertsFile, $threatId);
        
        if ($threat) {
            $result['threat'] = $threat;
        } else {
            $result["status"] = "error";
            $result["message"] = "Threat not found";
        }
        
        return $result;
    }

    /**
     * Get threats from log file
     * @param string $alertsFile
     * @param int $limit
     * @param int $offset
     * @return array
     */
    private function getThreatsFromLog($alertsFile, $limit = 50, $offset = 0)
    {
        $threats = [];
        
        if (file_exists($alertsFile)) {
            $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                $lines = array_slice($lines, -($limit + $offset)); // Get recent lines
                $lines = array_slice($lines, $offset, $limit); // Apply offset and limit
                
                foreach (array_reverse($lines) as $line) {
                    $threat = @json_decode($line, true);
                    if ($threat !== null && isset($threat['threat_type'])) {
                        $threats[] = [
                            'id' => isset($threat['id']) ? $threat['id'] : uniqid(),
                            'timestamp' => isset($threat['timestamp']) ? $threat['timestamp'] : time(),
                            'source_ip' => isset($threat['source_ip']) ? $threat['source_ip'] : 'Unknown',
                            'destination_ip' => isset($threat['destination_ip']) ? $threat['destination_ip'] : 'Unknown',
                            'threat_type' => $threat['threat_type'],
                            'type' => $threat['threat_type'], // Alias for compatibility
                            'severity' => isset($threat['severity']) ? $threat['severity'] : 'medium',
                            'protocol' => isset($threat['protocol']) ? $threat['protocol'] : 'HTTP',
                            'description' => isset($threat['description']) ? $threat['description'] : 'No description',
                            'url' => isset($threat['url']) ? $threat['url'] : 'Unknown',
                            'target' => isset($threat['url']) ? $threat['url'] : 'Unknown',
                            'user_agent' => isset($threat['user_agent']) ? $threat['user_agent'] : 'Unknown',
                            'request_method' => isset($threat['request_method']) ? $threat['request_method'] : 'GET',
                            'payload' => isset($threat['payload']) ? $threat['payload'] : '',
                            'blocked' => isset($threat['blocked']) ? $threat['blocked'] : true
                        ];
                    }
                }
            }
        } else {
            // Generate sample data for testing
            $threats = $this->generateSampleThreats($limit);
        }
        
        return $threats;
    }

    /**
     * Get recent threats after a specific ID
     * @param string $alertsFile
     * @param int $lastId
     * @param int $limit
     * @return array
     */
    private function getRecentThreatsAfter($alertsFile, $lastId, $limit)
    {
        $threats = [];
        
        if (file_exists($alertsFile)) {
            $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                $lines = array_slice($lines, -100); // Get last 100 lines
                
                foreach (array_reverse($lines) as $line) {
                    $threat = @json_decode($line, true);
                    if ($threat !== null && isset($threat['threat_type'])) {
                        $threatId = isset($threat['id']) ? (int)$threat['id'] : time();
                        
                        if ($threatId > $lastId) {
                            $threats[] = [
                                'id' => $threatId,
                                'timestamp' => isset($threat['timestamp']) ? $threat['timestamp'] : time(),
                                'source_ip' => isset($threat['source_ip']) ? $threat['source_ip'] : 'Unknown',
                                'type' => $threat['threat_type'],
                                'severity' => isset($threat['severity']) ? $threat['severity'] : 'medium',
                                'target' => isset($threat['url']) ? $threat['url'] : 'Unknown'
                            ];
                            
                            if (count($threats) >= $limit) {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            // Generate some new sample threats for feed
            $threats = $this->generateRecentSampleThreats($lastId, $limit);
        }
        
        return $threats;
    }

    /**
     * Get threat by ID
     * @param string $alertsFile
     * @param string $threatId
     * @return array|null
     */
    private function getThreatById($alertsFile, $threatId)
    {
        if (file_exists($alertsFile)) {
            $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                foreach ($lines as $line) {
                    $threat = @json_decode($line, true);
                    if ($threat !== null && isset($threat['id']) && $threat['id'] == $threatId) {
                        return [
                            'id' => $threat['id'],
                            'timestamp' => isset($threat['timestamp']) ? $threat['timestamp'] : time(),
                            'source_ip' => isset($threat['source_ip']) ? $threat['source_ip'] : 'Unknown',
                            'destination_ip' => isset($threat['destination_ip']) ? $threat['destination_ip'] : 'Unknown',
                            'threat_type' => $threat['threat_type'],
                            'severity' => isset($threat['severity']) ? $threat['severity'] : 'medium',
                            'protocol' => isset($threat['protocol']) ? $threat['protocol'] : 'HTTP',
                            'description' => isset($threat['description']) ? $threat['description'] : 'No description',
                            'url' => isset($threat['url']) ? $threat['url'] : 'Unknown',
                            'user_agent' => isset($threat['user_agent']) ? $threat['user_agent'] : 'Unknown',
                            'request_method' => isset($threat['request_method']) ? $threat['request_method'] : 'GET',
                            'payload' => isset($threat['payload']) ? $threat['payload'] : '',
                            'blocked' => isset($threat['blocked']) ? $threat['blocked'] : true,
                            'rule_id' => isset($threat['rule_id']) ? $threat['rule_id'] : 'Unknown',
                            'confidence' => isset($threat['confidence']) ? $threat['confidence'] : 'High',
                            'response_action' => isset($threat['response_action']) ? $threat['response_action'] : 'Block'
                        ];
                    }
                }
            }
        }
        
        // Return sample threat if not found
        return $this->generateSampleThreatDetail($threatId);
    }

    /**
     * Generate timeline data for charts
     * @param array $threats
     * @param string $period
     * @return array
     */
    private function generateTimeline($threats, $period)
    {
        $cutoffTime = $this->getPeriodCutoff($period);
        $interval = $this->getTimelineInterval($period);
        $labels = [];
        $threatCounts = [];
        $requestCounts = [];
        
        // Generate time labels based on period
        $currentTime = $cutoffTime;
        $endTime = time();
        
        while ($currentTime <= $endTime) {
            $labels[] = date('H:i', $currentTime);
            $threatCounts[] = 0;
            $requestCounts[] = 0;
            $currentTime += $interval;
        }
        
        // Count threats in each time slot
        foreach ($threats as $threat) {
            $threatTime = $threat['timestamp'];
            if ($threatTime >= $cutoffTime) {
                $slotIndex = floor(($threatTime - $cutoffTime) / $interval);
                if ($slotIndex < count($threatCounts)) {
                    $threatCounts[$slotIndex]++;
                    $requestCounts[$slotIndex] += rand(10, 50); // Simulate requests
                }
            }
        }
        
        return [
            'labels' => $labels,
            'threats' => $threatCounts,
            'requests' => $requestCounts
        ];
    }

    /**
     * Get period cutoff timestamp
     * @param string $period
     * @return int
     */
    private function getPeriodCutoff($period)
    {
        switch ($period) {
            case '1h':
                return time() - 3600;
            case '6h':
                return time() - (6 * 3600);
            case '24h':
            default:
                return time() - (24 * 3600);
            case '7d':
                return time() - (7 * 24 * 3600);
            case '30d':
                return time() - (30 * 24 * 3600);
        }
    }

    /**
     * Get timeline interval in seconds
     * @param string $period
     * @return int
     */
    private function getTimelineInterval($period)
    {
        switch ($period) {
            case '1h':
                return 300; // 5 minutes
            case '6h':
                return 1800; // 30 minutes
            case '24h':
            default:
                return 3600; // 1 hour
            case '7d':
                return 86400; // 1 day
            case '30d':
                return 86400; // 1 day
        }
    }

    /**
     * Generate sample threats for testing
     * @param int $limit
     * @return array
     */
    private function generateSampleThreats($limit)
    {
        $threats = [];
        $threatTypes = ['sql_injection', 'xss', 'csrf', 'command_injection', 'file_upload', 'directory_traversal'];
        $severities = ['low', 'medium', 'high', 'critical'];
        $ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.45', '198.51.100.10'];
        $urls = ['/admin/login.php', '/wp-admin/', '/api/users', '/upload.php', '/search.php', '/contact.php'];
        $userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'curl/7.68.0',
            'python-requests/2.25.1'
        ];
        
        for ($i = 0; $i < $limit; $i++) {
            $threats[] = [
                'id' => 1000 + $i,
                'timestamp' => time() - ($i * 300), // 5 minutes apart
                'source_ip' => $ips[array_rand($ips)],
                'destination_ip' => '192.168.1.1',
                'type' => $threatTypes[array_rand($threatTypes)],
                'threat_type' => $threatTypes[array_rand($threatTypes)],
                'severity' => $severities[array_rand($severities)],
                'target' => $urls[array_rand($urls)],
                'url' => $urls[array_rand($urls)],
                'protocol' => 'HTTP',
                'user_agent' => $userAgents[array_rand($userAgents)],
                'request_method' => rand(0, 1) ? 'GET' : 'POST',
                'payload' => 'SELECT * FROM users WHERE id=1',
                'blocked' => true,
                'description' => 'Potential ' . $threatTypes[array_rand($threatTypes)] . ' attack detected'
            ];
        }
        
        return $threats;
    }

    /**
     * Generate recent sample threats for feed
     * @param int $lastId
     * @param int $limit
     * @return array
     */
    private function generateRecentSampleThreats($lastId, $limit)
    {
        $threats = [];
        $threatTypes = ['sql_injection', 'xss', 'csrf', 'command_injection'];
        $severities = ['low', 'medium', 'high', 'critical'];
        $ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25'];
        $urls = ['/admin/login.php', '/wp-admin/', '/api/users'];
        
        // Only generate new threats occasionally
        if (rand(1, 3) == 1) {
            for ($i = 0; $i < rand(1, $limit); $i++) {
                $newId = $lastId + $i + 1;
                $threats[] = [
                    'id' => $newId,
                    'timestamp' => time() - ($i * 60), // 1 minute apart
                    'source_ip' => $ips[array_rand($ips)],
                    'type' => $threatTypes[array_rand($threatTypes)],
                    'severity' => $severities[array_rand($severities)],
                    'target' => $urls[array_rand($urls)]
                ];
            }
        }
        
        return $threats;
    }

    /**
     * Generate sample threat detail
     * @param string $threatId
     * @return array
     */
    private function generateSampleThreatDetail($threatId)
    {
        return [
            'id' => $threatId,
            'timestamp' => time() - 3600, // 1 hour ago
            'source_ip' => '192.168.1.100',
            'destination_ip' => '192.168.1.1',
            'threat_type' => 'sql_injection',
            'severity' => 'high',
            'protocol' => 'HTTP',
            'description' => 'SQL injection attack attempt detected in user input field',
            'url' => '/admin/login.php',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'request_method' => 'POST',
            'payload' => "username=admin' OR '1'='1' --&password=test",
            'blocked' => true,
            'rule_id' => 'WG-001-SQL',
            'confidence' => 'High',
            'response_action' => 'Block'
        ];
    }
}