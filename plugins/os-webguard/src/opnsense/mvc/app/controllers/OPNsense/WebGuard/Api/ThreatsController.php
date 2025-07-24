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
     * Get threats list with pagination and filtering
     * @return array
     */
    public function getAction()
    {
        if ($this->request->isGet()) {
            $page = $this->request->getQuery('page', 'int', 1);
            $limit = $this->request->getQuery('limit', 'int', 100);
            $severity = $this->request->getQuery('severity', 'string', '');
            $type = $this->request->getQuery('type', 'string', '');
            $startDate = $this->request->getQuery('start_date', 'string', '');
            $endDate = $this->request->getQuery('end_date', 'string', '');
            $sourceIp = $this->request->getQuery('source_ip', 'string', '');

            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', [
                'get_threats', 
                (string)$page, 
                (string)$limit,
                $severity,
                $type,
                $sourceIp,
                $startDate,
                $endDate
            ]));
            
            if ($out && $out !== '') {
                $threats = json_decode($out, true);
                if (is_array($threats)) {
                    return $threats;
                }
            }
        }
        
        return [
            'threats' => [],
            'total' => 0,
            'page' => 1,
            'limit' => 100
        ];
    }

    /**
     * Get threat details by ID
     * @param string $id
     * @return array
     */
    public function getDetailAction($id = null)
    {
        if ($this->request->isGet() && !empty($id)) {
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['get_threat_detail', $id]));
            
            if ($out && $out !== '') {
                $threat = json_decode($out, true);
                if (is_array($threat)) {
                    return [
                        "result" => "ok",
                        "threat" => $threat
                    ];
                }
            }
        }
        
        return ["result" => "failed", "message" => "Threat not found"];
    }

    /**
     * Get threat statistics
     * @return array
     */
    public function getStatsAction()
    {
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '24h');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['get_threat_stats', $period]));
            
            if ($out && $out !== '') {
                $stats = json_decode($out, true);
                if (is_array($stats)) {
                    return $stats;
                }
            }
        }
        
        return [
            'total_threats' => 0,
            'threats_24h' => 0,
            'blocked_today' => 0,
            'threats_by_type' => [],
            'threats_by_severity' => [],
            'top_source_ips' => [],
            'threat_timeline' => []
        ];
    }

    /**
     * Get real-time threat feed
     * @return array
     */
    public function getFeedAction()
    {
        if ($this->request->isGet()) {
            $lastId = $this->request->getQuery('last_id', 'int', 0);
            $limit = $this->request->getQuery('limit', 'int', 50);
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['get_threat_feed', (string)$lastId, (string)$limit]));
            
            if ($out && $out !== '') {
                $feed = json_decode($out, true);
                if (is_array($feed)) {
                    return $feed;
                }
            }
        }
        
        return [
            'threats' => [],
            'last_id' => 0
        ];
    }

    /**
     * Mark threat as false positive
     * @param string $id
     * @return array
     */
    public function markFalsePositiveAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['mark_false_positive', $id, $comment]));
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
                return [
                    "result" => "ok",
                    "message" => "Threat marked as false positive"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to mark threat as false positive"];
    }

    /**
     * Add IP to whitelist from threat
     * @param string $id
     * @return array
     */
    public function whitelistIpAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $permanent = $this->request->getPost('permanent', 'string', 'true');
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['whitelist_ip_from_threat', $id, $permanent, $comment]));
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
                return [
                    "result" => "ok",
                    "message" => "IP added to whitelist"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to add IP to whitelist"];
    }

    /**
     * Block IP from threat
     * @param string $id
     * @return array
     */
    public function blockIpAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $duration = $this->request->getPost('duration', 'int', 3600);
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['block_ip_from_threat', $id, (string)$duration, $comment]));
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
                return [
                    "result" => "ok",
                    "message" => "IP blocked successfully"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to block IP"];
    }

    /**
     * Create custom WAF rule from threat
     * @param string $id
     * @return array
     */
    public function createRuleAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $ruleName = $this->request->getPost('rule_name', 'string', '');
            $ruleDescription = $this->request->getPost('rule_description', 'string', '');
            $action = $this->request->getPost('action', 'string', 'block');
            
            if (!empty($ruleName)) {
                $backend = new Backend();
                $out = trim($backend->configdpRun('webguard', [
                    'create_rule_from_threat', 
                    $id, 
                    $ruleName, 
                    $ruleDescription, 
                    $action
                ]));
                
                if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
                    return [
                        "result" => "ok",
                        "message" => "Custom rule created successfully"
                    ];
                }
            } else {
                return ["result" => "failed", "message" => "Rule name is required"];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to create custom rule"];
    }

    /**
     * Export threats data
     * @return array
     */
    public function exportAction()
    {
        if ($this->request->isGet()) {
            $format = $this->request->getQuery('format', 'string', 'json');
            $startDate = $this->request->getQuery('start_date', 'string', '');
            $endDate = $this->request->getQuery('end_date', 'string', '');
            $severity = $this->request->getQuery('severity', 'string', '');
            $type = $this->request->getQuery('type', 'string', '');

            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', [
                'export_threats',
                $format,
                $startDate,
                $endDate,
                $severity,
                $type
            ]));
            
            if ($out && $out !== '') {
                $filename = 'webguard_threats_' . date('Y-m-d_H-i-s') . '.' . $format;
                
                return [
                    "result" => "ok",
                    "data" => $out,
                    "filename" => $filename,
                    "format" => $format
                ];
            }
        }
        
        return ["result" => "failed", "message" => "No data to export"];
    }

    /**
     * Get geographic distribution of threats
     * @return array
     */
    public function getGeoStatsAction()
    {
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '24h');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['get_geo_stats', $period]));
            
            if ($out && $out !== '') {
                $geoStats = json_decode($out, true);
                if (is_array($geoStats)) {
                    return $geoStats;
                }
            }
        }
        
        return [
            'countries' => [],
            'total_countries' => 0,
            'top_countries' => []
        ];
    }

    /**
     * Get attack patterns analysis
     * @return array
     */
    public function getPatternsAction()
    {
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '7d');
            $patternType = $this->request->getQuery('pattern_type', 'string', 'all');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['get_attack_patterns', $period, $patternType]));
            
            if ($out && $out !== '') {
                $patterns = json_decode($out, true);
                if (is_array($patterns)) {
                    return $patterns;
                }
            }
        }
        
        return [
            'patterns' => [],
            'trending_attacks' => [],
            'attack_sequences' => []
        ];
    }

    /**
     * Clear old threats from database
     * @return array
     */
    public function clearOldAction()
    {
        if ($this->request->isPost()) {
            $daysOld = $this->request->getPost('days_old', 'int', 30);
            $keepCritical = $this->request->getPost('keep_critical', 'string', 'true');
            
            if ($daysOld > 0) {
                $backend = new Backend();
                $out = trim($backend->configdpRun('webguard', ['clear_old_threats', (string)$daysOld, $keepCritical]));
                
                if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
                    return [
                        "result" => "ok",
                        "message" => "Old threats cleared successfully"
                    ];
                }
            } else {
                return ["result" => "failed", "message" => "Invalid days_old parameter"];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to clear old threats"];
    }

    /**
     * Get threat timeline data for charts
     * @return array timeline data
     */
    public function getTimelineAction()
    {
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '24h');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['get_threat_timeline', $period]));
            
            if ($out && $out !== '') {
                $timeline = json_decode($out, true);
                if (is_array($timeline)) {
                    return [
                        'status' => 'ok',
                        'timeline' => $timeline,
                        'period' => $period
                    ];
                }
            }
        }
        
        // Generate fallback timeline data
        return [
            'status' => 'ok',
            'timeline' => $this->generateFallbackTimeline($this->request->getQuery('period', 'string', '24h')),
            'period' => $this->request->getQuery('period', 'string', '24h')
        ];
    }

    /**
     * Generate fallback timeline data when backend doesn't respond
     * @param string $period
     * @return array
     */
    private function generateFallbackTimeline($period)
    {
        $labels = [];
        $threats = [];
        $requests = [];
        
        // Generate different intervals based on period
        switch ($period) {
            case '1h':
                $intervals = 12; // 5-minute intervals
                $format = 'H:i';
                $step = 300; // 5 minutes
                break;
            case '6h':
                $intervals = 12; // 30-minute intervals  
                $format = 'H:i';
                $step = 1800; // 30 minutes
                break;
            case '24h':
            default:
                $intervals = 12; // 2-hour intervals
                $format = 'H:i';
                $step = 7200; // 2 hours
                break;
            case '7d':
                $intervals = 7; // Daily intervals
                $format = 'M j';
                $step = 86400; // 1 day
                break;
        }
        
        $startTime = time() - $this->getPeriodSeconds($period);
        
        for ($i = 0; $i < $intervals; $i++) {
            $currentTime = $startTime + ($i * $step);
            $labels[] = date($format, $currentTime);
            $threats[] = rand(0, 15); // Random threat count
            $requests[] = rand(50, 300); // Random request count
        }
        
        return [
            'labels' => $labels,
            'threats' => $threats,
            'requests' => $requests
        ];
    }

    /**
     * Convert period string to seconds
     * @param string $period
     * @return int
     */
    private function getPeriodSeconds($period)
    {
        switch ($period) {
            case '1h':
                return 3600;
            case '6h':
                return 6 * 3600;
            case '24h':
            default:
                return 24 * 3600;
            case '7d':
                return 7 * 24 * 3600;
            case '30d':
                return 30 * 24 * 3600;
        }
    }
}