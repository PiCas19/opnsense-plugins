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
        if (!$this->request->isGet()) {
            return ['status' => 'error', 'message' => 'GET required'];
        }
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        $limit = max(1, (int)$this->request->getQuery('limit', 'int', 50));

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threats', (string)$page]));

        if ($out !== '') {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['threats'])) {
                return [
                    'status' => 'ok',
                    'threats' => $data['threats'],
                    'total'   => isset($data['total']) ? (int)$data['total'] : count($data['threats']),
                    'page'    => $page
                ];
            }
        }

        // NESSUN FALLBACK - solo dati reali
        return [
            'status'  => 'ok',
            'threats' => [],
            'total'   => 0,
            'page'    => $page
        ];
    }

    /**
     * Get recent threats list
     * @return array
     */
    public function getRecentAction()
    {
        if (!($this->request->isGet() || $this->request->isPost())) {
            return ['status' => 'error', 'message' => 'GET or POST required'];
        }
        
        $limit = max(1, (int)$this->request->getQuery('limit', 'int', 10));
        if ($this->request->isPost()) {
            $limit = max(1, (int)$this->request->getPost('limit', 'int', $limit));
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_recent_threats', (string)$limit]));

        if (!empty($out)) {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['recent'])) {
                return ['status' => 'ok', 'recent_threats' => $data['recent']];
            }
        }
        
        // NESSUN FALLBACK - solo dati reali
        return ['status' => 'ok', 'recent_threats' => []];
    }

    /**
     * Get real-time threat feed
     * @return array
     */
    public function getFeedAction()
    {
        if (!($this->request->isGet() || $this->request->isPost())) {
            return ['status' => 'error', 'message' => 'GET or POST required'];
        }
        
        $sinceId = (int)$this->request->getQuery('sinceId', 'int', 0);
        $limit = max(1, (int)$this->request->getQuery('limit', 'int', 50));
        if ($this->request->isPost()) {
            $sinceId = (int)$this->request->getPost('sinceId', 'int', $sinceId);
            $limit = max(1, (int)$this->request->getPost('limit', 'int', $limit));
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_feed', (string)$sinceId, (string)$limit]));

        if (!empty($out)) {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['feed'])) {
                return [
                    'status' => 'ok',
                    'recent_threats' => $data['feed'],
                    'last_id' => isset($data['lastId']) ? $data['lastId'] : $sinceId
                ];
            }
        }
        
        // NESSUN FALLBACK - solo dati reali
        return ['status' => 'ok', 'recent_threats' => [], 'last_id' => $sinceId];
    }

    /**
     * Get threat details by ID
     * @param string $id
     * @return array
     */
    public function getDetailAction($id = null)
    {
        if (!$this->request->isGet() || empty($id)) {
            return ["result" => "failed", "message" => "Threat ID required"];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_detail', $id]));
        
        if ($out && $out !== '') {
            $threat = json_decode($out, true);
            if (is_array($threat) && !isset($threat['error'])) {
                return [
                    "result" => "ok",
                    "threat" => $threat
                ];
            }
        }
        
        // NESSUN FALLBACK - solo errore se non trovato
        return [
            "result" => "failed",
            "message" => "Threat not found"
        ];
    }

    /**
     * Get threat statistics - SOLO DATI REALI
     * @return array
     */
    public function getStatsAction()
    {
        if (!$this->request->isGet()) {
            return [
                'total_threats' => 0,
                'threats_24h' => 0,
                'blocked_today' => 0,
                'threats_by_type' => [],
                'threats_by_severity' => [],
                'top_source_ips' => [],
                'patterns' => []
            ];
        }
        
        $period = $this->request->getQuery('period', 'string', '24h');
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_stats', $period]));
        
        if ($out && $out !== '') {
            $stats = json_decode($out, true);
            if (is_array($stats)) {
                return $stats;
            }
        }
        
        // SE IL BACKEND NON RISPONDE, CONTA I THREATS REALI DAL DATABASE
        return $this->getStatsFromDatabase($period);
    }

    /**
     * Conta i threats reali dal database quando il backend non risponde
     */
    private function getStatsFromDatabase($period)
    {
        $backend = new Backend();
        
        // Prima prova a ottenere tutti i threats
        $threatsOut = trim($backend->configdpRun('webguard', ['get_threat_all', '1']));
        
        if ($threatsOut && $threatsOut !== '') {
            $threatsData = json_decode($threatsOut, true);
            
            if (is_array($threatsData) && isset($threatsData['threats'])) {
                $threats = $threatsData['threats'];
                $totalThreats = $threatsData['total'] ?? count($threats);
                
                // Calcola statistiche dai dati reali
                $stats = $this->calculateStatsFromThreats($threats, $period);
                $stats['total_threats'] = $totalThreats;
                
                return $stats;
            }
        }
        
        // Se anche questo fallisce, prova con get_threats normale
        $normalThreatsOut = trim($backend->configdpRun('webguard', ['get_threats', '1']));
        
        if ($normalThreatsOut && $normalThreatsOut !== '') {
            $normalData = json_decode($normalThreatsOut, true);
            
            if (is_array($normalData) && isset($normalData['threats'])) {
                $threats = $normalData['threats'];
                $totalThreats = $normalData['total'] ?? count($threats);
                
                $stats = $this->calculateStatsFromThreats($threats, $period);
                $stats['total_threats'] = $totalThreats;
                
                return $stats;
            }
        }
        
        // ULTIMO RESORT: dati vuoti ma reali (NESSUN MOCK!)
        return [
            'total_threats' => 0,
            'threats_24h' => 0,
            'blocked_today' => 0,
            'threats_by_type' => [],
            'threats_by_severity' => [],
            'top_source_ips' => [],
            'patterns' => []
        ];
    }

    /**
     * Calcola le statistiche dai threats reali
     */
    private function calculateStatsFromThreats($threats, $period)
    {
        $now = time();
        $periodSeconds = $this->getPeriodSeconds($period);
        $cutoffTime = $now - $periodSeconds;
        
        $stats = [
            'threats_24h' => 0,
            'blocked_today' => 0,
            'threats_by_type' => [],
            'threats_by_severity' => [],
            'top_source_ips' => [],
            'patterns' => [
                'sql_injection_patterns' => [],
                'xss_patterns' => []
            ]
        ];
        
        foreach ($threats as $threat) {
            // Controlla se il threat è nel periodo richiesto
            $threatTime = 0;
            if (isset($threat['timestamp'])) {
                $threatTime = is_numeric($threat['timestamp']) ? $threat['timestamp'] : strtotime($threat['timestamp']);
            } elseif (isset($threat['first_seen_iso'])) {
                $threatTime = strtotime($threat['first_seen_iso']);
            } elseif (isset($threat['last_seen_iso'])) {
                $threatTime = strtotime($threat['last_seen_iso']);
            }
            
            if ($threatTime >= $cutoffTime) {
                $stats['threats_24h']++;
                
                // Conta per tipo
                $type = $threat['threat_type'] ?? 'unknown';
                $stats['threats_by_type'][$type] = ($stats['threats_by_type'][$type] ?? 0) + 1;
                
                // Conta per severità
                $severity = $threat['severity'] ?? 'medium';
                $stats['threats_by_severity'][$severity] = ($stats['threats_by_severity'][$severity] ?? 0) + 1;
                
                // Conta IP sources
                $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? 'unknown';
                if ($ip !== 'unknown') {
                    $stats['top_source_ips'][$ip] = ($stats['top_source_ips'][$ip] ?? 0) + 1;
                }
                
                // Conta se bloccato
                if (isset($threat['status']) && $threat['status'] === 'blocked') {
                    $stats['blocked_today']++;
                }
                
                // Analizza patterns
                if (stripos($type, 'sql') !== false || stripos($type, 'injection') !== false) {
                    $stats['patterns']['sql_injection_patterns']['detected'] = 
                        ($stats['patterns']['sql_injection_patterns']['detected'] ?? 0) + 1;
                }
                if (stripos($type, 'xss') !== false || stripos($type, 'script') !== false) {
                    $stats['patterns']['xss_patterns']['detected'] = 
                        ($stats['patterns']['xss_patterns']['detected'] ?? 0) + 1;
                }
            }
        }
        
        return $stats;
    }

    /**
     * Get threat timeline data - SOLO DATI REALI
     * @return array
     */
    public function getTimelineAction()
    {
        if (!$this->request->isGet()) {
            return [
                'status' => 'ok',
                'timeline' => ['labels' => [], 'threats' => []],
                'period' => '24h'
            ];
        }
        
        $period = $this->request->getQuery('period', 'string', '24h');
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_timeline', $period]));
        
        if ($out && $out !== '') {
            $timeline = json_decode($out, true);
            if (is_array($timeline) && isset($timeline['labels']) && isset($timeline['threats'])) {
                return [
                    'status' => 'ok',
                    'timeline' => $timeline,
                    'period' => $period
                ];
            }
        }
        
        // PROVA A GENERARE TIMELINE DAI DATI REALI
        return $this->generateTimelineFromRealData($period);
    }

    /**
     * Genera timeline dai dati reali del database
     */
    private function generateTimelineFromRealData($period)
    {
        $backend = new Backend();
        $threatsOut = trim($backend->configdpRun('webguard', ['get_threat_all', '1']));
        
        if ($threatsOut && $threatsOut !== '') {
            $threatsData = json_decode($threatsOut, true);
            
            if (is_array($threatsData) && isset($threatsData['threats'])) {
                $threats = $threatsData['threats'];
                
                // Genera timeline dai dati reali
                $timeline = $this->buildTimelineFromThreats($threats, $period);
                
                return [
                    'status' => 'ok',
                    'timeline' => $timeline,
                    'period' => $period
                ];
            }
        }
        
        // NESSUN DATO - timeline vuota
        return [
            'status' => 'ok',
            'timeline' => ['labels' => [], 'threats' => []],
            'period' => $period
        ];
    }

    /**
     * Costruisce timeline dai threats reali
     */
    private function buildTimelineFromThreats($threats, $period)
    {
        $labels = [];
        $threatCounts = [];
        
        // Determina intervalli in base al periodo
        switch ($period) {
            case '1h':
                $intervals = 6; // 10-minute intervals
                $format = 'H:i';
                $step = 600; // 10 minutes
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
            case '30d':
                $intervals = 15; // Every 2 days
                $format = 'M j';
                $step = 172800; // 2 days
                break;
        }
        
        $startTime = time() - $this->getPeriodSeconds($period);
        
        // Inizializza tutti gli intervalli a 0
        for ($i = 0; $i < $intervals; $i++) {
            $currentTime = $startTime + ($i * $step);
            $labels[] = date($format, $currentTime);
            $threatCounts[] = 0;
        }
        
        // Conta i threats reali in ogni intervallo
        foreach ($threats as $threat) {
            $threatTime = 0;
            if (isset($threat['timestamp'])) {
                $threatTime = is_numeric($threat['timestamp']) ? $threat['timestamp'] : strtotime($threat['timestamp']);
            } elseif (isset($threat['first_seen_iso'])) {
                $threatTime = strtotime($threat['first_seen_iso']);
            } elseif (isset($threat['last_seen_iso'])) {
                $threatTime = strtotime($threat['last_seen_iso']);
            }
            
            if ($threatTime >= $startTime) {
                // Trova l'intervallo corretto
                $intervalIndex = (int)(($threatTime - $startTime) / $step);
                if ($intervalIndex >= 0 && $intervalIndex < $intervals) {
                    $threatCounts[$intervalIndex]++;
                }
            }
        }
        
        return [
            'labels' => $labels,
            'threats' => $threatCounts
        ];
    }

    /**
     * Get all threats list with pagination
     * @return array
     */
    public function getAllThreatsAction()
    {
        if (!$this->request->isGet()) {
            return ['status' => 'error', 'message' => 'GET required'];
        }
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_all', (string)$page]));

        if ($out !== '') {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['threats'])) {
                return [
                    'status' => 'ok',
                    'threats' => $data['threats'],
                    'total'   => isset($data['total']) ? (int)$data['total'] : count($data['threats']),
                    'page'    => $page
                ];
            }
        }

        // NESSUN FALLBACK - solo dati reali
        return [
            'status'  => 'ok',
            'threats' => [],
            'total'   => 0,
            'page'    => $page
        ];
    }

    /* ===== AZIONI SU THREATS ===== */

    public function markFalsePositiveAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['mark_false_positive', $id, $comment]));
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
                return [
                    "result" => "ok",
                    "message" => "Threat marked as false positive"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to mark threat as false positive"];
    }

    public function whitelistIpAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $description = $this->request->getPost('description', 'string', '');
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['whitelist_ip_from_threat', $id, $description, $comment]));
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
                return [
                    "result" => "ok",
                    "message" => "IP added to whitelist"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to add IP to whitelist"];
    }

    public function blockIpAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $duration = $this->request->getPost('duration', 'int', 3600);
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['block_ip_from_threat', $id, (string)$duration, $comment]));
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
                return [
                    "result" => "ok",
                    "message" => "IP blocked successfully"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to block IP"];
    }

    public function unmarkFalsePositiveAction($id = null)
    {
        if ($this->request->isPost() && !empty($id)) {
            $comment = $this->request->getPost('comment', 'string', '');
            $backend = new Backend();
            $out = trim($backend->configdpRun('webguard', ['unmark_false_positive', $id, $comment]));
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
                return ['status' => 'ok', 'message' => 'Threat unmarked as false positive'];
            }
        }
        return ['status' => 'failed', 'message' => 'Failed to unmark threat as false positive'];
    }

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
                
                if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
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

    public function clearOldAction()
    {
        if ($this->request->isPost()) {
            $daysOld = $this->request->getPost('days_old', 'int', 30);
            $keepCritical = $this->request->getPost('keep_critical', 'string', 'true');
            
            if ($daysOld > 0) {
                $backend = new Backend();
                $out = trim($backend->configdpRun('webguard', ['clear_old_threats', (string)$daysOld, $keepCritical]));
                
                if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
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

    public function getFalsePositivesAction()
    {
        if (!$this->request->isGet()) {
            return ['status' => 'error', 'message' => 'GET required'];
        }
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_false_positive', (string)$page]));

        if ($out !== '') {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['threats'])) {
                return [
                    'status' => 'ok',
                    'threats' => $data['threats'],
                    'total'   => isset($data['total']) ? (int)$data['total'] : count($data['threats']),
                    'page'    => $page
                ];
            }
        }

        return [
            'status'  => 'ok',
            'threats' => [],
            'total'   => 0,
            'page'    => $page
        ];
    }

    /* ===== UTILITY METHODS ===== */

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