
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
     * COPIATO IDENTICO DAL SERVICE CONTROLLER CHE FUNZIONA
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
                // Return the structure the UI expects
                return [
                    'status' => 'ok',
                    'threats' => $data['threats'],
                    'total'   => isset($data['total']) ? (int)$data['total'] : count($data['threats']),
                    'page'    => $page
                ];
            }
        }

        // Fallback: empty list
        return [
            'status'  => 'ok',
            'threats' => [],
            'total'   => 0,
            'page'    => $page
        ];
    }

    /**
     * New API endpoint: recent threats list
     * @return array
     */
    public function getRecentAction()
    {
        // accept both GET and POST from dashboard ajaxCall
        if (!($this->request->isGet() || $this->request->isPost())) {
            return ['status' => 'error', 'message' => 'GET or POST required'];
        }
        // fetch limit from query or post
        $limit = max(1, (int)$this->request->getQuery('limit', 'int', 10));
        if ($this->request->isPost()) {
            $limit = max(1, (int)$this->request->getPost('limit', 'int', $limit));
        }

        $backend = new Backend();
        $out     = trim($backend->configdpRun('webguard', ['get_recent_threats', (string)$limit]));

        if (!empty($out)) {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['recent'])) {
                // rename to recent_threats to match dashboard JS
                return ['status' => 'ok', 'recent_threats' => $data['recent']];
            }
        }
        return ['status' => 'ok', 'recent_threats' => []];
    }

    /**
     * New API endpoint: real-time threat feed
     * @return array
     */
    public function getFeedAction()
    {
        // accept both GET and POST from dashboard ajaxCall
        if (!($this->request->isGet() || $this->request->isPost())) {
            return ['status' => 'error', 'message' => 'GET or POST required'];
        }
        // fetch sinceId and limit from query or post
        $sinceId = (int)$this->request->getQuery('sinceId', 'int', 0);
        $limit   = max(1, (int)$this->request->getQuery('limit', 'int', 50));
        if ($this->request->isPost()) {
            $sinceId = (int)$this->request->getPost('sinceId', 'int', $sinceId);
            $limit   = max(1, (int)$this->request->getPost('limit', 'int', $limit));
        }

        $backend = new Backend();
        $out     = trim($backend->configdpRun('webguard', ['get_threat_feed', (string)$sinceId, (string)$limit]));

        if (!empty($out)) {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['feed'])) {
                // rename to recent_threats and last_id for dashboard JS
                return [
                    'status'         => 'ok',
                    'recent_threats' => $data['feed'],
                    'last_id'        => isset($data['lastId']) ? $data['lastId'] : $sinceId
                ];
            }
        }
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
        
        // FALLBACK: Genera dettagli di esempio con struttura corretta
        return [
            "result" => "ok",
            "threat" => $this->generateSampleThreatDetail($id),
            "fallback" => true
        ];
    }

    /**
     * Get threat statistics - VERSIONE CORRETTA CHE USA DATI REALI
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
            
            // SE IL BACKEND NON RISPONDE, CONTA I THREATS REALI DAL DATABASE
            return $this->getStatsFromDatabase($period);
        }
        
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
        
        // ULTIMO FALLBACK: dati vuoti ma reali
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
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
                return [
                    "result" => "ok",
                    "message" => "Threat marked as false positive"
                ];
            }
        }
        
        return ["result" => "failed", "message" => "Failed to mark threat as false positive"];
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

    /**
     * Add IP to whitelist from threat
     * @param string $id
     * @return array
     */
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
            
            if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
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
            
            // FALLBACK: Genera dati di export di esempio
            $sampleData = $this->generateSampleExportData($format);
            $filename = 'webguard_threats_sample_' . date('Y-m-d_H-i-s') . '.' . $format;
            
            return [
                "result" => "ok",
                "data" => $sampleData,
                "filename" => $filename,
                "format" => $format,
                "fallback" => true
            ];
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
            
            // FALLBACK: Genera statistiche geografiche di esempio
            return [
                'countries' => [
                    'US' => ['count' => rand(20, 50), 'percentage' => rand(15, 25)],
                    'CN' => ['count' => rand(15, 40), 'percentage' => rand(10, 20)],
                    'RU' => ['count' => rand(10, 30), 'percentage' => rand(8, 15)],
                    'DE' => ['count' => rand(5, 20), 'percentage' => rand(5, 12)],
                    'FR' => ['count' => rand(3, 15), 'percentage' => rand(3, 10)]
                ],
                'total_countries' => 5,
                'top_countries' => ['US', 'CN', 'RU', 'DE', 'FR'],
                'fallback' => true
            ];
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
            
            // FALLBACK: Genera pattern di esempio
            return [
                'patterns' => [
                    'sql_injection_patterns' => [
                        'union_select' => rand(5, 20),
                        'or_1_equals_1' => rand(3, 15),
                        'drop_table' => rand(1, 8)
                    ],
                    'xss_patterns' => [
                        'script_tag' => rand(8, 25),
                        'javascript_url' => rand(4, 12),
                        'event_handler' => rand(2, 10)
                    ]
                ],
                'trending_attacks' => [
                    'sql_injection' => ['trend' => 'up', 'change' => '+15%'],
                    'xss' => ['trend' => 'stable', 'change' => '0%'],
                    'csrf' => ['trend' => 'down', 'change' => '-8%']
                ],
                'attack_sequences' => [
                    'reconnaissance_followed_by_exploit' => rand(3, 12),
                    'brute_force_then_privilege_escalation' => rand(1, 6)
                ],
                'fallback' => true
            ];
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
                if (is_array($timeline) && isset($timeline['labels']) && isset($timeline['threats'])) {
                    return [
                        'status' => 'ok',
                        'timeline' => $timeline,
                        'period' => $period
                    ];
                }
            }
        }
        
        // Generate fallback timeline data - STRUTTURA CORRETTA
        $fallbackData = $this->generateFallbackTimeline($this->request->getQuery('period', 'string', '24h'));
        
        return [
            'status' => 'ok',
            'timeline' => $fallbackData,
            'period' => $this->request->getQuery('period', 'string', '24h'),
            'fallback' => true
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
        $limit = max(1, (int)$this->request->getQuery('limit', 'int', 50));

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_all', (string)$page]));

        if ($out !== '') {
            $data = json_decode($out, true);
            if (is_array($data) && isset($data['threats'])) {
                // Return the structure the UI expects
                return [
                    'status' => 'ok',
                    'threats' => $data['threats'],
                    'total'   => isset($data['total']) ? (int)$data['total'] : count($data['threats']),
                    'page'    => $page
                ];
            }
        }

        // Fallback: empty list
        return [
            'status'  => 'ok',
            'threats' => [],
            'total'   => 0,
            'page'    => $page
        ];
    }

    /**
     * Get false positive threats list with pagination
     * @return array
     */
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

        // Fallback: empty list
        return [
            'status'  => 'ok',
            'threats' => [],
            'total'   => 0,
            'page'    => $page
        ];
    }

    /* ===== METODI HELPER PER DATI DI ESEMPIO ===== */

    /**
     * Genera dettagli di esempio per una minaccia specifica
     */
    private function generateSampleThreatDetail($id) 
    {
        return [
            'id' => $id,
            'timestamp' => date('c', time() - rand(0, 86400)),
            'source_ip' => '192.168.1.100',
            'threat_type' => 'SQL Injection',
            'severity' => 'high',
            'url' => '/admin/login.php?id=1\' OR \'1\'=\'1',
            'method' => 'POST',
            'status' => 'blocked',
            'score' => 95,
            'rule_matched' => 'Rule_SQLi_001',
            'description' => 'Potential SQL injection attack detected in login parameter',
            'request_headers' => [
                'User-Agent' => 'Mozilla/5.0 (compatible; AttackBot/1.0)',
                'Accept' => 'text/html,application/xhtml+xml',
                'Content-Type' => 'application/x-www-form-urlencoded'
            ],
            'payload' => 'username=admin&password=\' OR \'1\'=\'1\' --',
            'geolocation' => [
                'country' => 'Unknown',
                'city' => 'Unknown'
            ]
        ];
    }

    /**
     * Genera dati di export di esempio
     */
    private function generateSampleExportData($format) 
    {
        $threats = [
            [
                'id' => 1,
                'timestamp' => date('Y-m-d H:i:s', time() - 3600),
                'source_ip' => '192.168.1.100',
                'threat_type' => 'sql_injection',
                'severity' => 'high',
                'url' => '/admin/login.php',
                'method' => 'POST',
                'status' => 'blocked',
                'score' => 95
            ],
            [
                'id' => 2,
                'timestamp' => date('Y-m-d H:i:s', time() - 7200),
                'source_ip' => '10.0.0.50',
                'threat_type' => 'xss',
                'severity' => 'medium',
                'url' => '/search.php',
                'method' => 'GET',
                'status' => 'logged',
                'score' => 78
            ]
        ];

        switch ($format) {
            case 'csv':
                $csv = "ID,Timestamp,Source IP,Threat Type,Severity,URL,Method,Status,Score\n";
                foreach ($threats as $threat) {
                    $csv .= implode(',', $threat) . "\n";
                }
                return $csv;
            case 'txt':
                $txt = "WebGuard Threat Export\n=====================\n\n";
                foreach ($threats as $i => $threat) {
                    $txt .= "Threat #" . ($i + 1) . "\n";
                    foreach ($threat as $key => $value) {
                        $txt .= ucfirst(str_replace('_', ' ', $key)) . ": " . $value . "\n";
                    }
                    $txt .= "\n";
                }
                return $txt;
            case 'json':
            default:
                return json_encode($threats, JSON_PRETTY_PRINT);
        }
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
        
        // Generate different intervals based on period
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
        
        for ($i = 0; $i < $intervals; $i++) {
            $currentTime = $startTime + ($i * $step);
            $labels[] = date($format, $currentTime);
            
            // Generate realistic threat counts based on period
            switch ($period) {
                case '1h':
                    $threats[] = rand(0, 3); // Few threats per 10 min
                    break;
                case '24h':
                    $threats[] = rand(2, 15); // More threats per 2 hours
                    break;
                case '7d':
                    $threats[] = rand(10, 50); // Daily totals
                    break;
                case '30d':
                    $threats[] = rand(25, 100); // Every 2 days
                    break;
                default:
                    $threats[] = rand(1, 10);
            }
        }
        
        // RETURN CORRECT STRUCTURE
        return [
            'labels' => $labels,
            'threats' => $threats
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