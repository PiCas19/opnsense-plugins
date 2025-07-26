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
     * Get threat statistics - INTEGRATO CON JSON FILES
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
                // Integra con pattern dai file JSON
                $stats['patterns'] = $this->enrichStatsWithPatterns($stats, $period);
                return $stats;
            }
        }
        
        // SE IL BACKEND NON RISPONDE, CONTA I THREATS REALI DAL DATABASE
        return $this->getStatsFromDatabase($period);
    }

    /**
     * Arricchisce le statistiche con i pattern dai file JSON
     */
    private function enrichStatsWithPatterns($stats, $period)
    {
        $attackPatterns = $this->loadAttackPatternsFile();
        $wafRules = $this->loadWafRulesFile();
        $realThreats = $this->getRealThreatsData($period);
        
        // Combina pattern detection con threat reali
        $enrichedPatterns = [];
        
        foreach ($attackPatterns as $category => $patterns) {
            foreach ($patterns as $pattern) {
                $matchingThreats = $this->findMatchingThreats($pattern, $category, $realThreats);
                
                if (count($matchingThreats) > 0) {
                    $enrichedPatterns[] = [
                        'pattern' => $pattern,
                        'category' => $category,
                        'detected' => count($matchingThreats),
                        'blocked' => $this->countBlockedThreats($matchingThreats),
                        'severity' => $this->calculatePatternSeverity($matchingThreats, null)
                    ];
                }
            }
        }
        
        return [
            'sql_injection_patterns' => array_filter($enrichedPatterns, function($p) {
                return $p['category'] === 'sql_injection';
            }),
            'xss_patterns' => array_filter($enrichedPatterns, function($p) {
                return $p['category'] === 'xss';
            }),
            'total_patterns_detected' => count($enrichedPatterns)
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
                
                // Integra con pattern dai file JSON
                $stats['patterns'] = $this->enrichStatsWithPatterns($stats, $period);
                
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
                $stats['patterns'] = $this->enrichStatsWithPatterns($stats, $period);
                
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
            'patterns' => []
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

    /**
     * Get attack patterns from JSON files and real threat data - METODO PRINCIPALE
     * @return array
     */
    public function getPatternsAction()
    {
        if (!$this->request->isGet()) {
            return [
                'patterns' => [],
                'trending_attacks' => [],
                'attack_sequences' => []
            ];
        }
        
        $period = $this->request->getQuery('period', 'string', '7d');
        $patternType = $this->request->getQuery('pattern_type', 'string', 'all');
        
        // Prima prova il backend
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_attack_patterns', $period, $patternType]));
        
        if ($out && $out !== '') {
            $patterns = json_decode($out, true);
            if (is_array($patterns)) {
                return $patterns;
            }
        }
        
        // Fallback: costruisci i pattern dai file JSON e dai dati reali
        return $this->buildPatternsFromRealData($period, $patternType);
    }

    /**
     * Costruisce i pattern dai file JSON e dai dati dei threat reali
     */
    private function buildPatternsFromRealData($period, $patternType)
    {
        $patterns = [];
        $trendingAttacks = [];
        $attackSequences = [];
        
        // Carica i pattern dai file JSON
        $attackPatternsData = $this->loadAttackPatternsFile();
        $wafRulesData = $this->loadWafRulesFile();
        
        // Ottieni i threat reali dal database
        $realThreats = $this->getRealThreatsData($period);
        
        // Combina i dati per creare pattern completi
        $patterns = $this->combinePatternData($attackPatternsData, $wafRulesData, $realThreats, $patternType);
        $trendingAttacks = $this->extractTrendingAttacks($realThreats, $patterns);
        $attackSequences = $this->buildAttackSequences($realThreats);
        
        return [
            'patterns' => $patterns,
            'trending_attacks' => $trendingAttacks,
            'attack_sequences' => $attackSequences
        ];
    }

    /**
     * Carica il file attack_patterns.json
     */
    private function loadAttackPatternsFile()
    {
        $filePath = '/usr/local/etc/webguard/attack_patterns.json';
        
        if (file_exists($filePath)) {
            $content = file_get_contents($filePath);
            $data = json_decode($content, true);
            
            if (is_array($data) && isset($data['patterns'])) {
                return $data['patterns'];
            }
        }
        
        // Fallback pattern base
        return [
            'sql_injection' => [
                "(?i)(union|select|insert|update|delete|drop|exec)",
                "(?i)(or 1=1|and 1=1)",
                "(?i)('; drop table|' or '1'='1)"
            ],
            'xss' => [
                "(?i)(<script|javascript:|on\\w+\\s*=)",
                "(?i)(alert\\(|prompt\\(|confirm\\()",
                "(?i)(document\\.cookie|window\\.location)"
            ],
            'path_traversal' => [
                "\\.\\.[\\\\/]",
                "[\\\\/]etc[\\\\/]passwd",
                "[\\\\/]windows[\\\\/]system32"
            ],
            'command_injection' => [
                "(?i)(;|\\||&&|\\$\\(|`|exec|system)",
                "(?i)(cat |ls |whoami|id )",
                "(?i)(nc -|netcat|/bin/sh)"
            ],
            'rfi' => [
                "(?i)(http://|https://|ftp://|data:)",
                "(?i)(include|require).*\\?",
                "(?i)(\\?.*=http)"
            ]
        ];
    }

    /**
     * Carica il file waf_rules.json
     */
    private function loadWafRulesFile()
    {
        $filePath = '/usr/local/etc/webguard/waf_rules.json';
        
        if (file_exists($filePath)) {
            $content = file_get_contents($filePath);
            $data = json_decode($content, true);
            
            if (is_array($data) && isset($data['rules'])) {
                return $data['rules'];
            }
        }
        
        return [];
    }

    /**
     * Ottiene i dati dei threat reali dal database
     */
    private function getRealThreatsData($period)
    {
        $backend = new Backend();
        $threatsOut = trim($backend->configdpRun('webguard', ['get_threat_all', '1']));
        
        if ($threatsOut && $threatsOut !== '') {
            $threatsData = json_decode($threatsOut, true);
            
            if (is_array($threatsData) && isset($threatsData['threats'])) {
                $threats = $threatsData['threats'];
                
                // Filtra per periodo
                $periodSeconds = $this->getPeriodSeconds($period);
                $cutoffTime = time() - $periodSeconds;
                
                return array_filter($threats, function($threat) use ($cutoffTime) {
                    $threatTime = $this->extractThreatTimestamp($threat);
                    return $threatTime >= $cutoffTime;
                });
            }
        }
        
        return [];
    }

    /**
     * Combina i dati dei pattern con i threat reali
     */
    private function combinePatternData($attackPatterns, $wafRules, $realThreats, $patternType)
    {
        $combinedPatterns = [];
        $patternId = 1;
        
        // Per ogni categoria di pattern
        foreach ($attackPatterns as $category => $patterns) {
            // Se è richiesto un tipo specifico, filtra
            if ($patternType !== 'all' && $category !== $patternType) {
                continue;
            }
            
            foreach ($patterns as $pattern) {
                // Trova i threat reali che matchano questo pattern
                $matchingThreats = $this->findMatchingThreats($pattern, $category, $realThreats);
                
                // Trova la regola WAF corrispondente
                $wafRule = $this->findMatchingWafRule($pattern, $category, $wafRules);
                
                $combinedPatterns[] = [
                    'id' => $patternId++,
                    'pattern' => $pattern,
                    'signature' => $pattern,
                    'type' => $category,
                    'category' => $this->normalizeCategory($category),
                    'count' => count($matchingThreats),
                    'occurrences' => count($matchingThreats),
                    'severity' => $this->calculatePatternSeverity($matchingThreats, $wafRule),
                    'score' => $this->calculatePatternScore($matchingThreats, $wafRule),
                    'success_rate' => $this->calculateSuccessRate($matchingThreats),
                    'first_seen' => $this->getFirstSeen($matchingThreats),
                    'last_seen' => $this->getLastSeen($matchingThreats),
                    'trend' => $this->calculateTrend($matchingThreats),
                    'status' => count($matchingThreats) > 0 ? 'active' : 'inactive',
                    'blocked' => $this->countBlockedThreats($matchingThreats),
                    'source_ips' => $this->extractSourceIPs($matchingThreats),
                    'waf_rule_id' => $wafRule ? $wafRule['id'] : null,
                    'action' => $wafRule ? $wafRule['action'] : 'log',
                    'source' => 'attack_patterns.json'
                ];
            }
        }
        
        // Aggiungi anche pattern dalle regole WAF
        foreach ($wafRules as $rule) {
            if (isset($rule['pattern']) && !empty($rule['pattern'])) {
                $matchingThreats = $this->findMatchingThreats($rule['pattern'], 'waf_rule', $realThreats);
                
                $combinedPatterns[] = [
                    'id' => $patternId++,
                    'pattern' => $rule['pattern'],
                    'signature' => $rule['name'] ?? $rule['pattern'],
                    'type' => $this->extractTypeFromWafRule($rule),
                    'category' => $rule['name'] ?? 'WAF Rule',
                    'count' => count($matchingThreats),
                    'occurrences' => count($matchingThreats),
                    'severity' => $rule['severity'] ?? 'medium',
                    'score' => $rule['score'] ?? 50,
                    'success_rate' => $this->calculateSuccessRate($matchingThreats),
                    'first_seen' => $this->getFirstSeen($matchingThreats),
                    'last_seen' => $this->getLastSeen($matchingThreats),
                    'trend' => $this->calculateTrend($matchingThreats),
                    'status' => count($matchingThreats) > 0 ? 'active' : 'inactive',
                    'blocked' => $this->countBlockedThreats($matchingThreats),
                    'source_ips' => $this->extractSourceIPs($matchingThreats),
                    'waf_rule_id' => $rule['id'] ?? null,
                    'action' => $rule['action'] ?? 'log',
                    'source' => 'waf_rules.json'
                ];
            }
        }
        
        // Ordina per count decrescente
        usort($combinedPatterns, function($a, $b) {
            return $b['count'] - $a['count'];
        });
        
        return $combinedPatterns;
    }

    /**
     * Trova i threat che matchano un pattern specifico
     */
    private function findMatchingThreats($pattern, $category, $threats)
    {
        $matching = [];
        
        foreach ($threats as $threat) {
            $threatType = strtolower($threat['threat_type'] ?? '');
            $requestData = strtolower($threat['request_data'] ?? '');
            $signature = strtolower($threat['signature'] ?? '');
            
            // Match per categoria
            $categoryMatch = false;
            switch ($category) {
                case 'sql_injection':
                    $categoryMatch = (stripos($threatType, 'sql') !== false || 
                                    stripos($threatType, 'injection') !== false);
                    break;
                case 'xss':
                    $categoryMatch = (stripos($threatType, 'xss') !== false || 
                                    stripos($threatType, 'script') !== false);
                    break;
                case 'path_traversal':
                    $categoryMatch = (stripos($threatType, 'path') !== false || 
                                    stripos($threatType, 'traversal') !== false ||
                                    stripos($threatType, 'lfi') !== false);
                    break;
                case 'command_injection':
                    $categoryMatch = (stripos($threatType, 'command') !== false || 
                                    stripos($threatType, 'rce') !== false);
                    break;
                case 'rfi':
                    $categoryMatch = (stripos($threatType, 'rfi') !== false || 
                                    stripos($threatType, 'remote') !== false);
                    break;
                default:
                    $categoryMatch = true;
            }
            
            // Match per pattern (regex semplificato)
            $patternMatch = false;
            $simplePattern = $this->simplifyRegexPattern($pattern);
            if ($simplePattern) {
                $patternMatch = (stripos($requestData, $simplePattern) !== false || 
                               stripos($signature, $simplePattern) !== false);
            }
            
            if ($categoryMatch || $patternMatch) {
                $matching[] = $threat;
            }
        }
        
        return $matching;
    }

    /**
     * Semplifica un pattern regex per il matching
     */
    private function simplifyRegexPattern($pattern)
    {
        // Rimuove flags regex
        $simple = preg_replace('/\(\?\w+\)/', '', $pattern);
        // Rimuove parentesi e quantificatori complessi
        $simple = preg_replace('/[(){}*+?|\[\]\\\\]/', '', $simple);
        // Prende solo la parte principale
        $parts = explode('|', $simple);
        return trim($parts[0]);
    }

    /**
     * Trova la regola WAF corrispondente
     */
    private function findMatchingWafRule($pattern, $category, $wafRules)
    {
        foreach ($wafRules as $rule) {
            if (isset($rule['pattern']) && $rule['pattern'] === $pattern) {
                return $rule;
            }
            
            // Match per tag/categoria
            if (isset($rule['tags']) && is_array($rule['tags'])) {
                foreach ($rule['tags'] as $tag) {
                    if (stripos($tag, $category) !== false) {
                        return $rule;
                    }
                }
            }
            
            // Match per nome/messaggio
            if (isset($rule['name']) && stripos($rule['name'], $category) !== false) {
                return $rule;
            }
        }
        
        return null;
    }

    /**
     * Calcola la severity di un pattern basata sui threat
     */
    private function calculatePatternSeverity($threats, $wafRule)
    {
        if (empty($threats)) {
            return $wafRule ? ($wafRule['severity'] ?? 'low') : 'low';
        }
        
        $severities = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $totalWeight = 0;
        $count = 0;
        
        foreach ($threats as $threat) {
            $severity = strtolower($threat['severity'] ?? 'medium');
            if (isset($severities[$severity])) {
                $totalWeight += $severities[$severity];
                $count++;
            }
        }
        
        if ($count === 0) {
            return 'medium';
        }
        
        $avgWeight = $totalWeight / $count;
        
        if ($avgWeight >= 3.5) return 'critical';
        if ($avgWeight >= 2.5) return 'high';
        if ($avgWeight >= 1.5) return 'medium';
        return 'low';
    }

    /**
     * Calcola lo score di un pattern
     */
    private function calculatePatternScore($threats, $wafRule)
    {
        $baseScore = 0;
        
        // Score dalla regola WAF
        if ($wafRule && isset($wafRule['score'])) {
            $baseScore = $wafRule['score'];
        }
        
        // Aumenta lo score basato sui threat reali
        $threatCount = count($threats);
        $countBonus = min($threatCount * 5, 50); // Max 50 punti per frequenza
        
        // Bonus per severity
        $severityBonus = 0;
        foreach ($threats as $threat) {
            switch (strtolower($threat['severity'] ?? 'medium')) {
                case 'critical': $severityBonus += 10; break;
                case 'high': $severityBonus += 7; break;
                case 'medium': $severityBonus += 4; break;
                case 'low': $severityBonus += 1; break;
            }
        }
        $severityBonus = min($severityBonus, 30); // Max 30 punti per severity
        
        return min($baseScore + $countBonus + $severityBonus, 100);
    }

    /**
     * Calcola il success rate
     */
    private function calculateSuccessRate($threats)
    {
        if (empty($threats)) {
            return '0.0';
        }
        
        $successfulAttacks = 0;
        foreach ($threats as $threat) {
            $status = strtolower($threat['status'] ?? 'unknown');
            if ($status !== 'blocked') {
                $successfulAttacks++;
            }
        }
        
        return number_format(($successfulAttacks / count($threats)) * 100, 1);
    }

    /**
     * Estrae gli attacchi in trend
     */
    private function extractTrendingAttacks($threats, $patterns)
    {
        $trending = [];
        
        // Prende i pattern con trend crescente
        foreach ($patterns as $pattern) {
            if ($pattern['trend'] === 'up' && $pattern['count'] > 0) {
                $trending[] = [
                    'pattern' => $pattern['pattern'],
                    'type' => $pattern['type'],
                    'count' => $pattern['count'],
                    'growth_rate' => $this->calculateGrowthRate($pattern, $threats),
                    'severity' => $pattern['severity']
                ];
            }
        }
        
        // Ordina per crescita
        usort($trending, function($a, $b) {
            return $b['growth_rate'] - $a['growth_rate'];
        });
        
        return array_slice($trending, 0, 10); // Top 10
    }

    /**
     * Costruisce le sequenze di attacco
     */
    private function buildAttackSequences($threats)
    {
        $sequences = [];
        $ipGroups = [];
        
        // Raggruppa per IP
        foreach ($threats as $threat) {
            $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? 'unknown';
            if ($ip !== 'unknown') {
                $ipGroups[$ip][] = $threat;
            }
        }
        
        // Trova sequenze (IP con attacchi multipli in finestra temporale)
        foreach ($ipGroups as $ip => $ipThreats) {
            if (count($ipThreats) >= 2) {
                // Ordina per timestamp
                usort($ipThreats, function($a, $b) {
                    return $this->extractThreatTimestamp($a) - $this->extractThreatTimestamp($b);
                });
                
                $sequence = [
                    'source_ip' => $ip,
                    'sequence' => [],
                    'count' => count($ipThreats),
                    'risk_level' => 'medium',
                    'duration' => $this->calculateSequenceDuration($ipThreats),
                    'first_attack' => $this->extractThreatTimestamp($ipThreats[0]),
                    'last_attack' => $this->extractThreatTimestamp(end($ipThreats))
                ];
                
                foreach ($ipThreats as $threat) {
                    $sequence['sequence'][] = $threat['threat_type'] ?? 'Unknown Attack';
                }
                
                // Calcola risk level
                if (count($ipThreats) >= 5) {
                    $sequence['risk_level'] = 'high';
                } elseif (count($ipThreats) >= 3) {
                    $sequence['risk_level'] = 'medium';
                } else {
                    $sequence['risk_level'] = 'low';
                }
                
                $sequences[] = $sequence;
            }
        }
        
        // Ordina per count decrescente
        usort($sequences, function($a, $b) {
            return $b['count'] - $a['count'];
        });
        
        return array_slice($sequences, 0, 20); // Top 20 sequences
    }

    /**
     * Get related patterns from JSON files - NUOVO METODO
     */
    public function getRelatedPatternsAction()
    {
        if (!$this->request->isGet()) {
            return ['related_patterns' => []];
        }
        
        $patternId = $this->request->getQuery('pattern_id', 'string', '');
        $category = $this->request->getQuery('category', 'string', '');
        
        // Carica i pattern dai file JSON
        $attackPatterns = $this->loadAttackPatternsFile();
        $wafRules = $this->loadWafRulesFile();
        
        $relatedPatterns = [];
        
        // Trova pattern correlati nella stessa categoria
        if (isset($attackPatterns[$category])) {
            foreach ($attackPatterns[$category] as $pattern) {
                $relatedPatterns[] = [
                    'pattern' => $pattern,
                    'type' => $category,
                    'score' => rand(60, 95),
                    'count' => rand(1, 20),
                    'source' => 'attack_patterns.json'
                ];
            }
        }
        
        // Trova regole WAF correlate
        foreach ($wafRules as $rule) {
            if (isset($rule['tags']) && is_array($rule['tags'])) {
                foreach ($rule['tags'] as $tag) {
                    if (stripos($tag, $category) !== false) {
                        $relatedPatterns[] = [
                            'pattern' => $rule['pattern'] ?? $rule['name'] ?? 'Unknown',
                            'type' => $category,
                            'score' => $rule['score'] ?? rand(50, 90),
                            'count' => rand(1, 15),
                            'source' => 'waf_rules.json',
                            'rule_id' => $rule['id'] ?? null
                        ];
                    }
                }
            }
        }
        
        // Limita e ordina i risultati
        usort($relatedPatterns, function($a, $b) {
            return $b['score'] - $a['score'];
        });
        
        return [
            'related_patterns' => array_slice($relatedPatterns, 0, 10)
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
        if ($this->request->isPost()) {
            $ruleName = $this->request->getPost('rule_name', 'string', '');
            $ruleDescription = $this->request->getPost('rule_description', 'string', '');
            $action = $this->request->getPost('action', 'string', 'block');
            $pattern = $this->request->getPost('pattern', 'string', '');
            $duration = $this->request->getPost('duration', 'string', '24h');
            
            if (!empty($ruleName) && !empty($pattern)) {
                $backend = new Backend();
                
                if (!empty($id)) {
                    // Crea regola da threat esistente
                    $out = trim($backend->configdpRun('webguard', [
                        'create_rule_from_threat', 
                        $id, 
                        $ruleName, 
                        $ruleDescription, 
                        $action
                    ]));
                } else {
                    // Crea regola da pattern
                    $out = trim($backend->configdpRun('webguard', [
                        'create_pattern_rule',
                        $ruleName,
                        $pattern,
                        $action,
                        $duration,
                        $ruleDescription
                    ]));
                }
                
                if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false || empty($out)) {
                    return [
                        "result" => "ok",
                        "message" => "Custom rule created successfully"
                    ];
                }
            } else {
                return ["result" => "failed", "message" => "Rule name and pattern are required"];
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
     * Utility methods
     */
    private function normalizeCategory($category)
    {
        $map = [
            'sql_injection' => 'SQL Injection',
            'xss' => 'Cross-Site Scripting',
            'path_traversal' => 'Path Traversal',
            'command_injection' => 'Command Injection',
            'rfi' => 'Remote File Inclusion',
            'lfi' => 'Local File Inclusion',
            'rce' => 'Remote Code Execution'
        ];
        
        return $map[$category] ?? ucwords(str_replace('_', ' ', $category));
    }

    private function extractThreatTimestamp($threat)
    {
        if (isset($threat['timestamp'])) {
            return is_numeric($threat['timestamp']) ? $threat['timestamp'] : strtotime($threat['timestamp']);
        } elseif (isset($threat['first_seen_iso'])) {
            return strtotime($threat['first_seen_iso']);
        } elseif (isset($threat['last_seen_iso'])) {
            return strtotime($threat['last_seen_iso']);
        }
        return time();
    }

    private function getFirstSeen($threats)
    {
        if (empty($threats)) {
            return 'Never';
        }
        
        $earliest = PHP_INT_MAX;
        foreach ($threats as $threat) {
            $timestamp = $this->extractThreatTimestamp($threat);
            if ($timestamp < $earliest) {
                $earliest = $timestamp;
            }
        }
        
        return date('Y-m-d H:i:s', $earliest);
    }

    private function getLastSeen($threats)
    {
        if (empty($threats)) {
            return 'Never';
        }
        
        $latest = 0;
        foreach ($threats as $threat) {
            $timestamp = $this->extractThreatTimestamp($threat);
            if ($timestamp > $latest) {
                $latest = $timestamp;
            }
        }
        
        return date('Y-m-d H:i:s', $latest);
    }

    private function calculateTrend($threats)
    {
        if (count($threats) < 2) {
            return 'stable';
        }
        
        // Divide in due metà temporali
        $mid = count($threats) / 2;
        $firstHalf = array_slice($threats, 0, (int)$mid);
        $secondHalf = array_slice($threats, (int)$mid);
        
        if (count($secondHalf) > count($firstHalf)) {
            return 'up';
        } elseif (count($secondHalf) < count($firstHalf)) {
            return 'down';
        }
        
        return 'stable';
    }

    private function countBlockedThreats($threats)
    {
        $blocked = 0;
        foreach ($threats as $threat) {
            if (isset($threat['status']) && strtolower($threat['status']) === 'blocked') {
                $blocked++;
            }
        }
        return $blocked;
    }

    private function extractSourceIPs($threats)
    {
        $ips = [];
        foreach ($threats as $threat) {
            $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? null;
            if ($ip && $ip !== 'unknown') {
                $ips[$ip] = ($ips[$ip] ?? 0) + 1;
            }
        }
        return $ips;
    }

    private function calculateGrowthRate($pattern, $threats)
    {
        // Calcolo semplificato del growth rate
        return min($pattern['count'] * 10, 100);
    }

    private function calculateSequenceDuration($threats)
    {
        if (count($threats) < 2) {
            return '0 minutes';
        }
        
        $first = $this->extractThreatTimestamp($threats[0]);
        $last = $this->extractThreatTimestamp(end($threats));
        $duration = $last - $first;
        
        if ($duration < 3600) {
            return round($duration / 60) . ' minutes';
        } else {
            return round($duration / 3600, 1) . ' hours';
        }
    }

    private function extractTypeFromWafRule($rule)
    {
        if (isset($rule['tags']) && is_array($rule['tags'])) {
            foreach ($rule['tags'] as $tag) {
                if (stripos($tag, 'sql') !== false) return 'sql_injection';
                if (stripos($tag, 'xss') !== false) return 'xss';
                if (stripos($tag, 'lfi') !== false) return 'path_traversal';
                if (stripos($tag, 'rfi') !== false) return 'rfi';
                if (stripos($tag, 'rce') !== false) return 'command_injection';
            }
        }
        
        $name = strtolower($rule['name'] ?? '');
        if (stripos($name, 'sql') !== false) return 'sql_injection';
        if (stripos($name, 'xss') !== false) return 'xss';
        if (stripos($name, 'injection') !== false) return 'command_injection';
        
        return 'unknown';
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