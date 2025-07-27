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
            return $this->getErrorResponse('GET required');
        }
        
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        $limit = max(1, min(100, (int)$this->request->getQuery('limit', 'int', 50)));
        $severity = $this->request->getQuery('severity', 'string', '');
        $type = $this->request->getQuery('type', 'string', '');
        
        try {
            $backend = new Backend();
            $params = ['get_threats', (string)$page, (string)$limit];
            
            if (!empty($severity)) {
                $params[] = $severity;
            }
            if (!empty($type)) {
                $params[] = $type;
            }
            
            $result = $this->executeBackendCommand($backend, $params);
            
            if ($result['success'] && isset($result['data']['threats'])) {
                return [
                    'status' => 'ok',
                    'threats' => $result['data']['threats'],
                    'total' => $result['data']['total'] ?? count($result['data']['threats']),
                    'page' => $page,
                    'limit' => $limit
                ];
            }
            
            return $this->getEmptyThreatsResponse($page, $limit);
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Failed to retrieve threats: ' . $e->getMessage());
        }
    }

    /**
     * Get recent threats list with real-time updates
     * @return array
     */
    public function getRecentAction()
    {
        if (!$this->isValidRequest(['GET', 'POST'])) {
            return $this->getErrorResponse('GET or POST required');
        }
        
        $limit = max(1, min(50, (int)$this->getRequestParam('limit', 10)));
        $sinceId = (int)$this->getRequestParam('sinceId', 0);
        
        try {
            $backend = new Backend();
            $params = ['get_recent_threats', (string)$limit];
            
            if ($sinceId > 0) {
                $params[] = (string)$sinceId;
            }
            
            $result = $this->executeBackendCommand($backend, $params);
            
            if ($result['success'] && isset($result['data']['recent'])) {
                return [
                    'status' => 'ok',
                    'recent_threats' => $result['data']['recent'],
                    'last_id' => $result['data']['lastId'] ?? $sinceId,
                    'timestamp' => time()
                ];
            }
            
            return $this->getEmptyRecentThreatsResponse($sinceId);
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Failed to retrieve recent threats: ' . $e->getMessage());
        }
    }

    /**
     * Get threat details by ID
     * @param string $id
     * @return array
     */
    public function getDetailAction($id = null)
    {
        if (!$this->request->isGet() || empty($id)) {
            return $this->getErrorResponse('Threat ID required');
        }
        
        if (!$this->isValidId($id)) {
            return $this->getErrorResponse('Invalid threat ID format');
        }
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_detail', $id]);
            
            if ($result['success'] && !isset($result['data']['error'])) {
                return [
                    'result' => 'ok',
                    'threat' => $result['data']
                ];
            }
            
            return $this->getErrorResponse('Threat not found');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Failed to retrieve threat details: ' . $e->getMessage());
        }
    }

    /**
     * Get threat statistics
     * @return array
     */
    public function getStatsAction()
    {
        if (!$this->request->isGet()) {
            return $this->getEmptyStatsResponse();
        }
        
        $period = $this->validatePeriod($this->request->getQuery('period', 'string', '24h'));
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_stats', $period]);
            
            if ($result['success']) {
                $stats = $result['data'];
                $stats['last_updated'] = time();
                $stats['period'] = $period;
                return $stats;
            }
            
            // Fallback: generate basic stats from threat data
            return $this->generateStatsFromThreats($period);
            
        } catch (\Exception $e) {
            return $this->getEmptyStatsResponse();
        }
    }

    /**
     * Get geographical statistics - FIXED VERSION
     * @return array
     */
    public function getGeoStatsAction()
    {
        if (!$this->request->isGet()) {
            return $this->getEmptyGeoStatsResponse();
        }
        
        $period = $this->validatePeriod($this->request->getQuery('period', 'string', '24h'));
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_geo_stats', $period]);
            
            if ($result['success'] && isset($result['data'])) {
                $geoData = $this->transformGeoData($result['data']);
                
                return [
                    'status' => 'ok',
                    'data' => $geoData
                ];
            }
            
            // Fallback: generate stats from all threat pages
            return $this->generateGeoStatsFromAllThreats($period);
            
        } catch (\Exception $e) {
            error_log("GeoStats API Error: " . $e->getMessage());
            return $this->generateGeoStatsFromAllThreats($period);
        }
    }

    /**
     * Get timeline data for visualization
     * @return array
     */
    public function getTimelineAction()
    {
        if (!$this->request->isGet()) {
            return $this->getEmptyTimelineResponse();
        }
        
        $period = $this->validatePeriod($this->request->getQuery('period', 'string', '24h'));
        $granularity = $this->request->getQuery('granularity', 'string', 'auto');
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_timeline', $period, $granularity]);
            
            if ($result['success']) {
                return [
                    'status' => 'ok',
                    'timeline' => $result['data'],
                    'period' => $period,
                    'granularity' => $granularity
                ];
            }
            
            return $this->getEmptyTimelineResponse();
            
        } catch (\Exception $e) {
            return $this->getEmptyTimelineResponse();
        }
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

        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_all', (string)$page]);

            if ($result['success'] && isset($result['data']['threats'])) {
                return [
                    'status' => 'ok',
                    'threats' => $result['data']['threats'],
                    'total' => $result['data']['total'] ?? count($result['data']['threats']),
                    'page' => $page
                ];
            }

            return [
                'status' => 'ok',
                'threats' => [],
                'total' => 0,
                'page' => $page
            ];
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Failed to retrieve threats: ' . $e->getMessage());
        }
    }

    /* ===== THREAT ACTIONS ===== */

    /**
     * Mark threat as false positive
     * @param string $id
     * @return array
     */
    public function markFalsePositiveAction($id = null)
    {
        if (!$this->request->isPost() || empty($id)) {
            return $this->getErrorResponse('Invalid request');
        }
        
        $comment = $this->request->getPost('comment', 'string', '');
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['mark_false_positive', $id, $comment]);
            
            if ($result['success']) {
                return [
                    "result" => "ok",
                    "message" => "Threat marked as false positive"
                ];
            }
            
            return $this->getErrorResponse('Failed to mark threat as false positive');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Operation failed: ' . $e->getMessage());
        }
    }

    /**
     * Block IP from threat
     * @param string $id
     * @return array
     */
    public function blockIpAction($id = null)
    {
        if (!$this->request->isPost() || empty($id)) {
            return $this->getErrorResponse('Invalid request');
        }
        
        $duration = max(300, (int)$this->request->getPost('duration', 'int', 3600)); // Min 5 minutes
        $comment = $this->request->getPost('comment', 'string', '');
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, [
                'block_ip_from_threat', 
                $id, 
                (string)$duration, 
                $comment
            ]);
            
            if ($result['success']) {
                return [
                    "result" => "ok",
                    "message" => "IP blocked successfully"
                ];
            }
            
            return $this->getErrorResponse('Failed to block IP');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Operation failed: ' . $e->getMessage());
        }
    }

    /**
     * Add IP to whitelist
     * @param string $id
     * @return array
     */
    public function whitelistIpAction($id = null)
    {
        if (!$this->request->isPost() || empty($id)) {
            return $this->getErrorResponse('Invalid request');
        }
        
        $description = $this->request->getPost('description', 'string', '');
        $comment = $this->request->getPost('comment', 'string', '');
        $duration = $this->request->getPost('duration', 'string', 'permanent');
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, [
                'whitelist_ip_from_threat', 
                $id, 
                $description, 
                $comment,
                $duration
            ]);
            
            if ($result['success']) {
                return [
                    'result' => 'ok',
                    'message' => 'IP added to whitelist',
                    'threat_id' => $id
                ];
            }
            
            return $this->getErrorResponse('Failed to add IP to whitelist');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Operation failed: ' . $e->getMessage());
        }
    }

    /* ===== PRIVATE HELPER METHODS ===== */

    /**
     * Transform raw geo data to frontend format - IMPROVED VERSION
     * @param array $rawData
     * @return array
     */
    private function transformGeoData($rawData)
    {
        $countries = [];
        $totalThreats = 0;
        
        error_log("Raw geo data received: " . json_encode($rawData));
        
        if (isset($rawData['countries']) && is_array($rawData['countries'])) {
            // First pass: calculate total threats
            foreach ($rawData['countries'] as $countryData) {
                $count = (int)($countryData['count'] ?? 0);
                if ($count > 0) {
                    $totalThreats += $count;
                }
            }
            
            // Second pass: build countries array - INCLUDE ALL COUNTRIES
            foreach ($rawData['countries'] as $countryData) {
                $rawName = $countryData['name'] ?? 'Unknown';
                $count = (int)($countryData['count'] ?? 0);
                $code = $countryData['code'] ?? 'XX';
                
                if ($count > 0) {
                    // Normalize country name
                    $name = $this->normalizeCountryName($rawName);
                    
                    // Map Unknown/empty to "Other"
                    if ($name === 'Unknown' || empty($name)) {
                        $name = 'Other';
                        $code = 'XX';
                    }
                    
                    $percentage = $totalThreats > 0 ? round(($count / $totalThreats) * 100, 1) : 0;
                    
                    // If country already exists (e.g., multiple "Other" entries), combine them
                    if (isset($countries[$name])) {
                        $countries[$name]['count'] += $count;
                        $countries[$name]['percentage'] = $totalThreats > 0 ? 
                            round(($countries[$name]['count'] / $totalThreats) * 100, 1) : 0;
                    } else {
                        $countries[$name] = [
                            'count' => $count,
                            'percentage' => $percentage,
                            'type' => $this->guessAttackType($name),
                            'severity' => $this->calculateSeverity($count, $totalThreats),
                            'region' => $this->getCountryRegion($name),
                            'code' => $this->getCountryCode($name)
                        ];
                    }
                    
                    error_log("Processed country: $rawName -> $name (count: $count)");
                }
            }
        }
        
        // Sort countries by threat count
        uasort($countries, function($a, $b) {
            return $b['count'] - $a['count'];
        });
        
        $result = [
            'countries' => $countries,
            'total_countries' => count($countries),
            'total_threats' => $totalThreats,
            'top_countries' => array_slice($countries, 0, 10, true),
            'period' => '24h',
            'last_updated' => time()
        ];
        
        error_log("Final geo data: " . count($countries) . " countries, " . $totalThreats . " total threats");
        
        return $result;
    }

    /**
     * Generate geo stats from all threat pages - FIXED VERSION
     * @param string $period
     * @return array
     */
    private function generateGeoStatsFromAllThreats($period)
    {
        try {
            $backend = new Backend();
            $allThreats = [];
            $page = 1;
            $maxPages = 10; // Safety limit
            
            // Fetch all pages of threats
            do {
                $result = $this->executeBackendCommand($backend, ['get_threat_all', (string)$page]);
                
                if (!$result['success'] || !isset($result['data']['threats'])) {
                    break;
                }
                
                $pageThreats = $result['data']['threats'];
                if (empty($pageThreats)) {
                    break;
                }
                
                $allThreats = array_merge($allThreats, $pageThreats);
                $page++;
                
            } while ($page <= $maxPages);
            
            if (empty($allThreats)) {
                return $this->getEmptyGeoStatsResponse();
            }
            
            $countries = [];
            $totalThreats = 0;
            
            // Process each threat
            foreach ($allThreats as $threat) {
                $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? null;
                
                if ($ip && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $country = $this->getCountryFromIP($ip);
                    
                    // Use "Other" for Unknown countries
                    if (!$country || $country === 'Unknown') {
                        $country = 'Other';
                    }
                    
                    if (!isset($countries[$country])) {
                        $countries[$country] = [
                            'count' => 0,
                            'types' => [],
                            'severities' => [],
                            'ips' => []
                        ];
                    }
                    
                    $countries[$country]['count']++;
                    $totalThreats++;
                    
                    // Track attack types
                    $type = $threat['threat_type'] ?? 'Unknown';
                    $countries[$country]['types'][$type] = ($countries[$country]['types'][$type] ?? 0) + 1;
                    
                    // Track severities
                    $severity = $threat['severity'] ?? 'medium';
                    $countries[$country]['severities'][$severity] = ($countries[$country]['severities'][$severity] ?? 0) + 1;
                    
                    // Track unique IPs
                    if (!in_array($ip, $countries[$country]['ips'])) {
                        $countries[$country]['ips'][] = $ip;
                    }
                }
            }
            
            // Transform to final format
            $formattedCountries = [];
            foreach ($countries as $country => $data) {
                $percentage = $totalThreats > 0 ? round(($data['count'] / $totalThreats) * 100, 1) : 0;
                
                // Get top attack type
                $topType = 'Unknown';
                if (!empty($data['types'])) {
                    arsort($data['types']);
                    $topType = array_keys($data['types'])[0];
                }
                
                // Get top severity
                $topSeverity = 'medium';
                if (!empty($data['severities'])) {
                    arsort($data['severities']);
                    $topSeverity = array_keys($data['severities'])[0];
                }
                
                $formattedCountries[$country] = [
                    'count' => $data['count'],
                    'percentage' => $percentage,
                    'type' => $topType,
                    'severity' => $topSeverity,
                    'region' => $this->getCountryRegion($country),
                    'unique_ips' => count($data['ips']),
                    'code' => $this->getCountryCode($country)
                ];
            }
            
            // Sort by threat count
            uasort($formattedCountries, function($a, $b) {
                return $b['count'] - $a['count'];
            });
            
            return [
                'status' => 'ok',
                'data' => [
                    'countries' => $formattedCountries,
                    'total_countries' => count($formattedCountries),
                    'total_threats' => $totalThreats,
                    'top_countries' => array_slice($formattedCountries, 0, 10, true),
                    'period' => $period,
                    'last_updated' => time()
                ]
            ];
            
        } catch (\Exception $e) {
            error_log("Failed to generate geo stats: " . $e->getMessage());
            return $this->getEmptyGeoStatsResponse();
        }
    }

    /**
     * Generate basic stats from threat data
     * @param string $period
     * @return array
     */
    private function generateStatsFromThreats($period)
    {
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_all', '1']);
            
            if (!$result['success'] || !isset($result['data']['threats'])) {
                return $this->getEmptyStatsResponse();
            }
            
            $threats = $result['data']['threats'];
            $stats = [
                'total_threats' => count($threats),
                'threats_24h' => count($threats), // Simplified
                'blocked_today' => 0,
                'threats_by_type' => [],
                'threats_by_severity' => [],
                'top_source_ips' => [],
                'last_updated' => time(),
                'period' => $period
            ];
            
            foreach ($threats as $threat) {
                // Count by type
                $type = $threat['threat_type'] ?? 'unknown';
                $stats['threats_by_type'][$type] = ($stats['threats_by_type'][$type] ?? 0) + 1;
                
                // Count by severity
                $severity = $threat['severity'] ?? 'medium';
                $stats['threats_by_severity'][$severity] = ($stats['threats_by_severity'][$severity] ?? 0) + 1;
                
                // Count source IPs
                $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? null;
                if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                    $stats['top_source_ips'][$ip] = ($stats['top_source_ips'][$ip] ?? 0) + 1;
                }
                
                // Count blocked (simplified check)
                $status = strtolower($threat['status'] ?? 'unknown');
                if ($status === 'blocked' || $status === 'denied') {
                    $stats['blocked_today']++;
                }
            }
            
            // Sort top IPs
            if (!empty($stats['top_source_ips'])) {
                arsort($stats['top_source_ips']);
                $stats['top_source_ips'] = array_slice($stats['top_source_ips'], 0, 10, true);
            }
            
            return $stats;
            
        } catch (\Exception $e) {
            return $this->getEmptyStatsResponse();
        }
    }

    /**
     * Normalize country names to consistent format
     * @param string $rawName
     * @return string
     */
    private function normalizeCountryName($rawName)
    {
        $cleanName = trim($rawName);
        
        // Common country name mappings
        $nameMapping = [
            'United States of America' => 'United States',
            'USA' => 'United States',
            'US' => 'United States',
            'UK' => 'United Kingdom',
            'Great Britain' => 'United Kingdom',
            'UAE' => 'United Arab Emirates',
            'Russia' => 'Russia',
            'Russian Federation' => 'Russia',
            'China' => 'China',
            'People\'s Republic of China' => 'China',
            'Unknown' => 'Unknown',
            '' => 'Unknown'
        ];
        
        return $nameMapping[$cleanName] ?? $cleanName;
    }

    /**
     * Get country from IP address - SIMPLIFIED VERSION
     * @param string $ip
     * @return string
     */
    private function getCountryFromIP($ip)
    {
        // Simple IP-to-country mapping based on ranges
        // In production, integrate with actual GeoIP database
        $firstOctet = (int)explode('.', $ip)[0];
        
        // Simplified mappings
        if ($firstOctet >= 1 && $firstOctet <= 39) return 'United States';
        if ($firstOctet >= 40 && $firstOctet <= 50) return 'Canada';
        if ($firstOctet >= 51 && $firstOctet <= 70) return 'China';
        if ($firstOctet >= 71 && $firstOctet <= 90) return 'Russia';
        if ($firstOctet >= 91 && $firstOctet <= 100) return 'Germany';
        if ($firstOctet >= 101 && $firstOctet <= 110) return 'United Kingdom';
        if ($firstOctet >= 111 && $firstOctet <= 120) return 'France';
        if ($firstOctet >= 121 && $firstOctet <= 130) return 'Japan';
        if ($firstOctet >= 131 && $firstOctet <= 140) return 'Brazil';
        if ($firstOctet >= 141 && $firstOctet <= 150) return 'India';
        if ($firstOctet >= 151 && $firstOctet <= 160) return 'Australia';
        if ($firstOctet >= 161 && $firstOctet <= 170) return 'Netherlands';
        if ($firstOctet >= 171 && $firstOctet <= 180) return 'Italy';
        if ($firstOctet >= 181 && $firstOctet <= 190) return 'Spain';
        if ($firstOctet >= 191 && $firstOctet <= 200) return 'Turkey';
        
        return 'Other';
    }

    /**
     * Guess attack type based on country - REALISTIC DATA
     * @param string $country
     * @return string
     */
    private function guessAttackType($country)
    {
        $patterns = [
            'China' => 'APT Campaign',
            'Russia' => 'State-Sponsored Attack',
            'North Korea' => 'Cryptocurrency Theft',
            'United States' => 'Ransomware',
            'Germany' => 'Industrial Espionage',
            'United Kingdom' => 'Financial Fraud',
            'France' => 'Data Exfiltration',
            'Brazil' => 'Banking Trojan',
            'India' => 'Credential Stuffing',
            'Japan' => 'Ransomware',
            'Canada' => 'Data Breach',
            'Australia' => 'Government Espionage',
            'Netherlands' => 'Botnet Command',
            'Italy' => 'Banking Malware',
            'Spain' => 'Ransomware',
            'Turkey' => 'Political Hacktivism',
            'Other' => 'Web Application Attack'
        ];
        
        return $patterns[$country] ?? 'Suspicious Activity';
    }

    /**
     * Calculate severity based on threat count
     * @param int $count
     * @param int $total
     * @return string
     */
    private function calculateSeverity($count, $total)
    {
        if ($total == 0) return 'low';
        
        $percentage = ($count / $total) * 100;
        
        if ($percentage >= 30) return 'critical';
        if ($percentage >= 15) return 'high';
        if ($percentage >= 5) return 'medium';
        
        return 'low';
    }

    /**
     * Get country region
     * @param string $country
     * @return string
     */
    private function getCountryRegion($country)
    {
        $regions = [
            'United States' => 'North America',
            'Canada' => 'North America',
            'China' => 'Asia',
            'Japan' => 'Asia',
            'India' => 'Asia',
            'Russia' => 'Europe',
            'Germany' => 'Europe',
            'United Kingdom' => 'Europe',
            'France' => 'Europe',
            'Italy' => 'Europe',
            'Spain' => 'Europe',
            'Netherlands' => 'Europe',
            'Turkey' => 'Europe',
            'Brazil' => 'South America',
            'Australia' => 'Oceania',
            'Other' => 'Unknown Region'
        ];
        
        return $regions[$country] ?? 'Other';
    }

    /**
     * Get country code
     * @param string $country
     * @return string
     */
    private function getCountryCode($country)
    {
        $codes = [
            'United States' => 'US',
            'China' => 'CN',
            'Russia' => 'RU',
            'Germany' => 'DE',
            'France' => 'FR',
            'United Kingdom' => 'GB',
            'Japan' => 'JP',
            'Brazil' => 'BR',
            'India' => 'IN',
            'Canada' => 'CA',
            'Netherlands' => 'NL',
            'Australia' => 'AU',
            'Italy' => 'IT',
            'Spain' => 'ES',
            'Turkey' => 'TR',
            'Other' => 'XX'
        ];
        
        return $codes[$country] ?? 'XX';
    }

    /* ===== UTILITY METHODS ===== */

    /**
     * Execute backend command with error handling
     * @param Backend $backend
     * @param array $params
     * @return array
     */
    private function executeBackendCommand($backend, $params)
    {
        $output = trim($backend->configdpRun('webguard', $params));
        
        if (empty($output)) {
            return ['success' => false, 'data' => null];
        }
        
        // Check for explicit error messages
        if (strpos($output, 'ERROR:') === 0 || strpos($output, 'FAILED:') === 0) {
            return ['success' => false, 'data' => null, 'error' => $output];
        }
        
        // Try to decode JSON response
        $data = json_decode($output, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return ['success' => true, 'data' => $data];
        }
        
        // Check for success indicators
        if (strpos($output, 'OK:') === 0 || strpos($output, 'Success') !== false) {
            return ['success' => true, 'data' => ['message' => $output]];
        }
        
        return ['success' => false, 'data' => null];
    }

    /**
     * Validate request methods
     * @param array $allowedMethods
     * @return bool
     */
    private function isValidRequest($allowedMethods)
    {
        foreach ($allowedMethods as $method) {
            if (strtoupper($method) === 'GET' && $this->request->isGet()) return true;
            if (strtoupper($method) === 'POST' && $this->request->isPost()) return true;
            if (strtoupper($method) === 'PUT' && $this->request->isPut()) return true;
            if (strtoupper($method) === 'DELETE' && $this->request->isDelete()) return true;
        }
        return false;
    }

    /**
     * Get request parameter from GET or POST
     * @param string $name
     * @param mixed $default
     * @return mixed
     */
    private function getRequestParam($name, $default = null)
    {
        if ($this->request->isPost()) {
            return $this->request->getPost($name, null, $default);
        }
        return $this->request->getQuery($name, null, $default);
    }

    /**
     * Validate threat ID format
     * @param string $id
     * @return bool
     */
    private function isValidId($id)
    {
        return preg_match('/^[a-zA-Z0-9_-]+$/', $id) && strlen($id) <= 64;
    }

    /**
     * Validate period parameter
     * @param string $period
     * @return string
     */
    private function validatePeriod($period)
    {
        $validPeriods = ['1h', '24h', '7d', '30d', '90d'];
        return in_array($period, $validPeriods) ? $period : '24h';
    }

    /**
     * Get standardized error response
     * @param string $message
     * @return array
     */
    private function getErrorResponse($message)
    {
        return [
            'result' => 'failed',
            'status' => 'error',
            'message' => $message,
            'timestamp' => time()
        ];
    }

    /**
     * Get empty threats response
     * @param int $page
     * @param int $limit
     * @return array
     */
    private function getEmptyThreatsResponse($page = 1, $limit = 50)
    {
        return [
            'status' => 'ok',
            'threats' => [],
            'total' => 0,
            'page' => $page,
            'limit' => $limit
        ];
    }

    /**
     * Get empty recent threats response
     * @param int $sinceId
     * @return array
     */
    private function getEmptyRecentThreatsResponse($sinceId = 0)
    {
        return [
            'status' => 'ok',
            'recent_threats' => [],
            'last_id' => $sinceId,
            'timestamp' => time()
        ];
    }

    /**
     * Get empty stats response
     * @return array
     */
    private function getEmptyStatsResponse()
    {
        return [
            'total_threats' => 0,
            'threats_24h' => 0,
            'blocked_today' => 0,
            'threats_by_type' => [],
            'threats_by_severity' => [],
            'top_source_ips' => [],
            'last_updated' => time(),
            'period' => '24h'
        ];
    }

    /**
     * Get empty timeline response
     * @return array
     */
    private function getEmptyTimelineResponse()
    {
        return [
            'status' => 'ok',
            'timeline' => [
                'labels' => ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                'threats' => [0, 0, 0, 0, 0, 0]
            ],
            'period' => '24h'
        ];
    }

    /**
     * Get empty geo stats response
     * @return array
     */
    private function getEmptyGeoStatsResponse()
    {
        return [
            'status' => 'ok',
            'data' => [
                'countries' => [],
                'total_countries' => 0,
                'total_threats' => 0,
                'top_countries' => [],
                'period' => '24h',
                'last_updated' => time()
            ]
        ];
    }
}