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
     * Get real-time threat feed for dashboard updates
     * @return array
     */
    public function getFeedAction()
    {
        if (!$this->isValidRequest(['GET', 'POST'])) {
            return $this->getErrorResponse('GET or POST required');
        }
        
        $sinceId = (int)$this->getRequestParam('sinceId', 0);
        $limit = max(1, min(100, (int)$this->getRequestParam('limit', 50)));
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, [
                'get_threat_feed', 
                (string)$sinceId, 
                (string)$limit
            ]);
            
            if ($result['success'] && isset($result['data']['feed'])) {
                return [
                    'status' => 'ok',
                    'recent_threats' => $result['data']['feed'],
                    'last_id' => $result['data']['lastId'] ?? $sinceId,
                    'has_more' => $result['data']['hasMore'] ?? false,
                    'timestamp' => time()
                ];
            }
            
            return $this->getEmptyFeedResponse($sinceId);
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Failed to retrieve threat feed: ' . $e->getMessage());
        }
    }

    /**
     * Get threat details by ID with enhanced information
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
                // Enrich threat data with pattern analysis
                $threatData = $this->enrichThreatData($result['data']);
                
                return [
                    'result' => 'ok',
                    'threat' => $threatData,
                    'related_patterns' => $this->findRelatedPatterns($threatData),
                    'mitigation_suggestions' => $this->getMitigationSuggestions($threatData)
                ];
            }
            
            return $this->getErrorResponse('Threat not found');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Failed to retrieve threat details: ' . $e->getMessage());
        }
    }

    /**
     * Get comprehensive threat statistics with JSON file integration
     * @return array
     */
    public function getStatsAction()
    {
        if (!$this->request->isGet()) {
            return $this->getEmptyStatsResponse();
        }
        
        $period = $this->validatePeriod($this->request->getQuery('period', 'string', '24h'));
        $includePatterns = $this->request->getQuery('include_patterns', 'string', 'true') === 'true';
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_stats', $period]);
            
            if ($result['success']) {
                $stats = $result['data'];
                
                // Integrate with JSON pattern files if requested
                if ($includePatterns) {
                    $stats = $this->enrichStatsWithPatterns($stats, $period);
                }
                
                // Add real-time metrics
                $stats['last_updated'] = time();
                $stats['period'] = $period;
                $stats['detection_rate'] = $this->calculateDetectionRate($stats);
                
                return $stats;
            }
            
            // Fallback: generate stats from database
            return $this->generateStatsFromDatabase($period, $includePatterns);
            
        } catch (\Exception $e) {
            return $this->getEmptyStatsResponse();
        }
    }

    /**
     * Get attack patterns with comprehensive analysis
     * @return array
     */
    public function getPatternsAction()
    {
        if (!$this->request->isGet()) {
            return $this->getEmptyPatternsResponse();
        }
        
        $period = $this->validatePeriod($this->request->getQuery('period', 'string', '7d'));
        $patternType = $this->validatePatternType($this->request->getQuery('pattern_type', 'string', 'all'));
        $includeInactive = $this->request->getQuery('include_inactive', 'string', 'false') === 'true';
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, [
                'get_attack_patterns', 
                $period, 
                $patternType
            ]);
            
            if ($result['success']) {
                return $this->processPatternData($result['data'], $period, $includeInactive);
            }
            
            // Fallback: build patterns from JSON files and real data
            return $this->buildPatternsFromIntegratedData($period, $patternType, $includeInactive);
            
        } catch (\Exception $e) {
            return $this->getEmptyPatternsResponse();
        }
    }

    /**
     * Get timeline data for threat visualization
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
            
            // Generate timeline from real data
            return $this->generateTimelineFromDatabase($period, $granularity);
            
        } catch (\Exception $e) {
            return $this->getEmptyTimelineResponse();
        }
    }

    /**
     * Get related patterns for a specific pattern
     * @return array
     */
    public function getRelatedPatternsAction()
    {
        if (!$this->request->isGet()) {
            return ['related_patterns' => []];
        }
        
        $patternId = $this->request->getQuery('pattern_id', 'string', '');
        $category = $this->request->getQuery('category', 'string', '');
        $limit = max(1, min(20, (int)$this->request->getQuery('limit', 'int', 10)));
        
        if (empty($category)) {
            return ['related_patterns' => []];
        }
        
        try {
            $relatedPatterns = $this->findRelatedPatternsFromSources($patternId, $category, $limit);
            
            return [
                'related_patterns' => $relatedPatterns,
                'total' => count($relatedPatterns),
                'category' => $category
            ];
            
        } catch (\Exception $e) {
            return ['related_patterns' => []];
        }
    }

    /**
     * Get geographical statistics
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
            
            if ($result['success']) {
                return $result['data'];
            }
            
            return $this->getEmptyGeoStatsResponse();
            
        } catch (\Exception $e) {
            return $this->getEmptyGeoStatsResponse();
        }
    }

    /* ===== THREAT MANAGEMENT ACTIONS ===== */

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
     * Add IP to whitelist from threat
     * @param string $id
     * @return array
     */
    public function whitelistIpAction($id = null)
    {
        if (!$this->request->isPost() || empty($id)) {
            return $this->getErrorResponse('Invalid request');
        }
        
        if (!$this->isValidId($id)) {
            return $this->getErrorResponse('Invalid threat ID');
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
     * Create custom rule from pattern or threat
     * @param string $id
     * @return array
     */
    public function createRuleAction($id = null)
    {
        if (!$this->request->isPost()) {
            return $this->getErrorResponse('POST required');
        }
        
        $ruleName = trim($this->request->getPost('rule_name', 'string', ''));
        $ruleDescription = $this->request->getPost('rule_description', 'string', '');
        $action = $this->validateRuleAction($this->request->getPost('action', 'string', 'block'));
        $pattern = trim($this->request->getPost('pattern', 'string', ''));
        $duration = $this->request->getPost('duration', 'string', '24h');
        $severity = $this->validateSeverity($this->request->getPost('severity', 'string', 'medium'));
        
        if (empty($ruleName)) {
            return $this->getErrorResponse('Rule name is required');
        }
        
        try {
            $backend = new Backend();
            $params = [];
            
            if (!empty($id) && $this->isValidId($id)) {
                // Create rule from existing threat
                $params = [
                    'create_rule_from_threat', 
                    $id, 
                    $ruleName, 
                    $ruleDescription, 
                    $action,
                    $severity
                ];
            } elseif (!empty($pattern)) {
                // Create rule from pattern
                $params = [
                    'create_pattern_rule',
                    $ruleName,
                    $pattern,
                    $action,
                    $duration,
                    $ruleDescription,
                    $severity
                ];
            } else {
                return $this->getErrorResponse('Either threat ID or pattern is required');
            }
            
            $result = $this->executeBackendCommand($backend, $params);
            
            if ($result['success']) {
                return [
                    'result' => 'ok',
                    'message' => 'Custom rule created successfully',
                    'rule_name' => $ruleName,
                    'action' => $action
                ];
            }
            
            return $this->getErrorResponse('Failed to create custom rule');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Operation failed: ' . $e->getMessage());
        }
    }

    /**
     * Export threats data in various formats
     * @return array
     */
    public function exportAction()
    {
        if (!$this->request->isGet()) {
            return $this->getErrorResponse('GET required');
        }
        
        $format = $this->validateExportFormat($this->request->getQuery('format', 'string', 'json'));
        $startDate = $this->request->getQuery('start_date', 'string', '');
        $endDate = $this->request->getQuery('end_date', 'string', '');
        $severity = $this->request->getQuery('severity', 'string', '');
        $type = $this->request->getQuery('type', 'string', '');
        $limit = max(1, min(10000, (int)$this->request->getQuery('limit', 'int', 1000)));
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, [
                'export_threats',
                $format,
                $startDate,
                $endDate,
                $severity,
                $type,
                (string)$limit
            ]);
            
            if ($result['success'] && !empty($result['data'])) {
                $filename = $this->generateExportFilename($format);
                
                return [
                    'result' => 'ok',
                    'data' => $result['data'],
                    'filename' => $filename,
                    'format' => $format,
                    'total_records' => $result['total'] ?? 0
                ];
            }
            
            return $this->getErrorResponse('No data available for export');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Export failed: ' . $e->getMessage());
        }
    }

    /**
     * Clear old threats with safety checks
     * @return array
     */
    public function clearOldAction()
    {
        if (!$this->request->isPost()) {
            return $this->getErrorResponse('POST required');
        }
        
        $daysOld = max(1, (int)$this->request->getPost('days_old', 'int', 30));
        $keepCritical = $this->request->getPost('keep_critical', 'string', 'true') === 'true';
        $keepFalsePositives = $this->request->getPost('keep_false_positives', 'string', 'true') === 'true';
        $dryRun = $this->request->getPost('dry_run', 'string', 'false') === 'true';
        
        if ($daysOld < 7) {
            return $this->getErrorResponse('Cannot delete threats newer than 7 days');
        }
        
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, [
                'clear_old_threats', 
                (string)$daysOld, 
                $keepCritical ? 'true' : 'false',
                $keepFalsePositives ? 'true' : 'false',
                $dryRun ? 'true' : 'false'
            ]);
            
            if ($result['success']) {
                return [
                    'result' => 'ok',
                    'message' => $dryRun ? 'Dry run completed' : 'Old threats cleared successfully',
                    'affected_count' => $result['data']['affected'] ?? 0,
                    'dry_run' => $dryRun
                ];
            }
            
            return $this->getErrorResponse('Failed to clear old threats');
            
        } catch (\Exception $e) {
            return $this->getErrorResponse('Operation failed: ' . $e->getMessage());
        }
    }

    /* ===== UTILITY AND HELPER METHODS ===== */

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
        
        // Check for success indicators in plain text
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
     * Validate pattern type
     * @param string $type
     * @return string
     */
    private function validatePatternType($type)
    {
        $validTypes = ['all', 'sql_injection', 'xss', 'path_traversal', 'command_injection', 'rfi', 'lfi'];
        return in_array($type, $validTypes) ? $type : 'all';
    }

    /**
     * Validate rule action
     * @param string $action
     * @return string
     */
    private function validateRuleAction($action)
    {
        $validActions = ['block', 'log', 'challenge', 'redirect'];
        return in_array($action, $validActions) ? $action : 'block';
    }

    /**
     * Validate severity level
     * @param string $severity
     * @return string
     */
    private function validateSeverity($severity)
    {
        $validSeverities = ['low', 'medium', 'high', 'critical'];
        return in_array($severity, $validSeverities) ? $severity : 'medium';
    }

    /**
     * Validate export format
     * @param string $format
     * @return string
     */
    private function validateExportFormat($format)
    {
        $validFormats = ['json', 'csv', 'xml'];
        return in_array($format, $validFormats) ? $format : 'json';
    }

    /**
     * Generate export filename
     * @param string $format
     * @return string
     */
    private function generateExportFilename($format)
    {
        return 'webguard_threats_' . date('Y-m-d_H-i-s') . '.' . $format;
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
     * Get empty feed response
     * @param int $sinceId
     * @return array
     */
    private function getEmptyFeedResponse($sinceId = 0)
    {
        return [
            'status' => 'ok',
            'recent_threats' => [],
            'last_id' => $sinceId,
            'has_more' => false,
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
            'patterns' => [],
            'last_updated' => time(),
            'period' => '24h',
            'detection_rate' => 0
        ];
    }

    /**
     * Get empty patterns response
     * @return array
     */
    private function getEmptyPatternsResponse()
    {
        return [
            'patterns' => [],
            'trending_attacks' => [],
            'attack_sequences' => [],
            'total_patterns' => 0
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
            'timeline' => ['labels' => [], 'threats' => []],
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
            'countries' => [],
            'total_countries' => 0,
            'top_countries' => []
        ];
    }

    /* ===== ADVANCED INTEGRATION METHODS ===== */

    /**
     * Enrich stats with pattern data from JSON files
     * @param array $stats
     * @param string $period
     * @return array
     */
    private function enrichStatsWithPatterns($stats, $period)
    {
        try {
            $attackPatterns = $this->loadJsonFile('/usr/local/etc/webguard/attack_patterns.json');
            $wafRules = $this->loadJsonFile('/usr/local/etc/webguard/waf_rules.json');
            $realThreats = $this->getRealThreatsForPeriod($period);
            
            // Combine pattern detection with real threats
            $enrichedPatterns = $this->combinePatternSources($attackPatterns, $wafRules, $realThreats);
            
            $stats['patterns'] = [
                'sql_injection_patterns' => $this->filterPatternsByType($enrichedPatterns, 'sql_injection'),
                'xss_patterns' => $this->filterPatternsByType($enrichedPatterns, 'xss'),
                'command_injection_patterns' => $this->filterPatternsByType($enrichedPatterns, 'command_injection'),
                'path_traversal_patterns' => $this->filterPatternsByType($enrichedPatterns, 'path_traversal'),
                'total_patterns_detected' => count($enrichedPatterns),
                'pattern_sources' => [
                    'attack_patterns_json' => isset($attackPatterns['patterns']) ? count($attackPatterns['patterns'], COUNT_RECURSIVE) - count($attackPatterns['patterns']) : 0,
                    'waf_rules_json' => isset($wafRules['rules']) ? count($wafRules['rules']) : 0,
                    'real_threats_matched' => count($realThreats)
                ]
            ];
            
            return $stats;
            
        } catch (\Exception $e) {
            // Return stats without pattern enhancement on error
            return $stats;
        }
    }

    /**
     * Load and parse JSON file safely
     * @param string $filePath
     * @return array
     */
    private function loadJsonFile($filePath)
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return [];
        }
        
        $content = file_get_contents($filePath);
        if ($content === false) {
            return [];
        }
        
        $data = json_decode($content, true);
        return (json_last_error() === JSON_ERROR_NONE && is_array($data)) ? $data : [];
    }

    /**
     * Get real threats for specified period
     * @param string $period
     * @return array
     */
    private function getRealThreatsForPeriod($period)
    {
        try {
            $backend = new Backend();
            $result = $this->executeBackendCommand($backend, ['get_threat_all', '1']);
            
            if (!$result['success'] || !isset($result['data']['threats'])) {
                return [];
            }
            
            $threats = $result['data']['threats'];
            $periodSeconds = $this->getPeriodSeconds($period);
            $cutoffTime = time() - $periodSeconds;
            
            return array_filter($threats, function($threat) use ($cutoffTime) {
                $threatTime = $this->extractThreatTimestamp($threat);
                return $threatTime >= $cutoffTime;
            });
            
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Combine pattern sources into unified format
     * @param array $attackPatterns
     * @param array $wafRules
     * @param array $realThreats
     * @return array
     */
    private function combinePatternSources($attackPatterns, $wafRules, $realThreats)
    {
        $combinedPatterns = [];
        $patternId = 1;
        
        // Process attack patterns from JSON
        if (isset($attackPatterns['patterns'])) {
            foreach ($attackPatterns['patterns'] as $category => $patterns) {
                foreach ($patterns as $pattern) {
                    $matchingThreats = $this->findMatchingThreats($pattern, $category, $realThreats);
                    $wafRule = $this->findCorrespondingWafRule($pattern, $category, $wafRules);
                    
                    $combinedPatterns[] = $this->createPatternEntry(
                        $patternId++,
                        $pattern,
                        $category,
                        $matchingThreats,
                        $wafRule,
                        'attack_patterns.json'
                    );
                }
            }
        }
        
        // Process WAF rules
        if (isset($wafRules['rules'])) {
            foreach ($wafRules['rules'] as $rule) {
                if (!isset($rule['pattern']) || empty($rule['pattern'])) continue;
                
                $category = $this->extractCategoryFromWafRule($rule);
                $matchingThreats = $this->findMatchingThreats($rule['pattern'], $category, $realThreats);
                
                $combinedPatterns[] = $this->createPatternEntry(
                    $patternId++,
                    $rule['pattern'],
                    $category,
                    $matchingThreats,
                    $rule,
                    'waf_rules.json'
                );
            }
        }
        
        // Sort by threat count (most active first)
        usort($combinedPatterns, function($a, $b) {
            return $b['count'] - $a['count'];
        });
        
        return $combinedPatterns;
    }

    /**
     * Create standardized pattern entry
     * @param int $id
     * @param string $pattern
     * @param string $category
     * @param array $matchingThreats
     * @param array|null $wafRule
     * @param string $source
     * @return array
     */
    private function createPatternEntry($id, $pattern, $category, $matchingThreats, $wafRule, $source)
    {
        return [
            'id' => $id,
            'pattern' => $pattern,
            'signature' => $pattern,
            'type' => $category,
            'category' => $this->normalizeCategoryName($category),
            'count' => count($matchingThreats),
            'occurrences' => count($matchingThreats),
            'severity' => $this->calculatePatternSeverity($matchingThreats, $wafRule),
            'score' => $this->calculatePatternScore($matchingThreats, $wafRule),
            'success_rate' => $this->calculateSuccessRate($matchingThreats),
            'first_seen' => $this->getFirstSeenTimestamp($matchingThreats),
            'last_seen' => $this->getLastSeenTimestamp($matchingThreats),
            'trend' => $this->calculatePatternTrend($matchingThreats),
            'status' => count($matchingThreats) > 0 ? 'active' : 'inactive',
            'blocked' => $this->countBlockedThreats($matchingThreats),
            'source_ips' => $this->extractUniqueSourceIPs($matchingThreats),
            'waf_rule_id' => $wafRule ? ($wafRule['id'] ?? null) : null,
            'action' => $wafRule ? ($wafRule['action'] ?? 'log') : 'log',
            'source' => $source
        ];
    }

    /**
     * Find threats matching a specific pattern
     * @param string $pattern
     * @param string $category
     * @param array $threats
     * @return array
     */
    private function findMatchingThreats($pattern, $category, $threats)
    {
        $matching = [];
        
        foreach ($threats as $threat) {
            if ($this->threatMatchesPattern($threat, $pattern, $category)) {
                $matching[] = $threat;
            }
        }
        
        return $matching;
    }

    /**
     * Check if threat matches pattern and category
     * @param array $threat
     * @param string $pattern
     * @param string $category
     * @return bool
     */
    private function threatMatchesPattern($threat, $pattern, $category)
    {
        $threatType = strtolower($threat['threat_type'] ?? '');
        $requestData = strtolower($threat['request_data'] ?? '');
        $signature = strtolower($threat['signature'] ?? '');
        
        // Category-based matching
        $categoryMatches = $this->checkCategoryMatch($threatType, $category);
        
        // Pattern-based matching (simplified regex handling)
        $patternMatches = $this->checkPatternMatch($requestData . ' ' . $signature, $pattern);
        
        return $categoryMatches || $patternMatches;
    }

    /**
     * Check category match
     * @param string $threatType
     * @param string $category
     * @return bool
     */
    private function checkCategoryMatch($threatType, $category)
    {
        $categoryMap = [
            'sql_injection' => ['sql', 'injection', 'sqli'],
            'xss' => ['xss', 'script', 'cross-site'],
            'path_traversal' => ['path', 'traversal', 'lfi', 'directory'],
            'command_injection' => ['command', 'rce', 'exec'],
            'rfi' => ['rfi', 'remote', 'include'],
            'lfi' => ['lfi', 'local', 'include']
        ];
        
        if (!isset($categoryMap[$category])) {
            return false;
        }
        
        foreach ($categoryMap[$category] as $keyword) {
            if (strpos($threatType, $keyword) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check pattern match (simplified)
     * @param string $content
     * @param string $pattern
     * @return bool
     */
    private function checkPatternMatch($content, $pattern)
    {
        // Simplify regex patterns for basic matching
        $simplifiedPattern = $this->simplifyRegexPattern($pattern);
        
        if (empty($simplifiedPattern)) {
            return false;
        }
        
        return strpos($content, strtolower($simplifiedPattern)) !== false;
    }

    /**
     * Simplify regex pattern for basic string matching
     * @param string $pattern
     * @return string
     */
    private function simplifyRegexPattern($pattern)
    {
        // Remove regex flags
        $simple = preg_replace('/\(\?\w+\)/', '', $pattern);
        
        // Remove complex regex elements
        $simple = preg_replace('/[(){}*+?|\[\]\\\\]/', '', $simple);
        
        // Extract main keywords
        $parts = explode('|', $simple);
        $cleanPart = trim($parts[0]);
        
        return strlen($cleanPart) > 2 ? $cleanPart : '';
    }

    /**
     * Calculate pattern severity based on threats and WAF rule
     * @param array $threats
     * @param array|null $wafRule
     * @return string
     */
    private function calculatePatternSeverity($threats, $wafRule)
    {
        if (empty($threats)) {
            return $wafRule ? ($wafRule['severity'] ?? 'low') : 'low';
        }
        
        $severityWeights = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $totalWeight = 0;
        $count = 0;
        
        foreach ($threats as $threat) {
            $severity = strtolower($threat['severity'] ?? 'medium');
            if (isset($severityWeights[$severity])) {
                $totalWeight += $severityWeights[$severity];
                $count++;
            }
        }
        
        if ($count === 0) {
            return $wafRule ? ($wafRule['severity'] ?? 'medium') : 'medium';
        }
        
        $avgWeight = $totalWeight / $count;
        
        // Apply WAF rule severity boost
        if ($wafRule && isset($wafRule['severity'])) {
            $ruleSeverity = $severityWeights[strtolower($wafRule['severity'])] ?? 2;
            $avgWeight = max($avgWeight, $ruleSeverity);
        }
        
        if ($avgWeight >= 3.5) return 'critical';
        if ($avgWeight >= 2.5) return 'high';
        if ($avgWeight >= 1.5) return 'medium';
        return 'low';
    }

    /**
     * Calculate pattern risk score
     * @param array $threats
     * @param array|null $wafRule
     * @return int
     */
    private function calculatePatternScore($threats, $wafRule)
    {
        $baseScore = 0;
        
        // Base score from WAF rule
        if ($wafRule && isset($wafRule['score'])) {
            $baseScore = max(0, min(100, (int)$wafRule['score']));
        }
        
        // Frequency bonus (0-40 points)
        $threatCount = count($threats);
        $frequencyBonus = min($threatCount * 3, 40);
        
        // Severity bonus (0-30 points)
        $severityBonus = 0;
        foreach ($threats as $threat) {
            switch (strtolower($threat['severity'] ?? 'medium')) {
                case 'critical': $severityBonus += 8; break;
                case 'high': $severityBonus += 6; break;
                case 'medium': $severityBonus += 3; break;
                case 'low': $severityBonus += 1; break;
            }
        }
        $severityBonus = min($severityBonus, 30);
        
        // Success rate penalty
        $successRate = $this->calculateSuccessRateNumeric($threats);
        $successPenalty = $successRate > 20 ? ($successRate * 0.5) : 0;
        
        $finalScore = $baseScore + $frequencyBonus + $severityBonus - $successPenalty;
        return max(0, min(100, (int)$finalScore));
    }

    /**
     * Calculate success rate as string percentage
     * @param array $threats
     * @return string
     */
    private function calculateSuccessRate($threats)
    {
        return number_format($this->calculateSuccessRateNumeric($threats), 1);
    }

    /**
     * Calculate success rate as numeric value
     * @param array $threats
     * @return float
     */
    private function calculateSuccessRateNumeric($threats)
    {
        if (empty($threats)) {
            return 0.0;
        }
        
        $successfulAttacks = 0;
        foreach ($threats as $threat) {
            $status = strtolower($threat['status'] ?? 'unknown');
            if ($status !== 'blocked' && $status !== 'denied') {
                $successfulAttacks++;
            }
        }
        
        return ($successfulAttacks / count($threats)) * 100;
    }

    /**
     * Extract timestamp from threat data
     * @param array $threat
     * @return int
     */
    private function extractThreatTimestamp($threat)
    {
        if (isset($threat['timestamp'])) {
            return is_numeric($threat['timestamp']) ? (int)$threat['timestamp'] : strtotime($threat['timestamp']);
        }
        
        if (isset($threat['first_seen_iso'])) {
            return strtotime($threat['first_seen_iso']);
        }
        
        if (isset($threat['last_seen_iso'])) {
            return strtotime($threat['last_seen_iso']);
        }
        
        if (isset($threat['created_at'])) {
            return is_numeric($threat['created_at']) ? (int)$threat['created_at'] : strtotime($threat['created_at']);
        }
        
        return time(); // Fallback to current time
    }

    /**
     * Get first seen timestamp for pattern
     * @param array $threats
     * @return string
     */
    private function getFirstSeenTimestamp($threats)
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
        
        return $earliest < PHP_INT_MAX ? date('Y-m-d H:i:s', $earliest) : 'Unknown';
    }

    /**
     * Get last seen timestamp for pattern
     * @param array $threats
     * @return string
     */
    private function getLastSeenTimestamp($threats)
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
        
        return $latest > 0 ? date('Y-m-d H:i:s', $latest) : 'Unknown';
    }

    /**
     * Calculate pattern trend
     * @param array $threats
     * @return string
     */
    private function calculatePatternTrend($threats)
    {
        if (count($threats) < 3) {
            return 'stable';
        }
        
        // Sort threats by timestamp
        usort($threats, function($a, $b) {
            return $this->extractThreatTimestamp($a) - $this->extractThreatTimestamp($b);
        });
        
        // Compare recent vs older activity
        $totalCount = count($threats);
        $recentCount = 0;
        $cutoffTime = time() - (24 * 3600); // Last 24 hours
        
        foreach ($threats as $threat) {
            if ($this->extractThreatTimestamp($threat) >= $cutoffTime) {
                $recentCount++;
            }
        }
        
        $recentPercentage = ($recentCount / $totalCount) * 100;
        
        if ($recentPercentage > 60) return 'up';
        if ($recentPercentage < 20) return 'down';
        return 'stable';
    }

    /**
     * Count blocked threats
     * @param array $threats
     * @return int
     */
    private function countBlockedThreats($threats)
    {
        $blocked = 0;
        foreach ($threats as $threat) {
            $status = strtolower($threat['status'] ?? 'unknown');
            if ($status === 'blocked' || $status === 'denied') {
                $blocked++;
            }
        }
        return $blocked;
    }

    /**
     * Extract unique source IPs with counts
     * @param array $threats
     * @return array
     */
    private function extractUniqueSourceIPs($threats)
    {
        $ips = [];
        foreach ($threats as $threat) {
            $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? null;
            if ($ip && $ip !== 'unknown' && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[$ip] = ($ips[$ip] ?? 0) + 1;
            }
        }
        
        // Sort by count descending and limit to top 10
        arsort($ips);
        return array_slice($ips, 0, 10, true);
    }

    /**
     * Find corresponding WAF rule for pattern
     * @param string $pattern
     * @param string $category
     * @param array $wafRules
     * @return array|null
     */
    private function findCorrespondingWafRule($pattern, $category, $wafRules)
    {
        if (!isset($wafRules['rules'])) {
            return null;
        }
        
        foreach ($wafRules['rules'] as $rule) {
            // Exact pattern match
            if (isset($rule['pattern']) && $rule['pattern'] === $pattern) {
                return $rule;
            }
            
            // Category match in tags
            if (isset($rule['tags']) && is_array($rule['tags'])) {
                foreach ($rule['tags'] as $tag) {
                    if (stripos($tag, $category) !== false) {
                        return $rule;
                    }
                }
            }
            
            // Category match in name or description
            $ruleName = strtolower($rule['name'] ?? '');
            $ruleDesc = strtolower($rule['description'] ?? '');
            
            if (stripos($ruleName, $category) !== false || stripos($ruleDesc, $category) !== false) {
                return $rule;
            }
        }
        
        return null;
    }

    /**
     * Extract category from WAF rule
     * @param array $rule
     * @return string
     */
    private function extractCategoryFromWafRule($rule)
    {
        // Check tags first
        if (isset($rule['tags']) && is_array($rule['tags'])) {
            foreach ($rule['tags'] as $tag) {
                $tag = strtolower($tag);
                if (strpos($tag, 'sql') !== false) return 'sql_injection';
                if (strpos($tag, 'xss') !== false) return 'xss';
                if (strpos($tag, 'lfi') !== false) return 'path_traversal';
                if (strpos($tag, 'rfi') !== false) return 'rfi';
                if (strpos($tag, 'rce') !== false || strpos($tag, 'command') !== false) return 'command_injection';
            }
        }
        
        // Check name and description
        $text = strtolower(($rule['name'] ?? '') . ' ' . ($rule['description'] ?? ''));
        
        if (strpos($text, 'sql') !== false || strpos($text, 'injection') !== false) return 'sql_injection';
        if (strpos($text, 'xss') !== false || strpos($text, 'script') !== false) return 'xss';
        if (strpos($text, 'traversal') !== false || strpos($text, 'lfi') !== false) return 'path_traversal';
        if (strpos($text, 'rfi') !== false) return 'rfi';
        if (strpos($text, 'command') !== false || strpos($text, 'rce') !== false) return 'command_injection';
        
        return 'unknown';
    }

    /**
     * Normalize category name for display
     * @param string $category
     * @return string
     */
    private function normalizeCategoryName($category)
    {
        $categoryMap = [
            'sql_injection' => 'SQL Injection',
            'xss' => 'Cross-Site Scripting (XSS)',
            'path_traversal' => 'Path Traversal',
            'command_injection' => 'Command Injection',
            'rfi' => 'Remote File Inclusion',
            'lfi' => 'Local File Inclusion',
            'rce' => 'Remote Code Execution',
            'unknown' => 'Unknown Attack Type'
        ];
        
        return $categoryMap[$category] ?? ucwords(str_replace('_', ' ', $category));
    }

    /**
     * Filter patterns by type
     * @param array $patterns
     * @param string $type
     * @return array
     */
    private function filterPatternsByType($patterns, $type)
    {
        return array_filter($patterns, function($pattern) use ($type) {
            return $pattern['type'] === $type;
        });
    }

    /**
     * Convert period to seconds
     * @param string $period
     * @return int
     */
    private function getPeriodSeconds($period)
    {
        switch ($period) {
            case '1h': return 3600;
            case '24h': return 24 * 3600;
            case '7d': return 7 * 24 * 3600;
            case '30d': return 30 * 24 * 3600;
            case '90d': return 90 * 24 * 3600;
            default: return 24 * 3600;
        }
    }

    /**
     * Generate statistics from database when backend is unavailable
     * @param string $period
     * @param bool $includePatterns
     * @return array
     */
    private function generateStatsFromDatabase($period, $includePatterns = true)
    {
        try {
            $realThreats = $this->getRealThreatsForPeriod($period);
            $stats = $this->calculateStatsFromThreats($realThreats, $period);
            
            if ($includePatterns) {
                $stats = $this->enrichStatsWithPatterns($stats, $period);
            }
            
            return $stats;
            
        } catch (\Exception $e) {
            return $this->getEmptyStatsResponse();
        }
    }

    /**
     * Calculate statistics from threat array
     * @param array $threats
     * @param string $period
     * @return array
     */
    private function calculateStatsFromThreats($threats, $period)
    {
        $stats = $this->getEmptyStatsResponse();
        $stats['period'] = $period;
        
        $periodSeconds = $this->getPeriodSeconds($period);
        $cutoffTime = time() - $periodSeconds;
        
        foreach ($threats as $threat) {
            $threatTime = $this->extractThreatTimestamp($threat);
            
            if ($threatTime >= $cutoffTime) {
                $stats['threats_24h']++;
                
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
                
                // Count blocked
                $status = strtolower($threat['status'] ?? 'unknown');
                if ($status === 'blocked' || $status === 'denied') {
                    $stats['blocked_today']++;
                }
            }
        }
        
        $stats['total_threats'] = count($threats);
        
        // Sort top source IPs
        if (!empty($stats['top_source_ips'])) {
            arsort($stats['top_source_ips']);
            $stats['top_source_ips'] = array_slice($stats['top_source_ips'], 0, 10, true);
        }
        
        return $stats;
    }

    /**
     * Calculate detection rate from stats
     * @param array $stats
     * @return float
     */
    private function calculateDetectionRate($stats)
    {
        $total = $stats['threats_24h'] ?? 0;
        $blocked = $stats['blocked_today'] ?? 0;
        
        if ($total === 0) {
            return 0.0;
        }
        
        return round(($blocked / $total) * 100, 1);
    }

    /**
     * Build patterns from integrated data sources
     * @param string $period
     * @param string $patternType
     * @param bool $includeInactive
     * @return array
     */
    private function buildPatternsFromIntegratedData($period, $patternType, $includeInactive)
    {
        try {
            $attackPatterns = $this->loadJsonFile('/usr/local/etc/webguard/attack_patterns.json');
            $wafRules = $this->loadJsonFile('/usr/local/etc/webguard/waf_rules.json');
            $realThreats = $this->getRealThreatsForPeriod($period);
            
            $patterns = $this->combinePatternSources($attackPatterns, $wafRules, $realThreats);
            
            // Filter by type if specified
            if ($patternType !== 'all') {
                $patterns = array_filter($patterns, function($pattern) use ($patternType) {
                    return $pattern['type'] === $patternType;
                });
            }
            
            // Filter inactive patterns if requested
            if (!$includeInactive) {
                $patterns = array_filter($patterns, function($pattern) {
                    return $pattern['status'] === 'active';
                });
            }
            
            // Generate additional analysis data
            $trendingAttacks = $this->extractTrendingAttacks($patterns);
            $attackSequences = $this->buildAttackSequences($realThreats);
            
            return [
                'patterns' => array_values($patterns),
                'trending_attacks' => $trendingAttacks,
                'attack_sequences' => $attackSequences,
                'total_patterns' => count($patterns),
                'active_patterns' => count(array_filter($patterns, function($p) { return $p['status'] === 'active'; })),
                'pattern_sources' => [
                    'json_files' => 2,
                    'real_threats' => count($realThreats)
                ]
            ];
            
        } catch (\Exception $e) {
            return $this->getEmptyPatternsResponse();
        }
    }

    /**
     * Extract trending attacks from patterns
     * @param array $patterns
     * @return array
     */
    private function extractTrendingAttacks($patterns)
    {
        $trending = [];
        
        foreach ($patterns as $pattern) {
            if ($pattern['trend'] === 'up' && $pattern['count'] > 0) {
                $trending[] = [
                    'pattern' => $pattern['pattern'],
                    'type' => $pattern['type'],
                    'count' => $pattern['count'],
                    'growth_rate' => $this->calculateGrowthRate($pattern),
                    'severity' => $pattern['severity'],
                    'score' => $pattern['score']
                ];
            }
        }
        
        // Sort by growth rate
        usort($trending, function($a, $b) {
            return $b['growth_rate'] - $a['growth_rate'];
        });
        
        return array_slice($trending, 0, 10);
    }

    /**
     * Calculate growth rate for pattern
     * @param array $pattern
     * @return float
     */
    private function calculateGrowthRate($pattern)
    {
        $baseRate = min($pattern['count'] * 5, 100);
        
        // Boost for high severity
        if ($pattern['severity'] === 'critical') {
            $baseRate *= 1.5;
        } elseif ($pattern['severity'] === 'high') {
            $baseRate *= 1.3;
        }
        
        // Boost for high success rate
        $successRate = (float)$pattern['success_rate'];
        if ($successRate > 50) {
            $baseRate *= 1.2;
        }
        
        return min($baseRate, 100);
    }

    /**
     * Build attack sequences from real threats
     * @param array $threats
     * @return array
     */
    private function buildAttackSequences($threats)
    {
        $sequences = [];
        $ipGroups = [];
        
        // Group threats by IP address
        foreach ($threats as $threat) {
            $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? null;
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                if (!isset($ipGroups[$ip])) {
                    $ipGroups[$ip] = [];
                }
                $ipGroups[$ip][] = $threat;
            }
        }
        
        // Find sequences (IPs with multiple attacks in time window)
        foreach ($ipGroups as $ip => $ipThreats) {
            if (count($ipThreats) >= 2) {
                // Sort by timestamp
                usort($ipThreats, function($a, $b) {
                    return $this->extractThreatTimestamp($a) - $this->extractThreatTimestamp($b);
                });
                
                $sequence = [
                    'source_ip' => $ip,
                    'sequence' => [],
                    'count' => count($ipThreats),
                    'risk_level' => $this->calculateSequenceRiskLevel(count($ipThreats)),
                    'duration' => $this->calculateSequenceDuration($ipThreats),
                    'first_attack' => $this->extractThreatTimestamp($ipThreats[0]),
                    'last_attack' => $this->extractThreatTimestamp(end($ipThreats)),
                    'attack_types' => $this->extractAttackTypes($ipThreats),
                    'success_rate' => $this->calculateSuccessRateNumeric($ipThreats)
                ];
                
                foreach ($ipThreats as $threat) {
                    $sequence['sequence'][] = $threat['threat_type'] ?? 'Unknown Attack';
                }
                
                $sequences[] = $sequence;
            }
        }
        
        // Sort by attack count descending
        usort($sequences, function($a, $b) {
            return $b['count'] - $a['count'];
        });
        
        return array_slice($sequences, 0, 20);
    }

    /**
     * Calculate sequence risk level
     * @param int $attackCount
     * @return string
     */
    private function calculateSequenceRiskLevel($attackCount)
    {
        if ($attackCount >= 10) return 'critical';
        if ($attackCount >= 5) return 'high';
        if ($attackCount >= 3) return 'medium';
        return 'low';
    }

    /**
     * Calculate sequence duration
     * @param array $threats
     * @return string
     */
    private function calculateSequenceDuration($threats)
    {
        if (count($threats) < 2) {
            return '0 minutes';
        }
        
        $first = $this->extractThreatTimestamp($threats[0]);
        $last = $this->extractThreatTimestamp(end($threats));
        $duration = $last - $first;
        
        if ($duration < 60) {
            return $duration . ' seconds';
        } elseif ($duration < 3600) {
            return round($duration / 60) . ' minutes';
        } elseif ($duration < 86400) {
            return round($duration / 3600, 1) . ' hours';
        } else {
            return round($duration / 86400, 1) . ' days';
        }
    }

    /**
     * Extract unique attack types from threats
     * @param array $threats
     * @return array
     */
    private function extractAttackTypes($threats)
    {
        $types = [];
        foreach ($threats as $threat) {
            $type = $threat['threat_type'] ?? 'Unknown';
            $types[$type] = ($types[$type] ?? 0) + 1;
        }
        return $types;
    }

    /**
     * Process pattern data from backend response
     * @param array $data
     * @param string $period
     * @param bool $includeInactive
     * @return array
     */
    private function processPatternData($data, $period, $includeInactive)
    {
        if (!$includeInactive && isset($data['patterns'])) {
            $data['patterns'] = array_filter($data['patterns'], function($pattern) {
                return ($pattern['status'] ?? 'active') === 'active';
            });
        }
        
        // Add metadata
        $data['period'] = $period;
        $data['total_patterns'] = count($data['patterns'] ?? []);
        $data['last_updated'] = time();
        
        return $data;
    }

    /**
     * Find related patterns from all sources
     * @param string $patternId
     * @param string $category
     * @param int $limit
     * @return array
     */
    private function findRelatedPatternsFromSources($patternId, $category, $limit)
    {
        $relatedPatterns = [];
        
        try {
            // Load JSON sources
            $attackPatterns = $this->loadJsonFile('/usr/local/etc/webguard/attack_patterns.json');
            $wafRules = $this->loadJsonFile('/usr/local/etc/webguard/waf_rules.json');
            
            // Find patterns in same category from attack_patterns.json
            if (isset($attackPatterns['patterns'][$category])) {
                foreach ($attackPatterns['patterns'][$category] as $pattern) {
                    $relatedPatterns[] = [
                        'pattern' => $pattern,
                        'type' => $category,
                        'score' => rand(60, 95),
                        'count' => rand(1, 20),
                        'source' => 'attack_patterns.json',
                        'similarity' => $this->calculatePatternSimilarity($patternId, $pattern)
                    ];
                }
            }
            
            // Find related WAF rules
            if (isset($wafRules['rules'])) {
                foreach ($wafRules['rules'] as $rule) {
                    if ($this->isWafRuleRelated($rule, $category)) {
                        $relatedPatterns[] = [
                            'pattern' => $rule['pattern'] ?? $rule['name'] ?? 'Unknown Rule',
                            'type' => $category,
                            'score' => $rule['score'] ?? rand(50, 90),
                            'count' => rand(1, 15),
                            'source' => 'waf_rules.json',
                            'rule_id' => $rule['id'] ?? null,
                            'severity' => $rule['severity'] ?? 'medium',
                            'similarity' => $this->calculatePatternSimilarity($patternId, $rule['pattern'] ?? '')
                        ];
                    }
                }
            }
            
            // Sort by similarity and score
            usort($relatedPatterns, function($a, $b) {
                $scoreA = $a['similarity'] * 0.6 + $a['score'] * 0.4;
                $scoreB = $b['similarity'] * 0.6 + $b['score'] * 0.4;
                return $scoreB <=> $scoreA;
            });
            
            return array_slice($relatedPatterns, 0, $limit);
            
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Check if WAF rule is related to category
     * @param array $rule
     * @param string $category
     * @return bool
     */
    private function isWafRuleRelated($rule, $category)
    {
        // Check tags
        if (isset($rule['tags']) && is_array($rule['tags'])) {
            foreach ($rule['tags'] as $tag) {
                if (stripos($tag, $category) !== false) {
                    return true;
                }
            }
        }
        
        // Check name and description
        $text = strtolower(($rule['name'] ?? '') . ' ' . ($rule['description'] ?? ''));
        return stripos($text, $category) !== false;
    }

    /**
     * Calculate pattern similarity (simplified)
     * @param string $pattern1
     * @param string $pattern2
     * @return float
     */
    private function calculatePatternSimilarity($pattern1, $pattern2)
    {
        if (empty($pattern1) || empty($pattern2)) {
            return 0.0;
        }
        
        // Simple similarity based on common substrings
        $pattern1 = strtolower($pattern1);
        $pattern2 = strtolower($pattern2);
        
        if ($pattern1 === $pattern2) {
            return 100.0;
        }
        
        $commonChars = 0;
        $totalChars = max(strlen($pattern1), strlen($pattern2));
        
        for ($i = 0; $i < min(strlen($pattern1), strlen($pattern2)); $i++) {
            if (isset($pattern1[$i]) && isset($pattern2[$i]) && $pattern1[$i] === $pattern2[$i]) {
                $commonChars++;
            }
        }
        
        return ($commonChars / $totalChars) * 100;
    }

    /**
     * Generate timeline from database
     * @param string $period
     * @param string $granularity
     * @return array
     */
    private function generateTimelineFromDatabase($period, $granularity)
    {
        try {
            $threats = $this->getRealThreatsForPeriod($period);
            $timeline = $this->buildTimelineFromThreats($threats, $period, $granularity);
            
            return [
                'status' => 'ok',
                'timeline' => $timeline,
                'period' => $period,
                'granularity' => $granularity
            ];
            
        } catch (\Exception $e) {
            return $this->getEmptyTimelineResponse();
        }
    }

    /**
     * Build timeline data from threat array
     * @param array $threats
     * @param string $period
     * @param string $granularity
     * @return array
     */
    private function buildTimelineFromThreats($threats, $period, $granularity)
    {
        $intervals = $this->getTimelineIntervals($period, $granularity);
        $labels = [];
        $threatCounts = [];
        
        $periodSeconds = $this->getPeriodSeconds($period);
        $startTime = time() - $periodSeconds;
        $stepSize = $periodSeconds / $intervals['count'];
        
        // Initialize timeline
        for ($i = 0; $i < $intervals['count']; $i++) {
            $currentTime = $startTime + ($i * $stepSize);
            $labels[] = date($intervals['format'], $currentTime);
            $threatCounts[] = 0;
        }
        
        // Count threats in each interval
        foreach ($threats as $threat) {
            $threatTime = $this->extractThreatTimestamp($threat);
            
            if ($threatTime >= $startTime) {
                $intervalIndex = (int)(($threatTime - $startTime) / $stepSize);
                $intervalIndex = max(0, min($intervalIndex, $intervals['count'] - 1));
                $threatCounts[$intervalIndex]++;
            }
        }
        
        return [
            'labels' => $labels,
            'threats' => $threatCounts,
            'total_threats' => array_sum($threatCounts)
        ];
    }

    /**
     * Get timeline intervals configuration
     * @param string $period
     * @param string $granularity
     * @return array
     */
    private function getTimelineIntervals($period, $granularity)
    {
        if ($granularity === 'auto') {
            switch ($period) {
                case '1h':
                    return ['count' => 6, 'format' => 'H:i'];
                case '24h':
                    return ['count' => 12, 'format' => 'H:i'];
                case '7d':
                    return ['count' => 7, 'format' => 'M j'];
                case '30d':
                    return ['count' => 15, 'format' => 'M j'];
                case '90d':
                    return ['count' => 18, 'format' => 'M j'];
                default:
                    return ['count' => 12, 'format' => 'H:i'];
            }
        }
        
        // Custom granularity handling
        switch ($granularity) {
            case 'hourly':
                return ['count' => min(24, $this->getPeriodSeconds($period) / 3600), 'format' => 'H:i'];
            case 'daily':
                return ['count' => min(30, $this->getPeriodSeconds($period) / 86400), 'format' => 'M j'];
            case 'weekly':
                return ['count' => min(12, $this->getPeriodSeconds($period) / 604800), 'format' => 'M j'];
            default:
                return ['count' => 12, 'format' => 'H:i'];
        }
    }

    /**
     * Enrich threat data with additional information
     * @param array $threat
     * @return array
     */
    private function enrichThreatData($threat)
    {
        // Add geolocation info if IP is available
        if (isset($threat['ip_address']) || isset($threat['source_ip'])) {
            $ip = $threat['ip_address'] ?? $threat['source_ip'];
            $threat['geolocation'] = $this->getGeolocationForIP($ip);
        }
        
        // Add pattern analysis
        $threat['pattern_analysis'] = $this->analyzeRequestPattern($threat);
        
        // Add risk assessment
        $threat['risk_assessment'] = $this->assessThreatRisk($threat);
        
        // Add mitigation history
        $threat['mitigation_history'] = $this->getMitigationHistory($threat);
        
        return $threat;
    }

    /**
     * Get geolocation for IP (placeholder)
     * @param string $ip
     * @return array
     */
    private function getGeolocationForIP($ip)
    {
        // In a real implementation, this would query a geolocation service
        return [
            'country' => 'Unknown',
            'region' => 'Unknown',
            'city' => 'Unknown',
            'is_tor' => false,
            'is_proxy' => false,
            'threat_level' => 'unknown'
        ];
    }

    /**
     * Analyze request pattern
     * @param array $threat
     * @return array
     */
    private function analyzeRequestPattern($threat)
    {
        $requestData = $threat['request_data'] ?? '';
        $signature = $threat['signature'] ?? '';
        
        return [
            'pattern_type' => $this->identifyPatternType($requestData . ' ' . $signature),
            'complexity' => $this->calculatePatternComplexity($requestData),
            'evasion_techniques' => $this->detectEvasionTechniques($requestData),
            'payload_analysis' => $this->analyzePayload($requestData)
        ];
    }

    /**
     * Identify pattern type from request data
     * @param string $data
     * @return string
     */
    private function identifyPatternType($data)
    {
        $data = strtolower($data);
        
        if (preg_match('/(union|select|insert|update|delete|drop)/i', $data)) {
            return 'sql_injection';
        }
        
        if (preg_match('/(<script|javascript:|alert\(|prompt\()/i', $data)) {
            return 'xss';
        }
        
        if (preg_match('/(\.\.\/|\.\.\\\\|\.\.[\/\\\\])/i', $data)) {
            return 'path_traversal';
        }
        
        if (preg_match('/(;|&&|\|\||`|\$\()/i', $data)) {
            return 'command_injection';
        }
        
        return 'unknown';
    }

    /**
     * Calculate pattern complexity score
     * @param string $data
     * @return int
     */
    private function calculatePatternComplexity($data)
    {
        $complexity = 0;
        
        // Length factor
        $complexity += min(strlen($data) / 10, 20);
        
        // Special characters
        $complexity += substr_count($data, '%') * 2;
        $complexity += substr_count($data, '&') * 1.5;
        $complexity += substr_count($data, '<') * 2;
        
        // Encoding attempts
        if (preg_match('/(%[0-9a-f]{2})/i', $data)) {
            $complexity += 10;
        }
        
        return min((int)$complexity, 100);
    }

    /**
     * Detect evasion techniques
     * @param string $data
     * @return array
     */
    private function detectEvasionTechniques($data)
    {
        $techniques = [];
        
        if (preg_match('/(%[0-9a-f]{2})/i', $data)) {
            $techniques[] = 'URL Encoding';
        }
        
        if (preg_match('/(&[a-z]+;)/i', $data)) {
            $techniques[] = 'HTML Entity Encoding';
        }
        
        if (preg_match('/\/\*.*?\*\//i', $data)) {
            $techniques[] = 'SQL Comments';
        }
        
        if (preg_match('/\s+/i', $data) && strlen(trim($data)) < strlen($data) * 0.7) {
            $techniques[] = 'Whitespace Evasion';
        }
        
        return $techniques;
    }

    /**
     * Analyze payload content
     * @param string $data
     * @return array
     */
    private function analyzePayload($data)
    {
        return [
            'size' => strlen($data),
            'has_special_chars' => preg_match('/[<>&"\']/', $data) ? true : false,
            'has_sql_keywords' => preg_match('/(select|union|insert|update|delete|drop|exec)/i', $data) ? true : false,
            'has_script_tags' => preg_match('/<script/i', $data) ? true : false,
            'has_path_traversal' => preg_match('/\.\.[\\/\\\\]/', $data) ? true : false,
            'entropy' => $this->calculateStringEntropy($data)
        ];
    }

    /**
     * Calculate string entropy
     * @param string $string
     * @return float
     */
    private function calculateStringEntropy($string)
    {
        if (strlen($string) === 0) return 0.0;
        
        $frequencies = array_count_values(str_split($string));
        $entropy = 0.0;
        $length = strlen($string);
        
        foreach ($frequencies as $frequency) {
            $probability = $frequency / $length;
            $entropy -= $probability * log($probability, 2);
        }
        
        return round($entropy, 2);
    }

    /**
     * Assess threat risk level
     * @param array $threat
     * @return array
     */
    private function assessThreatRisk($threat)
    {
        $riskScore = 0;
        $factors = [];
        
        // Severity factor
        switch (strtolower($threat['severity'] ?? 'medium')) {
            case 'critical': $riskScore += 40; $factors[] = 'Critical severity'; break;
            case 'high': $riskScore += 30; $factors[] = 'High severity'; break;
            case 'medium': $riskScore += 20; $factors[] = 'Medium severity'; break;
            case 'low': $riskScore += 10; $factors[] = 'Low severity'; break;
        }
        
        // Frequency factor (simulated)
        $riskScore += min(20, ($threat['count'] ?? 1) * 2);
        if (($threat['count'] ?? 1) > 5) {
            $factors[] = 'High frequency attacks';
        }
        
        // Success rate factor
        $successRate = (float)($threat['success_rate'] ?? 0);
        if ($successRate > 50) {
            $riskScore += 20;
            $factors[] = 'High success rate';
        }
        
        // Pattern complexity
        $complexity = $threat['pattern_analysis']['complexity'] ?? 0;
        if ($complexity > 50) {
            $riskScore += 10;
            $factors[] = 'Complex attack pattern';
        }
        
        $riskLevel = 'low';
        if ($riskScore >= 80) $riskLevel = 'critical';
        elseif ($riskScore >= 60) $riskLevel = 'high';
        elseif ($riskScore >= 40) $riskLevel = 'medium';
        
        return [
            'score' => min($riskScore, 100),
            'level' => $riskLevel,
            'factors' => $factors,
            'recommendation' => $this->getRiskRecommendation($riskLevel, $riskScore)
        ];
    }

    /**
     * Get risk-based recommendation
     * @param string $level
     * @param int $score
     * @return string
     */
    private function getRiskRecommendation($level, $score)
    {
        switch ($level) {
            case 'critical':
                return 'Immediate blocking required. Investigate source and implement permanent mitigation.';
            case 'high':
                return 'Consider immediate blocking. Monitor closely and prepare mitigation strategies.';
            case 'medium':
                return 'Increase monitoring frequency. Consider rate limiting or challenge responses.';
            case 'low':
            default:
                return 'Continue normal monitoring. Consider logging for pattern analysis.';
        }
    }

    /**
     * Get mitigation history for threat
     * @param array $threat
     * @return array
     */
    private function getMitigationHistory($threat)
    {
        // In a real implementation, this would query mitigation history from database
        return [
            'previous_blocks' => 0,
            'false_positive_reports' => 0,
            'rule_adjustments' => 0,
            'last_mitigation' => null,
            'mitigation_effectiveness' => 'unknown'
        ];
    }

    /**
     * Find related patterns for threat analysis
     * @param array $threat
     * @return array
     */
    private function findRelatedPatterns($threat)
    {
        $threatType = $threat['threat_type'] ?? 'unknown';
        $category = $this->mapThreatTypeToCategory($threatType);
        
        return $this->findRelatedPatternsFromSources('', $category, 5);
    }

    /**
     * Map threat type to pattern category
     * @param string $threatType
     * @return string
     */
    private function mapThreatTypeToCategory($threatType)
    {
        $threatType = strtolower($threatType);
        
        if (strpos($threatType, 'sql') !== false) return 'sql_injection';
        if (strpos($threatType, 'xss') !== false) return 'xss';
        if (strpos($threatType, 'traversal') !== false) return 'path_traversal';
        if (strpos($threatType, 'command') !== false) return 'command_injection';
        if (strpos($threatType, 'rfi') !== false) return 'rfi';
        
        return 'unknown';
    }

    /**
     * Get mitigation suggestions for threat
     * @param array $threat
     * @return array
     */
    private function getMitigationSuggestions($threat)
    {
        $suggestions = [];
        $threatType = strtolower($threat['threat_type'] ?? '');
        
        if (strpos($threatType, 'sql') !== false) {
            $suggestions[] = [
                'type' => 'immediate',
                'action' => 'Enable SQL injection protection rules',
                'description' => 'Activate parameterized query validation and SQL keyword filtering'
            ];
            $suggestions[] = [
                'type' => 'preventive',
                'action' => 'Implement input validation',
                'description' => 'Add server-side validation for all user inputs'
            ];
        }
        
        if (strpos($threatType, 'xss') !== false) {
            $suggestions[] = [
                'type' => 'immediate',
                'action' => 'Enable XSS protection headers',
                'description' => 'Implement Content Security Policy and X-XSS-Protection headers'
            ];
            $suggestions[] = [
                'type' => 'preventive',
                'action' => 'Output encoding',
                'description' => 'Ensure all user output is properly encoded'
            ];
        }
        
        // Add IP-based suggestions
        $ip = $threat['ip_address'] ?? $threat['source_ip'] ?? null;
        if ($ip) {
            $suggestions[] = [
                'type' => 'immediate',
                'action' => 'Consider IP blocking',
                'description' => "Block or rate-limit IP address: {$ip}"
            ];
        }
        
        return $suggestions;
    }
}