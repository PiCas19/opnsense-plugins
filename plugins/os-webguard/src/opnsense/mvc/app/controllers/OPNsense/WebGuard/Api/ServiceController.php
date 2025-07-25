<?php
/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * /api/webguard/service/<action>
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass    = '\\OPNsense\\WebGuard\\WebGuard';
    protected static $internalServiceTemplate = 'OPNsense/WebGuard';
    protected static $internalServiceEnabled  = 'enabled';
    protected static $internalServiceName     = 'webguard';

    /* ===== SERVICE MANAGEMENT ===== */

    public function startAction()   
    { 
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        return $this->svcCmd('start'); 
    }
    
    public function stopAction()    
    { 
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        return $this->svcCmd('stop'); 
    }
    
    public function restartAction() 
    { 
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        return $this->svcCmd('restart'); 
    }

    public function statusAction()
    {
        $backend = new Backend();
        $out = trim($backend->configdRun('webguard status'));
        
        $isRunning = (strpos($out, 'is running') !== false) || 
                     (strpos($out, 'webguard is running') !== false) ||
                     (strpos($out, 'active') !== false);
        
        return [
            'status'   => 'ok',
            'running'  => $isRunning,
            'response' => $out
        ];
    }

    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        
        $backend = new Backend();
        $result = $backend->configdRun('webguard reconfigure');
        
        return [
            'status' => 'ok',
            'message' => 'Configuration reloaded',
            'response' => $result
        ];
    }

    /* ===== STATISTICS ===== */

    public function getStatsAction()
    {
        $backend = new Backend();
        
        // USA configdpRun per i comandi applicativi
        $statsOut = trim($backend->configdpRun('webguard', ['get_stats', '']));
        
        if ($statsOut && $statsOut !== '') {
            $stats = json_decode($statsOut, true);
            if (is_array($stats)) {
                return ['status' => 'ok', 'data' => $stats];
            }
        }
        
        // Fallback: get counts manually
        $blockedOut = trim($backend->configdpRun('webguard', ['get_blocked_ips', '1']));
        $whitelistOut = trim($backend->configdpRun('webguard', ['get_whitelist', '1', '100']));
        
        $blockedCount = 0;
        $whitelistCount = 0;
        $activeBlocks = 0;
        
        if ($blockedOut) {
            $blockedData = json_decode($blockedOut, true);
            if (isset($blockedData['total'])) {
                $blockedCount = (int)$blockedData['total'];
            }
            if (isset($blockedData['blocked_ips']) && is_array($blockedData['blocked_ips'])) {
                $activeBlocks = count(array_filter($blockedData['blocked_ips'], function($item) {
                    return !($item['expired'] ?? false);
                }));
            }
        }
        
        if ($whitelistOut) {
            $whitelistData = json_decode($whitelistOut, true);
            if (isset($whitelistData['total'])) {
                $whitelistCount = (int)$whitelistData['total'];
            }
        }
        
        return [
            'status' => 'ok',
            'data' => [
                'blocked_count' => $blockedCount,
                'whitelist_count' => $whitelistCount,
                'active_blocks' => $activeBlocks,
                'temp_blocks' => $activeBlocks
            ]
        ];
    }

    /* ===== BLOCKED IPS MANAGEMENT ===== */

    public function listBlockedAction()
    {
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_blocked_ips', (string)$page]));

        if ($out && $out !== '') {
            $data = json_decode($out, true);
            if (is_array($data)) {
                // Clean up data for display
                if (!empty($data['blocked_ips'])) {
                    foreach ($data['blocked_ips'] as &$row) {
                        $row['reason'] = $this->viewSafe($row['reason'] ?? 'Unknown');
                        $row['block_type'] = $this->viewSafe($row['block_type'] ?? 'manual');
                        
                        // Ensure proper date formatting
                        if (isset($row['blocked_since']) && !isset($row['blocked_since_iso'])) {
                            $row['blocked_since_iso'] = date('c', $row['blocked_since']);
                        }
                        if (isset($row['expires_at']) && $row['expires_at'] > 0 && !isset($row['expires_at_iso'])) {
                            $row['expires_at_iso'] = date('c', $row['expires_at']);
                        }
                    }
                }
                return ['status' => 'ok', 'data' => $data];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve blocked IPs', 'data' => []];
    }

    public function blockIPAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        $duration = (int)$this->request->getPost('duration', 'int', 3600);
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'Manual_block'));
        $blockType = $this->argSafe($this->request->getPost('block_type', 'string', 'manual'));

        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', [
            'block_ip', 
            $ip, 
            (string)$duration, 
            $reason, 
            $blockType
        ]));

        // Controllo più flessibile del successo
        if (strpos($out, 'OK:') === 0 || 
            strpos($out, 'Success') !== false || 
            strpos($out, 'blocked') !== false ||
            strpos($out, 'added') !== false ||
            empty($out) || // Alcuni script non restituiscono output se tutto va bene
            strpos($out, 'ERROR:') === false) {
            return ['status' => 'ok', 'message' => 'IP blocked successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function unblockIPAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        
        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['unblock_ip', $ip]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'IP unblocked successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function bulkBlockAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ipList = $this->request->getPost('ip_list', 'string', '');
        $duration = (int)$this->request->getPost('duration', 'int', 3600);
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'Bulk_block'));
        $blockType = $this->argSafe($this->request->getPost('block_type', 'string', 'manual'));

        if (empty($ipList)) {
            return ['status' => 'error', 'message' => 'IP list is required'];
        }

        $ips = array_filter(array_map('trim', preg_split('/[\r\n,;]+/', $ipList)));
        $valid = array_values(array_filter($ips, [$this, 'validateIP']));
        $invalid = array_values(array_diff($ips, $valid));

        if (empty($valid)) {
            return ['status' => 'error', 'message' => 'No valid IP addresses found'];
        }

        $ipListFormatted = implode("\n", $valid);

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', [
            'bulk_block_ips',
            $ipListFormatted, 
            (string)$duration, 
            $reason, 
            $blockType
        ]));

        // Controllo più flessibile del successo
        if (strpos($out, 'OK:') === 0 || 
            strpos($out, 'Success') !== false || 
            strpos($out, 'blocked') !== false ||
            strpos($out, 'added') !== false ||
            empty($out) || // Alcuni script non restituiscono output se tutto va bene
            strpos($out, 'ERROR:') === false) {
            return [
                'status' => 'ok', 
                'message' => count($valid) . ' IPs blocked successfully',
                'blocked_count' => count($valid),
                'invalid_ips' => $invalid
            ];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    /* ===== WHITELIST MANAGEMENT ===== */

    public function listWhitelistAction()
    {
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        $limit = max(1, min(1000, (int)$this->request->getQuery('limit', 'int', 100)));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_whitelist', (string)$page, (string)$limit]));

        if ($out && $out !== '') {
            $data = json_decode($out, true);
            if (is_array($data)) {
                // Clean up data for display
                if (!empty($data['whitelist'])) {
                    foreach ($data['whitelist'] as &$row) {
                        $row['description'] = $this->viewSafe($row['description'] ?? 'Manual entry');
                        
                        // Ensure proper date formatting
                        if (isset($row['added_at']) && !isset($row['added_at_iso'])) {
                            $row['added_at_iso'] = date('c', $row['added_at']);
                        }
                    }
                }
                return ['status' => 'ok', 'data' => $data];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve whitelist', 'data' => []];
    }

    public function addWhitelistAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        $description = $this->argSafe($this->request->getPost('description', 'string', 'Manual_whitelist'));
        $permanent = $this->request->getPost('permanent', 'string', '1');

        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['add_to_whitelist', $ip, $description, $permanent]));

        // Controllo più flessibile del successo
        if (strpos($out, 'OK:') === 0 || 
            strpos($out, 'Success') !== false || 
            strpos($out, 'added') !== false ||
            strpos($out, 'whitelist') !== false ||
            empty($out) || // Alcuni script non restituiscono output se tutto va bene
            strpos($out, 'ERROR:') === false) {
            return ['status' => 'ok', 'message' => 'IP whitelisted successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function removeWhitelistAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        
        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['remove_from_whitelist', $ip]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'IP removed from whitelist successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function checkWhitelistAction()
    {
        $ip = trim($this->request->getQuery('ip', 'string', ''));
        
        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['check_whitelist', $ip]));

        return [
            'status' => 'ok',
            'whitelisted' => (strpos($out, 'true') !== false || strpos($out, 'YES') !== false),
            'response' => $out
        ];
    }

    /* ===== THREATS MANAGEMENT ===== */

    public function getThreatsAction()
    {
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threats', (string)$page]));
        
        if ($out && $out !== '') {
            $threats = json_decode($out, true);
            if (is_array($threats)) {
                return ['status' => 'ok', 'data' => $threats];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve threats', 'data' => []];
    }

    public function getThreatDetailAction()
    {
        $threatId = trim($this->request->getQuery('id', 'string', ''));
        
        if (empty($threatId)) {
            return ['status' => 'error', 'message' => 'Threat ID required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_detail', $threatId]));
        
        if ($out && $out !== '') {
            $detail = json_decode($out, true);
            if (is_array($detail)) {
                return ['status' => 'ok', 'data' => $detail];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve threat detail', 'data' => []];
    }

    public function getThreatStatsAction()
    {
        $period = trim($this->request->getQuery('period', 'string', '24h'));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_stats', $period]));
        
        if ($out && $out !== '') {
            $stats = json_decode($out, true);
            if (is_array($stats)) {
                return ['status' => 'ok', 'data' => $stats];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve threat stats', 'data' => []];
    }

    /* ===== TESTING AND VALIDATION ===== */

    public function testRulesAction()
    {
        $ruleSet = trim($this->request->getPost('ruleset', 'string', 'default'));
        $testData = trim($this->request->getPost('test_data', 'string', ''));

        if (empty($testData)) {
            return ['status' => 'error', 'message' => 'Test data required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['test_rules', $ruleSet, $testData]));
        
        if ($out && $out !== '') {
            $results = json_decode($out, true);
            if (is_array($results)) {
                return ['status' => 'ok', 'data' => $results];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to test rules', 'data' => []];
    }

    /* ===== UTILITY METHODS ===== */

    public function getServiceInfoAction()
    {
        $backend = new Backend();
        
        $status = trim($backend->configdRun('webguard status'));
        $isRunning = (strpos($status, 'is running') !== false) || 
                     (strpos($status, 'webguard is running') !== false) ||
                     (strpos($status, 'active') !== false);

        // Get basic stats
        $statsOut = trim($backend->configdpRun('webguard', ['get_stats', '']));
        $stats = [];
        
        if ($statsOut && $statsOut !== '') {
            $decoded = json_decode($statsOut, true);
            if (is_array($decoded)) {
                $stats = $decoded;
            }
        }

        return [
            'status' => 'ok',
            'data' => [
                'service_running' => $isRunning,
                'service_status' => $status,
                'stats' => $stats,
                'version' => 'WebGuard 1.0.0',
                'last_updated' => date('Y-m-d H:i:s')
            ]
        ];
    }

    public function bulkOperationAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $operation = trim($this->request->getPost('operation', 'string', ''));
        $targets = $this->request->getPost('targets', 'array', []);

        if (empty($operation) || empty($targets)) {
            return ['status' => 'error', 'message' => 'Operation and targets required'];
        }

        $results = [];
        $successCount = 0;
        $errorCount = 0;

        foreach ($targets as $target) {
            $ip = trim($target['ip'] ?? '');
            if (!$this->validateIP($ip)) {
                $results[] = ['ip' => $ip, 'status' => 'error', 'message' => 'Invalid IP'];
                $errorCount++;
                continue;
            }

            $backend = new Backend();
            $success = false;

            switch ($operation) {
                case 'unblock':
                    $out = trim($backend->configdpRun('webguard', ['unblock_ip', $ip]));
                    $success = (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false);
                    break;

                case 'whitelist':
                    $description = $this->argSafe($target['description'] ?? 'Bulk_whitelist');
                    $permanent = $target['permanent'] ?? '1';
                    $out = trim($backend->configdpRun('webguard', ['add_to_whitelist', $ip, $description, $permanent]));
                    $success = (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false);
                    break;

                case 'remove_whitelist':
                    $out = trim($backend->configdpRun('webguard', ['remove_from_whitelist', $ip]));
                    $success = (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false);
                    break;

                default:
                    $results[] = ['ip' => $ip, 'status' => 'error', 'message' => 'Unknown operation'];
                    $errorCount++;
                    continue 2;
            }

            if ($success) {
                $results[] = ['ip' => $ip, 'status' => 'ok', 'message' => ucfirst($operation) . ' successful'];
                $successCount++;
            } else {
                $results[] = ['ip' => $ip, 'status' => 'error', 'message' => $this->cleanErrorMessage($out)];
                $errorCount++;
            }
        }

        return [
            'status' => 'ok',
            'message' => "Bulk operation completed: {$successCount} successful, {$errorCount} failed",
            'summary' => [
                'total' => count($targets),
                'successful' => $successCount,
                'failed' => $errorCount
            ],
            'results' => $results
        ];
    }

    public function searchAction()
    {
        $query = trim($this->request->getQuery('q', 'string', ''));
        $type = trim($this->request->getQuery('type', 'string', 'all'));
        $limit = max(1, min(100, (int)$this->request->getQuery('limit', 'int', 20)));

        if (empty($query)) {
            return ['status' => 'error', 'message' => 'Search query required'];
        }

        $results = [];
        $backend = new Backend();

        // Search in blocked IPs
        if ($type === 'all' || $type === 'blocked') {
            $blockedOut = trim($backend->configdpRun('webguard', ['get_blocked_ips', '1']));
            if ($blockedOut) {
                $blockedData = json_decode($blockedOut, true);
                if (isset($blockedData['blocked_ips'])) {
                    foreach ($blockedData['blocked_ips'] as $item) {
                        if (stripos($item['ip_address'], $query) !== false || 
                            stripos($item['reason'] ?? '', $query) !== false) {
                            $results[] = [
                                'type' => 'blocked',
                                'data' => $item
                            ];
                        }
                    }
                }
            }
        }

        // Search in whitelist
        if ($type === 'all' || $type === 'whitelist') {
            $whitelistOut = trim($backend->configdpRun('webguard', ['get_whitelist', '1', '100']));
            if ($whitelistOut) {
                $whitelistData = json_decode($whitelistOut, true);
                if (isset($whitelistData['whitelist'])) {
                    foreach ($whitelistData['whitelist'] as $item) {
                        if (stripos($item['ip_address'], $query) !== false || 
                            stripos($item['description'] ?? '', $query) !== false) {
                            $results[] = [
                                'type' => 'whitelist',
                                'data' => $item
                            ];
                        }
                    }
                }
            }
        }

        // Search in threats
        if ($type === 'all' || $type === 'threats') {
            $threatsOut = trim($backend->configdpRun('webguard', ['get_threats', '1']));
            if ($threatsOut) {
                $threatsData = json_decode($threatsOut, true);
                if (isset($threatsData['threats'])) {
                    foreach ($threatsData['threats'] as $item) {
                        if (stripos($item['ip_address'] ?? '', $query) !== false || 
                            stripos($item['threat_type'] ?? '', $query) !== false) {
                            $results[] = [
                                'type' => 'threat',
                                'data' => $item
                            ];
                        }
                    }
                }
            }
        }

        // Limit results
        $results = array_slice($results, 0, $limit);

        return [
            'status' => 'ok',
            'query' => $query,
            'type' => $type,
            'count' => count($results),
            'results' => $results
        ];
    }

    public function healthAction()
    {
        $backend = new Backend();
        
        // Check service status
        $serviceStatus = trim($backend->configdRun('webguard status'));
        $isRunning = (strpos($serviceStatus, 'is running') !== false);
        
        // Check if scripts are accessible
        $scriptsOk = true;
        $testOut = trim($backend->configdpRun('webguard', ['get_stats', '']));
        if (empty($testOut) || strpos($testOut, 'error') !== false) {
            $scriptsOk = false;
        }

        // Check basic functionality
        $functionalityOk = true;
        try {
            $blockedTest = trim($backend->configdpRun('webguard', ['get_blocked_ips', '1']));
            $whitelistTest = trim($backend->configdpRun('webguard', ['get_whitelist', '1', '1']));
            
            if (empty($blockedTest) && empty($whitelistTest)) {
                $functionalityOk = false;
            }
        } catch (Exception $e) {
            $functionalityOk = false;
        }

        $overall = $isRunning && $scriptsOk && $functionalityOk;

        return [
            'status' => 'ok',
            'health' => [
                'overall' => $overall ? 'healthy' : 'unhealthy',
                'service_running' => $isRunning,
                'scripts_accessible' => $scriptsOk,
                'functionality_ok' => $functionalityOk,
                'timestamp' => date('Y-m-d H:i:s')
            ],
            'checks' => [
                'service' => $isRunning ? 'pass' : 'fail',
                'scripts' => $scriptsOk ? 'pass' : 'fail',
                'functionality' => $functionalityOk ? 'pass' : 'fail'
            ]
        ];
    }

    public function validateConfigAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $config = $this->request->getPost('config', 'array', []);
        
        if (empty($config)) {
            return ['status' => 'error', 'message' => 'Configuration data required'];
        }

        $errors = [];
        $warnings = [];

        // Validate IP addresses in config
        if (isset($config['blocked_ips'])) {
            foreach ($config['blocked_ips'] as $ip) {
                if (!$this->validateIP($ip)) {
                    $errors[] = "Invalid IP address: {$ip}";
                }
            }
        }

        if (isset($config['whitelist'])) {
            foreach ($config['whitelist'] as $ip) {
                if (!$this->validateIP($ip)) {
                    $errors[] = "Invalid whitelist IP: {$ip}";
                }
            }
        }

        // Validate durations
        if (isset($config['default_duration'])) {
            $duration = (int)$config['default_duration'];
            if ($duration < 0) {
                $errors[] = "Invalid duration: must be positive";
            } elseif ($duration > 31536000) { // 1 year
                $warnings[] = "Duration is very long (> 1 year)";
            }
        }

        $isValid = empty($errors);

        return [
            'status' => 'ok',
            'valid' => $isValid,
            'errors' => $errors,
            'warnings' => $warnings,
            'summary' => [
                'error_count' => count($errors),
                'warning_count' => count($warnings),
                'validated_at' => date('Y-m-d H:i:s')
            ]
        ];
    }

    public function getSystemInfoAction()
    {
        $backend = new Backend();
        
        // Get basic system info
        $info = [
            'webguard_version' => '1.0.0',
            'php_version' => PHP_VERSION,
            'timestamp' => date('Y-m-d H:i:s'),
            'timezone' => date_default_timezone_get()
        ];

        // Get stats if available
        $statsOut = trim($backend->configdpRun('webguard', ['get_stats', '']));
        if ($statsOut) {
            $stats = json_decode($statsOut, true);
            if (is_array($stats)) {
                $info['stats'] = $stats;
            }
        }

        return [
            'status' => 'ok',
            'system_info' => $info
        ];
    }

    public function emergencyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $action = trim($this->request->getPost('action', 'string', ''));
        $confirm = $this->request->getPost('confirm', 'string', 'false');

        if ($confirm !== 'true') {
            return ['status' => 'error', 'message' => 'Emergency action requires confirmation'];
        }

        $backend = new Backend();
        $results = [];

        switch ($action) {
            case 'clear_all_blocks':
                $out = trim($backend->configdpRun('webguard', ['clear_expired_blocks']));
                $results['clear_blocks'] = $out;
                break;

            case 'restart_service':
                $out = trim($backend->configdRun('webguard restart'));
                $results['restart'] = $out;
                break;

            case 'clear_all_logs':
                $out = trim($backend->configdpRun('webguard', ['clear_logs']));
                $results['clear_logs'] = $out;
                break;

            case 'reset_config':
                $exportOut = trim($backend->configdpRun('webguard', ['export_config', '']));
                $restartOut = trim($backend->configdRun('webguard restart'));
                $results['export_config'] = $exportOut;
                $results['restart'] = $restartOut;
                break;

            default:
                return ['status' => 'error', 'message' => 'Unknown emergency action'];
        }

        return [
            'status' => 'ok',
            'message' => "Emergency action '{$action}' completed",
            'action' => $action,
            'results' => $results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /* ===== MAINTENANCE ACTIONS ===== */

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        // COMANDO CORRETTO: clear_expired (non clear_expired_blocks)
        $out = trim($backend->configdpRun('webguard', ['clear_expired']));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Expired blocks cleared'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function clearLogsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['clear_logs']));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Logs cleared successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function addSampleThreatsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['add_sample_threats']));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Sample threats added successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function updateRulesAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['update_rules']));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Rules updated successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    /* ===== EXPORT ACTIONS (FIXED) ===== */

    public function exportBlockedAction()
    {
        $format = $this->request->get('format', 'string', 'json');

        if (!in_array($format, ['json', 'csv', 'txt'])) {
            $format = 'json';
        }

        $backend = new Backend();
        // COMANDO CORRETTO: export_blocked (non export_blocked_ips)
        $out = trim($backend->configdpRun('webguard', ['export_blocked', $format]));

        if (empty($out)) {
            return ['status' => 'error', 'message' => 'Export failed - no data returned'];
        }

        // Restituisci i dati per il download via JavaScript invece di usare sendDownload
        $filename = 'webguard_blocked_' . date('Y-m-d_H-i-s') . '.' . $format;
        
        $contentTypes = [
            'json' => 'application/json',
            'csv' => 'text/csv',
            'txt' => 'text/plain'
        ];
        
        return [
            'status' => 'ok',
            'filename' => $filename,
            'content_type' => $contentTypes[$format] ?? 'application/octet-stream',
            'data' => $out
        ];
    }

    public function exportWhitelistAction()
    {
        $format = $this->request->get('format', 'string', 'json');

        if (!in_array($format, ['json', 'csv', 'txt'])) {
            $format = 'json';
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['export_whitelist', $format]));

        if (empty($out)) {
            return ['status' => 'error', 'message' => 'Export failed - no data returned'];
        }

        $filename = 'webguard_whitelist_' . date('Y-m-d_H-i-s') . '.' . $format;
        
        $contentTypes = [
            'json' => 'application/json',
            'csv' => 'text/csv',
            'txt' => 'text/plain'
        ];
        
        return [
            'status' => 'ok',
            'filename' => $filename,
            'content_type' => $contentTypes[$format] ?? 'application/octet-stream',
            'data' => $out
        ];
    }

    /* ===== ADVANCED ACTIONS ===== */

    public function markFalsePositiveAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $threatId = trim($this->request->getPost('threat_id', 'string', ''));
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'False_positive'));

        if (empty($threatId)) {
            return ['status' => 'error', 'message' => 'Threat ID required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['mark_false_positive', $threatId, $reason]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Threat marked as false positive'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function whitelistFromThreatAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        $threatId = trim($this->request->getPost('threat_id', 'string', ''));
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'Whitelisted_from_threat'));

        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['whitelist_ip_from_threat', $ip, $threatId, $reason]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'IP whitelisted from threat'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function blockFromThreatAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        $threatId = trim($this->request->getPost('threat_id', 'string', ''));
        $duration = (int)$this->request->getPost('duration', 'int', 3600);

        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['block_ip_from_threat', $ip, $threatId, (string)$duration]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'IP blocked from threat'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function createRuleFromThreatAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $threatId = trim($this->request->getPost('threat_id', 'string', ''));
        $ruleType = trim($this->request->getPost('rule_type', 'string', 'block'));
        $pattern = trim($this->request->getPost('pattern', 'string', ''));
        $description = $this->argSafe($this->request->getPost('description', 'string', 'Rule_from_threat'));

        if (empty($threatId)) {
            return ['status' => 'error', 'message' => 'Threat ID required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['create_rule_from_threat', $threatId, $ruleType, $pattern, $description]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Rule created from threat'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function clearOldThreatsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $days = (int)$this->request->getPost('days', 'int', 30);
        $severity = trim($this->request->getPost('severity', 'string', 'low'));

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['clear_old_threats', (string)$days, $severity]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Old threats cleared'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    /* ===== STATS AND ANALYTICS ===== */

    public function getGeoStatsAction()
    {
        $period = trim($this->request->getQuery('period', 'string', '24h'));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_geo_stats', $period]));
        
        if ($out && $out !== '') {
            $stats = json_decode($out, true);
            if (is_array($stats)) {
                return ['status' => 'ok', 'data' => $stats];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve geo stats', 'data' => []];
    }

    public function getAttackPatternsAction()
    {
        $period = trim($this->request->getQuery('period', 'string', '24h'));
        $limit = max(1, min(100, (int)$this->request->getQuery('limit', 'int', 20)));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_attack_patterns', $period, (string)$limit]));
        
        if ($out && $out !== '') {
            $patterns = json_decode($out, true);
            if (is_array($patterns)) {
                return ['status' => 'ok', 'data' => $patterns];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve attack patterns', 'data' => []];
    }

    public function getBlockingStatsAction()
    {
        $period = trim($this->request->getQuery('period', 'string', '24h'));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_blocking_stats', $period]));
        
        if ($out && $out !== '') {
            $stats = json_decode($out, true);
            if (is_array($stats)) {
                return ['status' => 'ok', 'data' => $stats];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve blocking stats', 'data' => []];
    }

    public function getIpHistoryAction()
    {
        $ip = trim($this->request->getQuery('ip', 'string', ''));
        
        if (!$this->validateIP($ip)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_ip_history', $ip]));
        
        if ($out && $out !== '') {
            $history = json_decode($out, true);
            if (is_array($history)) {
                return ['status' => 'ok', 'data' => $history];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve IP history', 'data' => []];
    }

    public function getThreatFeedAction()
    {
        $feedName = trim($this->request->getQuery('feed', 'string', 'default'));
        $limit = max(1, min(1000, (int)$this->request->getQuery('limit', 'int', 100)));
        
        $backend = new Backend();
        $out = trim($backend->configdpRun('webguard', ['get_threat_feed', $feedName, (string)$limit]));
        
        if ($out && $out !== '') {
            $feed = json_decode($out, true);
            if (is_array($feed)) {
                return ['status' => 'ok', 'data' => $feed];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve threat feed', 'data' => []];
    }

    /* ===== HELPER METHODS ===== */

    private function svcCmd(string $cmd): array
    {
        $backend = new Backend();
        
        // Per i comandi di servizio (start/stop/restart) usa configdRun
        // perché questi sono gestiti dal sistema di servizi OPNsense
        if (in_array($cmd, ['start', 'stop', 'restart', 'status'])) {
            $response = $backend->configdRun("webguard {$cmd}");
        } else {
            // Per tutti gli altri comandi usa configdpRun
            $response = $backend->configdpRun('webguard', [$cmd]);
        }
        
        $success = (strpos($response, 'OK:') === 0) || 
                   (strpos($response, 'Success') !== false) ||
                   (strpos($response, 'started') !== false) ||
                   (strpos($response, 'stopped') !== false) ||
                   (strpos($response, 'restarted') !== false);
        
        return [
            'status' => $success ? 'ok' : 'error',
            'response' => $response,
            'message' => $success ? ucfirst($cmd) . ' completed' : $this->cleanErrorMessage($response)
        ];
    }

    private function validateIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    private function argSafe(string $value): string
    {
        // Replace spaces and special chars with underscores for script compatibility
        return preg_replace('/[^a-zA-Z0-9_-]/', '_', trim($value));
    }

    private function viewSafe(string $value): string
    {
        // Convert underscores back to spaces and clean for display
        return htmlspecialchars(str_replace('_', ' ', $value), ENT_QUOTES, 'UTF-8');
    }

    private function cleanErrorMessage(string $message): string
    {
        // Clean up error messages for user display
        $message = trim($message);
        if (strpos($message, 'ERROR:') === 0) {
            $message = substr($message, 6);
        }
        return empty($message) ? 'Operation failed' : $message;
    }
}