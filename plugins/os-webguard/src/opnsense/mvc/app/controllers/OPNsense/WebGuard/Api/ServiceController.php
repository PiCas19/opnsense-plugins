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

    /* ===== STATISTICS AND MONITORING ===== */

    public function getStatsAction()
    {
        $backend = new Backend();
        
        // Try to get comprehensive stats
        $statsOut = trim($backend->configdRun('webguard get_stats'));
        
        if ($statsOut && $statsOut !== '') {
            $stats = json_decode($statsOut, true);
            if (is_array($stats)) {
                return ['status' => 'ok', 'data' => $stats];
            }
        }
        
        // Fallback: get individual counts
        $blockedOut = trim($backend->configdRun('webguard get_blocked_ips', ['1']));
        $whitelistOut = trim($backend->configdRun('webguard get_whitelist', ['1', '1000']));
        
        $blockedCount = 0;
        $whitelistCount = 0;
        $activeBlocks = 0;
        $expiredBlocks = 0;
        
        if ($blockedOut) {
            $blockedData = json_decode($blockedOut, true);
            if (isset($blockedData['total'])) {
                $blockedCount = (int)$blockedData['total'];
                $activeBlocks = isset($blockedData['active']) ? (int)$blockedData['active'] : $blockedCount;
                $expiredBlocks = isset($blockedData['expired']) ? (int)$blockedData['expired'] : 0;
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
                'expired_blocks' => $expiredBlocks,
                'temp_blocks' => max(0, $activeBlocks - $expiredBlocks),
                'last_updated' => date('Y-m-d H:i:s')
            ]
        ];
    }

    public function getThreatsAction()
    {
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        $limit = max(1, min(1000, (int)$this->request->getQuery('limit', 'int', 100)));
        
        $backend = new Backend();
        $out = trim($backend->configdRun('webguard get_threats', [(string)$page, (string)$limit]));
        
        if ($out && $out !== '') {
            $threats = json_decode($out, true);
            if (is_array($threats)) {
                return ['status' => 'ok', 'data' => $threats];
            }
        }
        
        return ['status' => 'error', 'message' => 'Failed to retrieve threats', 'data' => []];
    }

    /* ===== BLOCKED IPS MANAGEMENT ===== */

    public function listBlockedAction()
    {
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        $limit = max(1, min(1000, (int)$this->request->getQuery('limit', 'int', 100)));
        
        $backend = new Backend();
        $out = trim($backend->configdRun('webguard get_blocked_ips', [(string)$page, (string)$limit]));

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
        $out = trim($backend->configdRun('webguard block_ip', [
            $ip, 
            (string)$duration, 
            $reason, 
            $blockType
        ]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
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
        $out = trim($backend->configdRun('webguard unblock_ip', [$ip]));

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
        $out = trim($backend->configdRun('webguard bulk_block_ips', [
            $ipListFormatted, 
            (string)$duration, 
            $reason, 
            $blockType
        ]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
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
        $out = trim($backend->configdRun('webguard get_whitelist', [(string)$page, (string)$limit]));

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
        $out = trim($backend->configdRun('webguard add_to_whitelist', [$ip, $description, $permanent]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
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
        $out = trim($backend->configdRun('webguard remove_from_whitelist', [$ip]));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'IP removed from whitelist successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    /* ===== MAINTENANCE ACTIONS ===== */

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdRun('webguard clear_expired_blocks'));

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
        $out = trim($backend->configdRun('webguard clear_logs'));

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
        $out = trim($backend->configdRun('webguard add_sample_threats'));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Sample threats added successfully'];
        }
        
        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    /* ===== EXPORT ACTIONS ===== */

    public function exportBlockedAction()
    {
        $format = $this->request->get('format', 'string', 'json');
        $includeExpired = $this->request->get('include_expired', 'string', 'false');

        if (!in_array($format, ['json', 'csv', 'txt'])) {
            $format = 'json';
        }

        $backend = new Backend();
        $out = $backend->configdRun('webguard export_blocked_ips', [$format, $includeExpired]);

        if (empty($out)) {
            return ['status' => 'error', 'message' => 'Export failed - no data returned'];
        }

        $this->sendDownload('webguard_blocked_', $format, $out);
        return $this->response;
    }

    public function exportWhitelistAction()
    {
        $format = $this->request->get('format', 'string', 'json');

        if (!in_array($format, ['json', 'csv', 'txt'])) {
            $format = 'json';
        }

        $backend = new Backend();
        $out = $backend->configdRun('webguard export_whitelist', [$format]);

        if (empty($out)) {
            return ['status' => 'error', 'message' => 'Export failed - no data returned'];
        }

        $this->sendDownload('webguard_whitelist_', $format, $out);
        return $this->response;
    }

    /* ===== HELPER METHODS ===== */

    private function svcCmd(string $cmd): array
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard {$cmd}");
        
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

    private function sendDownload(string $prefix, string $format, string $body): void
    {
        $filename = $prefix . date('Y-m-d_H-i-s') . '.' . $format;
        
        $contentTypes = [
            'json' => 'application/json',
            'csv' => 'text/csv',
            'txt' => 'text/plain'
        ];
        
        $contentType = $contentTypes[$format] ?? 'application/octet-stream';

        $this->response->setHeader('Content-Type', $contentType);
        $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
        $this->response->setHeader('Content-Length', strlen($body));
        $this->response->setContent($body);
    }
}