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

    /* ===== SERVICE ===== */

    public function startAction()   { return $this->svcCmd('start'); }
    public function stopAction()    { return $this->svcCmd('stop'); }
    public function restartAction() { return $this->svcCmd('restart'); }

    public function statusAction()
    {
        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard status'));
        return [
            'status'   => 'ok',
            'running'  => (strpos($out, 'is running') !== false),
            'response' => $out
        ];
    }

    /* ===== LISTS (usati dalla UI) ===== */

    public function listBlockedAction()
    {
        $page    = (int)$this->request->getQuery('page', 'int', 1);
        $backend = new Backend();
        
        // FIX: Usa il comando show_json che funziona da CLI
        $out     = trim($backend->configdRun('webguard show_json', ['blocked', (string)$page]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json)) {
                // prettify reasons etc.
                if (!empty($json['blocked_ips'])) {
                    foreach ($json['blocked_ips'] as &$row) {
                        if (isset($row['reason'])) {
                            $row['reason'] = $this->viewSafe($row['reason']);
                        }
                        if (isset($row['block_type'])) {
                            $row['block_type'] = $this->viewSafe($row['block_type']);
                        }
                    }
                }
                return ['status' => 'ok', 'data' => $json];
            }
        }
        return ['status' => 'error', 'message' => 'Failed to retrieve blocked IPs', 'data' => []];
    }

    public function listWhitelistAction()
    {
        $page    = (int)$this->request->getQuery('page',  'int', 1);
        $limit   = (int)$this->request->getQuery('limit', 'int', 100);
        $backend = new Backend();
        
        // FIX: Usa il comando show_json che funziona da CLI
        $out     = trim($backend->configdRun('webguard show_json', ['whitelist', (string)$page, (string)$limit]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json)) {
                if (!empty($json['whitelist'])) {
                    foreach ($json['whitelist'] as &$row) {
                        if (isset($row['description'])) {
                            $row['description'] = $this->viewSafe($row['description']);
                        }
                    }
                }
                return ['status' => 'ok', 'data' => $json];
            }
        }
        return ['status' => 'error', 'message' => 'Failed to retrieve whitelist', 'data' => []];
    }

    /* ===== SINGLE ACTIONS ===== */

    public function blockIPAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip        = trim($this->request->getPost('ip', 'string', ''));
        $duration  = (string)$this->request->getPost('duration', 'int', 3600);
        $reason    = $this->argSafe($this->request->getPost('reason', 'string', 'Manual_block'));
        $blockType = $this->argSafe($this->request->getPost('block_type', 'string', 'manual'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard block_ip', [$ip, $duration, $reason, $blockType]));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'IP blocked successfully'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function unblockIPAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard unblock_ip', [$ip]));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'IP unblocked successfully'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function addWhitelistAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip          = trim($this->request->getPost('ip', 'string', ''));
        $description = $this->argSafe($this->request->getPost('description', 'string', 'Manual_whitelist'));
        $permanent   = $this->request->getPost('permanent', 'string', '1');

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard add_to_whitelist', [$ip, $description, $permanent]));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'IP whitelisted successfully'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function removeWhitelistAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard remove_from_whitelist', [$ip]));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'IP removed from whitelist successfully'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function bulkBlockAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ipList    = $this->request->getPost('ip_list', 'string', '');
        $duration  = (string)$this->request->getPost('duration', 'int', 3600);
        $reason    = $this->argSafe($this->request->getPost('reason', 'string', 'Bulk_block'));
        $blockType = $this->argSafe($this->request->getPost('block_type', 'string', 'manual'));

        if ($ipList === '') { return ['status' => 'error', 'message' => 'IP list is required']; }

        $ips     = array_filter(array_map('trim', preg_split('/\r?\n/', $ipList)));
        $valid   = array_values(array_filter($ips, fn($i) => filter_var($i, FILTER_VALIDATE_IP)));
        $invalid = array_values(array_diff($ips, $valid));

        if (!$valid) { return ['status' => 'error', 'message' => 'No valid IP addresses']; }

        // Convert to newline format for the script
        $ipListFormatted = implode("\n", $valid);

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard bulk_block_ips', [$ipListFormatted, $duration, $reason, $blockType]));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => count($valid).' IPs blocked', 'blocked_count' => count($valid), 'invalid_ips' => $invalid];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard clear_expired_blocks'));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'Expired blocks cleared'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function clearLogsAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard clear_logs'));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'Logs cleared'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    public function addSampleThreatsAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard add_sample_threats'));

        if (strpos($out, 'OK:') === 0) {
            return ['status' => 'ok', 'message' => 'Sample threats added'];
        }
        return ['status' => 'error', 'message' => $out];
    }

    /* ===== EXPORT / STATS ===== */

    public function exportBlockedAction()
    {
        $format         = $this->request->get('format', 'string', 'json');
        $includeExpired = $this->request->get('include_expired', 'string', 'false');

        $backend = new Backend();
        $out     = $backend->configdRun('webguard export_blocked_ips', [$format, $includeExpired]);

        if ($out === '') { return ['status' => 'error', 'message' => 'Export failed']; }

        $this->sendDownload('webguard_blocked_', $format, $out);
        return $this->response;
    }

    public function exportWhitelistAction()
    {
        $format  = $this->request->get('format', 'string', 'json');
        $backend = new Backend();
        $out     = $backend->configdRun('webguard export_whitelist', [$format]);

        if ($out === '') { return ['status' => 'error', 'message' => 'Export failed']; }

        $this->sendDownload('webguard_whitelist_', $format, $out);
        return $this->response;
    }

    public function getStatsAction()
    {
        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard get_stats'));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json)) {
                return ['status' => 'ok', 'data' => $json];
            }
        }
        
        // Fallback: get basic counts from the data we can retrieve
        $blockedOut = trim($backend->configdRun('webguard show_json', ['blocked', '1']));
        $whitelistOut = trim($backend->configdRun('webguard show_json', ['whitelist', '1', '1000']));
        
        $blockedCount = 0;
        $whitelistCount = 0;
        
        if ($blockedOut) {
            $blockedJson = json_decode($blockedOut, true);
            if (isset($blockedJson['total'])) {
                $blockedCount = $blockedJson['total'];
            }
        }
        
        if ($whitelistOut) {
            $whitelistJson = json_decode($whitelistOut, true);
            if (isset($whitelistJson['total'])) {
                $whitelistCount = $whitelistJson['total'];
            }
        }
        
        return [
            'status' => 'ok',
            'data'   => [
                'blocked_count'   => $blockedCount,
                'whitelist_count' => $whitelistCount,
                'active_blocks'   => $blockedCount,
                'expired_blocks'  => 0
            ]
        ];
    }

    /* ===== Helpers ===== */

    private function svcCmd(string $cmd): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend  = new Backend();
        $response = $backend->configdRun("webguard {$cmd}");
        return ['status' => 'ok', 'response' => $response];
    }

    private function argSafe(string $v): string
    {
        // Convert spaces to underscores for script compatibility
        return preg_replace('/\s+/', '_', trim($v));
    }

    private function viewSafe(string $v): string
    {
        // Convert underscores back to spaces for display
        return str_replace('_', ' ', $v);
    }

    private function sendDownload(string $prefix, string $format, string $body): void
    {
        $filename    = $prefix . date('Y-m-d_H-i-s') . '.' . $format;
        $contentType = ($format === 'json') ? 'application/json'
                     : (($format === 'csv') ? 'text/csv' : 'text/plain');

        $this->response->setHeader('Content-Type', $contentType);
        $this->response->setHeader('Content-Disposition', 'attachment; filename="'.$filename.'"');
        $this->response->setContent($body);
    }
}