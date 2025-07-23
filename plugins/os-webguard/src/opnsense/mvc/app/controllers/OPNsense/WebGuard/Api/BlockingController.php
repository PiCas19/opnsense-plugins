<?php
/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * /api/webguard/blocking/<action>
 * (Endpoints “REST” opzionali. Se usi solo ServiceController puoi anche ometterlo)
 */
class BlockingController extends ApiControllerBase
{
    public function getBlockedIpsAction()
    {
        if (!$this->request->isGet()) { return []; }

        $page    = (int)$this->request->getQuery('page', 'int', 1);
        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard get_blocked_ips', [$page]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json) && !empty($json['blocked_ips'])) {
                foreach ($json['blocked_ips'] as &$row) {
                    if (isset($row['reason'])) { $row['reason'] = $this->viewSafe($row['reason']); }
                    if (isset($row['block_type'])) { $row['block_type'] = $this->viewSafe($row['block_type']); }
                }
            }
            return $json ?? [];
        }

        return [
            'blocked_ips' => [],
            'total'       => 0,
            'page'        => $page,
            'limit'       => 0,
            'total_pages' => 0
        ];
    }

    public function getWhitelistAction()
    {
        if (!$this->request->isGet()) { return []; }

        $page  = (int)$this->request->getQuery('page', 'int', 1);
        $limit = (int)$this->request->getQuery('limit', 'int', 100);

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard get_whitelist', [$page, $limit]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json) && !empty($json['whitelist'])) {
                foreach ($json['whitelist'] as &$row) {
                    if (isset($row['description'])) { $row['description'] = $this->viewSafe($row['description']); }
                }
            }
            return $json ?? [];
        }

        return [
            'whitelist'   => [],
            'total'       => 0,
            'page'        => $page,
            'limit'       => $limit,
            'total_pages' => 0
        ];
    }

    public function blockIpAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $ip        = trim($this->request->getPost('ip_address', 'string', ''));
        $duration  = (string)$this->request->getPost('duration', 'int', 3600);
        $reason    = $this->argSafe($this->request->getPost('reason', 'string', 'Manual block'));
        $blockType = $this->argSafe($this->request->getPost('block_type', 'string', 'temporary'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard block_ip', [$ip, $duration, $reason, $blockType]));

        if (strpos($out, 'OK:') === 0) {
            return ['result' => 'ok', 'message' => 'IP address blocked successfully'];
        }
        return ['result' => 'failed', 'message' => 'Failed to block IP address: '.$out];
    }

    public function unblockIpAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $ip     = trim($this->request->getPost('ip_address', 'string', ''));
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'Manual unblock'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard unblock_ip', [$ip, $reason]));

        if (strpos($out, 'OK:') === 0) {
            return ['result' => 'ok', 'message' => 'IP address unblocked successfully'];
        }
        return ['result' => 'failed', 'message' => 'Failed to unblock IP address: '.$out];
    }

    public function addToWhitelistAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $ip          = trim($this->request->getPost('ip_address', 'string', ''));
        $description = $this->argSafe($this->request->getPost('description', 'string', ''));
        $permanent   = $this->request->getPost('permanent', 'boolean', true) ? '1' : '0';
        $expiry      = $this->request->getPost('expiry', 'string', '');

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard add_to_whitelist', [$ip, $description ?: 'Manual_entry', $permanent]));

        if (strpos($out, 'OK:') === 0) {
            return ['result' => 'ok', 'message' => 'IP address added to whitelist successfully'];
        }
        return ['result' => 'failed', 'message' => 'Failed to add IP to whitelist: '.$out];
    }

    public function removeFromWhitelistAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $ip     = trim($this->request->getPost('ip_address', 'string', ''));
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'Manual removal'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard remove_from_whitelist', [$ip, $reason]));

        if (strpos($out, 'OK:') === 0) {
            return ['result' => 'ok', 'message' => 'IP address removed from whitelist successfully'];
        }
        return ['result' => 'failed', 'message' => 'Failed to remove IP from whitelist: '.$out];
    }

    public function bulkBlockAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $ipList    = $this->request->getPost('ip_list', 'string', '');
        $duration  = (string)$this->request->getPost('duration', 'int', 3600);
        $reason    = $this->argSafe($this->request->getPost('reason', 'string', 'Bulk block'));
        $blockType = $this->argSafe($this->request->getPost('block_type', 'string', 'temporary'));

        if ($ipList === '') { return ['result' => 'failed', 'message' => 'IP list is required']; }

        $ips     = array_filter(array_map('trim', preg_split('/\r?\n/', $ipList)));
        $valid   = array_values(array_filter($ips, fn($i) => filter_var($i, FILTER_VALIDATE_IP)));
        $invalid = array_values(array_diff($ips, $valid));

        if (!$valid) { return ['result' => 'failed', 'message' => 'No valid IP addresses provided']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard bulk_block_ips', [json_encode($valid), $duration, $reason, $blockType]));

        if (strpos($out, 'OK:') === 0) {
            return [
                'result'        => 'ok',
                'message'       => count($valid).' IP addresses blocked successfully',
                'blocked_count' => count($valid),
                'invalid_ips'   => $invalid
            ];
        }
        return ['result' => 'failed', 'message' => 'Failed to block IP addresses: '.$out];
    }

    public function bulkUnblockAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $ipList = $this->request->getPost('ip_list', 'string', '');
        $reason = $this->argSafe($this->request->getPost('reason', 'string', 'Bulk unblock'));

        if ($ipList === '') { return ['result' => 'failed', 'message' => 'IP list is required']; }

        $ips     = array_filter(array_map('trim', preg_split('/\r?\n/', $ipList)));
        $valid   = array_values(array_filter($ips, fn($i) => filter_var($i, FILTER_VALIDATE_IP)));
        $invalid = array_values(array_diff($ips, $valid));

        if (!$valid) { return ['result' => 'failed', 'message' => 'No valid IP addresses provided']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard bulk_unblock_ips', [json_encode($valid), $reason]));

        if (strpos($out, 'OK:') === 0) {
            return [
                'result'          => 'ok',
                'message'         => count($valid).' IP addresses unblocked successfully',
                'unblocked_count' => count($valid),
                'invalid_ips'     => $invalid
            ];
        }
        return ['result' => 'failed', 'message' => 'Failed to unblock IP addresses: '.$out];
    }

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard clear_expired_blocks'));

        if (strpos($out, 'OK:') === 0) {
            $n = (int)str_replace('OK:', '', $out);
            return ['result' => 'ok', 'message' => 'Expired blocks cleared successfully', 'cleared_count' => $n];
        }
        return ['result' => 'failed', 'message' => 'Failed to clear expired blocks: '.$out];
    }

    public function getStatsAction()
    {
        if (!$this->request->isGet()) { return []; }

        $period  = $this->request->getQuery('period', 'string', '24h');
        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard get_blocking_stats', [$period]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json)) { return $json; }
        }

        return [
            'total_blocked'     => 0,
            'active_blocks'     => 0,
            'whitelist_entries' => 0,
            'auto_blocks'       => 0,
            'manual_blocks'     => 0,
            'block_timeline'    => []
        ];
    }

    public function exportBlockedAction()
    {
        if (!$this->request->isGet()) { return ['result' => 'failed', 'message' => 'GET required']; }

        $format         = $this->request->getQuery('format', 'string', 'csv');
        $includeExpired = $this->request->getQuery('include_expired', 'boolean', false);

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard export_blocked_ips', [$format, $includeExpired]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json) && isset($json['data'])) {
                return ['result' => 'ok', 'data' => $json['data'], 'filename' => $json['filename'], 'format' => $format];
            }
            return ['result' => 'failed', 'message' => 'Failed to export blocked IPs'];
        }
        return ['result' => 'failed', 'message' => 'No data to export'];
    }

    public function importBlockedAction()
    {
        if (!$this->request->isPost()) { return ['result' => 'failed', 'message' => 'POST required']; }

        $importData      = $this->request->getPost('import_data', 'string', '');
        $format          = $this->request->getPost('format', 'string', 'csv');
        $defaultDuration = (string)$this->request->getPost('default_duration', 'int', 3600);
        $reason          = $this->argSafe($this->request->getPost('reason', 'string', 'Imported block'));

        if ($importData === '') { return ['result' => 'failed', 'message' => 'Import data is required']; }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard import_blocked_ips', [$importData, $format, $defaultDuration, $reason]));

        if (strpos($out, 'OK:') === 0) {
            $n = (int)str_replace('OK:', '', $out);
            return ['result' => 'ok', 'message' => 'Blocked IPs imported successfully', 'imported_count' => $n];
        }
        return ['result' => 'failed', 'message' => 'Failed to import blocked IPs: '.$out];
    }

    public function getIpHistoryAction($ip = null)
    {
        if (!$this->request->isGet() || $ip === null || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $out     = trim($backend->configdRun('webguard get_ip_history', [$ip]));

        if ($out !== '') {
            $json = json_decode($out, true);
            if (is_array($json)) {
                // pretty reasons if any
                foreach ($json as &$row) {
                    if (isset($row['reason'])) { $row['reason'] = $this->viewSafe($row['reason']); }
                }
                return ['result' => 'ok', 'ip_address' => $ip, 'history' => $json];
            }
        }
        return ['result' => 'failed', 'message' => 'No history found for this IP'];
    }

    /* ---- helpers ---- */

    private function argSafe(string $v): string
    {
        return preg_replace('/\s+/', '_', trim($v));
    }

    private function viewSafe(string $v): string
    {
        return str_replace('_', ' ', $v);
    }
}
