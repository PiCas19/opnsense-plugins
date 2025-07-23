<?php
/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class BlockingController
 *  /api/webguard/blocking/<action>
 */
class BlockingController extends ApiControllerBase
{
    /* ----------------------- PUBLIC ACTIONS ----------------------- */

    public function getBlockedIpsAction()
    {
        if (!$this->request->isGet()) {
            return [];
        }

        $page      = $this->request->getQuery('page', 'int', 1);
        $limit     = $this->request->getQuery('limit', 'int', 100);
        $blockType = $this->request->getQuery('block_type', 'string', '');
        $startDate = $this->request->getQuery('start_date', 'string', '');
        $endDate   = $this->request->getQuery('end_date', 'string', '');
        $sourceIp  = $this->request->getQuery('source_ip', 'string', '');

        $filters = [
            'page'       => $page,
            'limit'      => $limit,
            'block_type' => $blockType,
            'start_date' => $startDate,
            'end_date'   => $endDate,
            'source_ip'  => $sourceIp
        ];

        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_blocked_ips", [json_encode($filters)]);

        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return [
            'blocked_ips' => [],
            'total'       => 0,
            'page'        => $page,
            'limit'       => $limit
        ];
    }

    public function getWhitelistAction()
    {
        if (!$this->request->isGet()) {
            return [];
        }

        $page  = $this->request->getQuery('page', 'int', 1);
        $limit = $this->request->getQuery('limit', 'int', 100);

        $filters  = ['page' => $page, 'limit' => $limit];
        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_whitelist", [json_encode($filters)]);

        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return [
            'whitelist' => [],
            'total'     => 0,
            'page'      => $page,
            'limit'     => $limit
        ];
    }

    public function blockIpAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip        = trim($this->request->getPost('ip', 'string', $this->request->getPost('ip_address', 'string', '')));
        $duration  = (string)$this->request->getPost('duration', 'int', 3600);
        $reason    = $this->safeArg($this->request->getPost('reason', 'string', 'Manual block'));
        $blockType = $this->safeArg($this->request->getPost('block_type', 'string', 'temporary'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard block_ip", [$ip, $duration, $reason, $blockType]));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'IP address blocked successfully', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function unblockIpAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip     = trim($this->request->getPost('ip', 'string', $this->request->getPost('ip_address', 'string', '')));
        $reason = $this->safeArg($this->request->getPost('reason', 'string', 'Manual unblock'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard unblock_ip", [$ip, $reason]));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'IP address unblocked successfully', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function addToWhitelistAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip          = trim($this->request->getPost('ip', 'string', $this->request->getPost('ip_address', 'string', '')));
        $description = $this->safeArg($this->request->getPost('description', 'string', ''));
        $permanent   = $this->request->getPost('permanent', 'boolean', true) ? '1' : '0';
        $expiry      = $this->safeArg($this->request->getPost('expiry', 'string', ''));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard add_to_whitelist", [$ip, $description, $permanent, $expiry]));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'IP address added to whitelist', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function removeFromWhitelistAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip     = trim($this->request->getPost('ip', 'string', $this->request->getPost('ip_address', 'string', '')));
        $reason = $this->safeArg($this->request->getPost('reason', 'string', 'Manual removal'));

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard remove_from_whitelist", [$ip, $reason]));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'IP removed from whitelist', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function bulkBlockAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ipList    = $this->request->getPost('ip_list', 'string', '');
        $duration  = (string)$this->request->getPost('duration', 'int', 3600);
        $reason    = $this->safeArg($this->request->getPost('reason', 'string', 'Bulk block'));
        $blockType = $this->safeArg($this->request->getPost('block_type', 'string', 'temporary'));

        if ($ipList === '') {
            return ['status' => 'error', 'message' => 'IP list is required'];
        }

        $ips        = array_filter(array_map('trim', preg_split('/\R+/', $ipList)));
        $validIps   = [];
        $invalidIps = [];

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $validIps[] = $ip;
            } else {
                $invalidIps[] = $ip;
            }
        }

        if (empty($validIps)) {
            return ['status' => 'error', 'message' => 'No valid IP addresses'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard bulk_block_ips", [json_encode($validIps), $duration, $reason, $blockType]));

        if ($this->isOkOutput($raw)) {
            return [
                'status'        => 'ok',
                'message'       => count($validIps) . ' IPs blocked',
                'blocked_count' => count($validIps),
                'invalid_ips'   => $invalidIps,
                'job_id'        => $this->isUuid($raw) ? $raw : null
            ];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function bulkUnblockAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ipList = $this->request->getPost('ip_list', 'string', '');
        $reason = $this->safeArg($this->request->getPost('reason', 'string', 'Bulk unblock'));

        if ($ipList === '') {
            return ['status' => 'error', 'message' => 'IP list is required'];
        }

        $ips        = array_filter(array_map('trim', preg_split('/\R+/', $ipList)));
        $validIps   = [];
        $invalidIps = [];

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $validIps[] = $ip;
            } else {
                $invalidIps[] = $ip;
            }
        }

        if (empty($validIps)) {
            return ['status' => 'error', 'message' => 'No valid IP addresses'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard bulk_unblock_ips", [json_encode($validIps), $reason]));

        if ($this->isOkOutput($raw)) {
            return [
                'status'          => 'ok',
                'message'         => count($validIps) . ' IPs unblocked',
                'unblocked_count' => count($validIps),
                'invalid_ips'     => $invalidIps,
                'job_id'          => $this->isUuid($raw) ? $raw : null
            ];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard clear_expired_blocks"));

        if ($this->isOkOutput($raw)) {
            $cleared = (int)preg_replace('/[^0-9]/', '', $raw);
            return ['status' => 'ok', 'message' => 'Expired blocks cleared', 'cleared_count' => $cleared];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function getStatsAction()
    {
        if (!$this->request->isGet()) {
            return [];
        }

        $period   = $this->request->getQuery('period', 'string', '24h');
        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_blocking_stats", [$period]);

        if (!empty($response)) {
            $stats = json_decode($response, true);
            if (is_array($stats)) {
                return $stats;
            }
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
        if (!$this->request->isGet()) {
            return ['status' => 'error', 'message' => 'GET required'];
        }

        $format         = $this->request->getQuery('format', 'string', 'csv');
        $includeExpired = $this->request->getQuery('include_expired', 'boolean', false) ? 'true' : 'false';

        $backend = new Backend();
        $raw     = $backend->configdRun("webguard export_blocked_ips", [$format, $includeExpired]);

        if (empty($raw)) {
            return ['status' => 'error', 'message' => 'Export failed'];
        }

        $export = json_decode($raw, true);
        if (is_array($export) && isset($export['data'])) {
            return ['status' => 'ok', 'data' => $export['data'], 'filename' => $export['filename'], 'format' => $format];
        }

        return ['status' => 'error', 'message' => 'Failed to export blocked IPs'];
    }

    public function importBlockedAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $importData      = $this->request->getPost('import_data', 'string', '');
        $format          = $this->safeArg($this->request->getPost('format', 'string', 'csv'));
        $defaultDuration = (string)$this->request->getPost('default_duration', 'int', 3600);
        $reason          = $this->safeArg($this->request->getPost('reason', 'string', 'Imported block'));

        if ($importData === '') {
            return ['status' => 'error', 'message' => 'Import data is required'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun("webguard import_blocked_ips", [$importData, $format, $defaultDuration, $reason]));

        if ($this->isOkOutput($raw)) {
            $imported = (int)preg_replace('/[^0-9]/', '', $raw);
            return ['status' => 'ok', 'message' => 'Blocked IPs imported', 'imported_count' => $imported];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function getIpHistoryAction($ip = null)
    {
        if (!$this->request->isGet() || empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = $backend->configdRun("webguard get_ip_history", [$ip]);

        if (!empty($raw)) {
            $history = json_decode($raw, true);
            if (is_array($history)) {
                return ['status' => 'ok', 'ip_address' => $ip, 'history' => $history];
            }
            return ['status' => 'error', 'message' => 'No history found for this IP'];
        }
        return ['status' => 'error', 'message' => 'No history found for this IP'];
    }

    /* ----------------------- HELPERS ----------------------- */

    private function safeArg($v)
    {
        return preg_replace('/\s+/', '_', trim((string)$v));
    }

    private function isUuid($s)
    {
        return (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $s);
    }

    private function isOkOutput($out)
    {
        return $out === '' ||
               strncmp($out, 'OK', 2) === 0 ||
               $out === '0' ||
               $this->isUuid($out);
    }
}
