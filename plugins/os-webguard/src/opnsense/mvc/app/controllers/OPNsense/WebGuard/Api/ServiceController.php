<?php
/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 *  /api/webguard/service/<action>
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass    = '\\OPNsense\\WebGuard\\WebGuard';
    protected static $internalServiceTemplate = 'OPNsense/WebGuard';
    protected static $internalServiceEnabled  = 'enabled';
    protected static $internalServiceName     = 'webguard';

    /* ---------------- SERVICE CONTROL ---------------- */

    public function startAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'failed']; }
        $backend  = new Backend();
        $response = $backend->configdRun('webguard start');
        return ['status' => 'ok', 'response' => $response];
    }

    public function stopAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'failed']; }
        $backend  = new Backend();
        $response = $backend->configdRun('webguard stop');
        return ['status' => 'ok', 'response' => $response];
    }

    public function restartAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'failed']; }
        $backend  = new Backend();
        $response = $backend->configdRun('webguard restart');
        return ['status' => 'ok', 'response' => $response];
    }

    public function statusAction()
    {
        $backend  = new Backend();
        $response = $backend->configdRun('webguard status');
        $running  = (strpos($response, 'is running') !== false);
        return ['status' => 'ok', 'response' => $response, 'running' => $running];
    }

    /* ------------- DATA (using configctl) ------------- */

    public function listBlockedAction()
    {
        $backend  = new Backend();
        $filters  = json_encode(['page' => 1, 'limit' => 100]);
        $response = $backend->configdRun('webguard get_blocked_ips', [$filters]);

        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return ['status' => 'ok', 'data' => $decoded];
            }
        }
        return ['status' => 'error', 'message' => 'Failed to retrieve blocked IPs', 'data' => []];
    }

    public function listWhitelistAction()
    {
        $backend  = new Backend();
        $filters  = json_encode(['page' => 1, 'limit' => 100]);
        $response = $backend->configdRun('webguard get_whitelist', [$filters]);

        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return ['status' => 'ok', 'data' => $decoded];
            }
        }
        return ['status' => 'error', 'message' => 'Failed to retrieve whitelist', 'data' => []];
    }

    public function blockIPAction()
    {
        try {
            if (!$this->request->isPost()) {
                return ['status' => 'error', 'message' => 'POST required'];
            }

            $ip        = trim($this->request->getPost('ip', 'string', ''));
            $duration  = (string)$this->request->getPost('duration', 'int', 3600);
            $reason    = $this->safeArg($this->request->getPost('reason', 'string', 'Manual block'));
            $blockType = $this->safeArg($this->request->getPost('block_type', 'string', 'manual'));

            if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['status' => 'error', 'message' => 'Invalid IP address'];
            }

            $backend = new Backend();
            $raw     = trim((string)$backend->configdRun('webguard block_ip', [$ip, $duration, $reason, $blockType]));

            if ($this->isOkOutput($raw)) {
                return ['status' => 'ok', 'message' => 'IP blocked successfully', 'job_id' => $this->isUuid($raw) ? $raw : null];
            }
            return ['status' => 'error', 'message' => $raw];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    public function unblockIPAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun('webguard unblock_ip', [$ip]));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'IP unblocked successfully', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function addWhitelistAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip          = trim($this->request->getPost('ip', 'string', ''));
        $description = $this->safeArg($this->request->getPost('description', 'string', 'Manual whitelist'));
        $permanent   = $this->request->getPost('permanent', 'string', '1');

        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun('webguard add_to_whitelist', [$ip, $description, $permanent]));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'IP whitelisted successfully', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function removeWhitelistAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip', 'string', ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun('webguard remove_from_whitelist', [$ip]));

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
        $blockType = $this->safeArg($this->request->getPost('block_type', 'string', 'manual'));

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
        $raw     = trim((string)$backend->configdRun('webguard bulk_block_ips', [json_encode($validIps), $duration, $reason, $blockType]));

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
        $raw     = trim((string)$backend->configdRun('webguard bulk_unblock_ips', [json_encode($validIps), $reason]));

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
        $raw     = trim((string)$backend->configdRun('webguard clear_expired_blocks'));

        if ($this->isOkOutput($raw)) {
            $cleared = (int)preg_replace('/[^0-9]/', '', $raw);
            return ['status' => 'ok', 'message' => 'Expired blocks cleared', 'cleared_count' => $cleared];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function clearLogsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun('webguard clear_logs'));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'Logs cleared', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    public function addSampleThreatsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw     = trim((string)$backend->configdRun('webguard add_sample_threats'));

        if ($this->isOkOutput($raw)) {
            return ['status' => 'ok', 'message' => 'Sample threats added', 'job_id' => $this->isUuid($raw) ? $raw : null];
        }
        return ['status' => 'error', 'message' => $raw];
    }

    /* ---------------- EXPORT / STATS ---------------- */

    public function exportBlockedAction()
    {
        $format         = $this->request->get('format', 'json');
        $includeExpired = $this->request->get('include_expired', 'false');

        $backend  = new Backend();
        $response = $backend->configdRun('webguard export_blocked_ips', [$format, $includeExpired]);

        if (empty($response)) {
            return ['status' => 'error', 'message' => 'Export failed'];
        }

        $filename    = 'webguard_blocked_' . date('Y-m-d_H-i-s') . '.' . $format;
        $contentType = $format === 'json' ? 'application/json' : ($format === 'csv' ? 'text/csv' : 'text/plain');

        $this->response->setHeader('Content-Type', $contentType);
        $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
        $this->response->setContent($response);
        return $this->response;
    }

    public function exportWhitelistAction()
    {
        $format   = $this->request->get('format', 'json');
        $backend  = new Backend();
        $response = $backend->configdRun('webguard export_whitelist', [$format]);

        if (empty($response)) {
            return ['status' => 'error', 'message' => 'Export failed'];
        }

        $filename    = 'webguard_whitelist_' . date('Y-m-d_H-i-s') . '.' . $format;
        $contentType = $format === 'json' ? 'application/json' : ($format === 'csv' ? 'text/csv' : 'text/plain');

        $this->response->setHeader('Content-Type', $contentType);
        $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
        $this->response->setContent($response);
        return $this->response;
    }

    public function getStatsAction()
    {
        $backend  = new Backend();
        $response = $backend->configdRun('webguard get_stats', ['']);

        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return ['status' => 'ok', 'data' => $decoded];
            }
        }

        return ['status' => 'ok', 'data' => [
            'blocked_count'   => 0,
            'whitelist_count' => 0,
            'active_blocks'   => 0,
            'expired_blocks'  => 0
        ]];
    }

    /* ---------------- HELPERS ---------------- */

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
