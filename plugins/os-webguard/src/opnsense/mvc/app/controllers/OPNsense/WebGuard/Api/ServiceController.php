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
 * /api/webguard/service/<action>
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass   = '\\OPNsense\\WebGuard\\WebGuard';
    protected static $internalServiceTemplate = 'OPNsense/WebGuard';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName    = 'webguard';

    /* ---------- SERVICE CONTROL ---------- */

    public function startAction()
    {
        if (!$this->request->isPost()) { return ["status" => "failed"]; }
        $backend  = new Backend();
        $response = $backend->configdRun("webguard start");
        return ["status" => "ok", "response" => $response];
    }

    public function stopAction()
    {
        if (!$this->request->isPost()) { return ["status" => "failed"]; }
        $backend  = new Backend();
        $response = $backend->configdRun("webguard stop");
        return ["status" => "ok", "response" => $response];
    }

    public function restartAction()
    {
        if (!$this->request->isPost()) { return ["status" => "failed"]; }
        $backend  = new Backend();
        $response = $backend->configdRun("webguard restart");
        return ["status" => "ok", "response" => $response];
    }

    public function statusAction()
    {
        $backend  = new Backend();
        $response = $backend->configdRun("webguard status");
        $running  = strpos($response, "is running") !== false;
        return ["status" => "ok", "response" => $response, "running" => $running];
    }

    /* ---------- BLOCK / WHITELIST CRUD (alias configctl CORRETTI) ---------- */

    public function listBlockedAction()
    {
        $backend  = new Backend();
        $filters  = json_encode(["page" => 1, "limit" => 100]);
        $response = $backend->configdRun("webguard get_blocked_ips", [$filters]);

        if ($response) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return ["status" => "ok", "data" => $decoded];
            }
        }
        return ["status" => "error", "message" => "Failed to retrieve blocked IPs", "data" => []];
    }

    public function listWhitelistAction()
    {
        $backend  = new Backend();
        $filters  = json_encode(["page" => 1, "limit" => 100]);
        $response = $backend->configdRun("webguard get_whitelist", [$filters]);

        if ($response) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                return ["status" => "ok", "data" => $decoded];
            }
        }
        return ["status" => "error", "message" => "Failed to retrieve whitelist", "data" => []];
    }

    public function blockIPAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip        = $this->request->getPost("ip");
        $duration  = $this->request->getPost("duration", "3600");
        $reason    = $this->request->getPost("reason", "Manual block");
        $blockType = $this->request->getPost("block_type", "manual");

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard block_ip", [$ip, $duration, $reason, $blockType]);

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => 'IP blocked successfully']
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function unblockIPAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip = $this->request->getPost("ip");
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard unblock_ip", [$ip]);

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => 'IP unblocked successfully']
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function addWhitelistAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip         = $this->request->getPost("ip");
        $description= $this->request->getPost("description", "Manual whitelist");
        $permanent  = $this->request->getPost("permanent", "1");

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard add_to_whitelist", [$ip, $description, $permanent]);

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => 'IP whitelisted successfully']
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function removeWhitelistAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ip = $this->request->getPost("ip");
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'Invalid IP address'];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard remove_from_whitelist", [$ip]);

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => 'IP removed from whitelist successfully']
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function bulkBlockAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ipList    = $this->request->getPost("ip_list", "");
        $duration  = $this->request->getPost("duration", "3600");
        $reason    = $this->request->getPost("reason", "Bulk block");
        $blockType = $this->request->getPost("block_type", "manual");

        if (empty($ipList)) { return ['status' => 'error', 'message' => 'IP list is required']; }

        $ips        = array_filter(array_map('trim', explode("\n", $ipList)));
        $validIps   = array_values(array_filter($ips, fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
        $invalidIps = array_values(array_diff($ips, $validIps));

        if (empty($validIps)) { return ['status' => 'error', 'message' => 'No valid IP addresses']; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard bulk_block_ips", [json_encode($validIps), $duration, $reason, $blockType]);

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => count($validIps).' IPs blocked', 'blocked_count' => count($validIps), 'invalid_ips' => $invalidIps]
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function bulkUnblockAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $ipList = $this->request->getPost("ip_list", "");
        $reason = $this->request->getPost("reason", "Bulk unblock");

        if (empty($ipList)) { return ['status' => 'error', 'message' => 'IP list is required']; }

        $ips        = array_filter(array_map('trim', explode("\n", $ipList)));
        $validIps   = array_values(array_filter($ips, fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
        $invalidIps = array_values(array_diff($ips, $validIps));

        if (empty($validIps)) { return ['status' => 'error', 'message' => 'No valid IP addresses']; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard bulk_unblock_ips", [json_encode($validIps), $reason]);

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => count($validIps).' IPs unblocked', 'unblocked_count' => count($validIps), 'invalid_ips' => $invalidIps]
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard clear_expired_blocks");

        if (strpos($response, "OK") !== false) {
            $cleared = (int)trim(str_replace("OK:", "", $response));
            return ['status' => 'ok', 'message' => 'Expired blocks cleared', 'cleared_count' => $cleared];
        }
        return ['status' => 'error', 'message' => trim($response)];
    }

    public function clearLogsAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }
        $backend  = new Backend();
        $response = $backend->configdRun("webguard clear_logs");

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => 'Logs cleared']
            : ['status' => 'error', 'message' => trim($response)];
    }

    public function addSampleThreatsAction()
    {
        if (!$this->request->isPost()) { return ['status' => 'error', 'message' => 'POST required']; }
        $backend  = new Backend();
        $response = $backend->configdRun("webguard add_sample_threats");

        return (strpos($response, 'OK:') !== false)
            ? ['status' => 'ok', 'message' => 'Sample threats added']
            : ['status' => 'error', 'message' => trim($response)];
    }

    /* ---------- EXPORT / STATS ---------- */

    public function exportBlockedAction()
    {
        $format         = $this->request->get("format", "json");
        $includeExpired = $this->request->get("include_expired", "false");

        $backend  = new Backend();
        $response = $backend->configdRun("webguard export_blocked_ips", [$format, $includeExpired]);

        if (!$response) { return ['status' => 'error', 'message' => 'Export failed']; }

        $filename    = 'webguard_blocked_' . date('Y-m-d_H-i-s') . '.' . $format;
        $contentType = $format === 'json' ? 'application/json' : ($format === 'csv' ? 'text/csv' : 'text/plain');

        $this->response->setHeader('Content-Type', $contentType);
        $this->response->setHeader('Content-Disposition', 'attachment; filename="'.$filename.'"');
        $this->response->setContent($response);
        return $this->response;
    }

    public function exportWhitelistAction()
    {
        $format = $this->request->get("format", "json");

        $backend  = new Backend();
        $response = $backend->configdRun("webguard export_whitelist", [$format]);

        if (!$response) { return ['status' => 'error', 'message' => 'Export failed']; }

        $filename    = 'webguard_whitelist_' . date('Y-m-d_H-i-s') . '.' . $format;
        $contentType = $format === 'json' ? 'application/json' : ($format === 'csv' ? 'text/csv' : 'text/plain');

        $this->response->setHeader('Content-Type', $contentType);
        $this->response->setHeader('Content-Disposition', 'attachment; filename="'.$filename.'"');
        $this->response->setContent($response);
        return $this->response;
    }

    public function getStatsAction()
    {
        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_stats", [""]);

        if ($response) {
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
}
