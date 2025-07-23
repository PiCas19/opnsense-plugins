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
 * /api/webguard/blocking/<action>
 */
class BlockingController extends ApiControllerBase
{
    public function getBlockedIpsAction()
    {
        if (!$this->request->isGet()) { return []; }

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

        if ($response) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) { return $decoded; }
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
        if (!$this->request->isGet()) { return []; }

        $page  = $this->request->getQuery('page', 'int', 1);
        $limit = $this->request->getQuery('limit', 'int', 100);

        $filters = ['page' => $page, 'limit' => $limit];

        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_whitelist", [json_encode($filters)]);

        if ($response) {
            $decoded = json_decode($response, true);
            if (is_array($decoded)) { return $decoded; }
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
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $ipAddress = $this->request->getPost('ip_address', 'string', '');
        $duration  = $this->request->getPost('duration', 'int', 3600);
        $reason    = $this->request->getPost('reason', 'string', 'Manual block');
        $blockType = $this->request->getPost('block_type', 'string', 'temporary');

        if (empty($ipAddress) || !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return ["result" => "failed", "message" => "Invalid IP address"];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard block_ip", [$ipAddress, $duration, $reason, $blockType]);

        if (strpos($response, "OK") !== false) {
            return ["result" => "ok", "message" => "IP address blocked successfully"];
        }
        return ["result" => "failed", "message" => "Failed to block IP address: ".trim($response)];
    }

    public function unblockIpAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $ipAddress = $this->request->getPost('ip_address', 'string', '');
        $reason    = $this->request->getPost('reason', 'string', 'Manual unblock');

        if (empty($ipAddress) || !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return ["result" => "failed", "message" => "Invalid IP address"];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard unblock_ip", [$ipAddress, $reason]);

        if (strpos($response, "OK") !== false) {
            return ["result" => "ok", "message" => "IP address unblocked successfully"];
        }
        return ["result" => "failed", "message" => "Failed to unblock IP address: ".trim($response)];
    }

    public function addToWhitelistAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $ipAddress   = $this->request->getPost('ip_address', 'string', '');
        $description = $this->request->getPost('description', 'string', '');
        $permanent   = $this->request->getPost('permanent', 'boolean', true);
        $expiry      = $this->request->getPost('expiry', 'string', '');

        if (empty($ipAddress) || !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return ["result" => "failed", "message" => "Invalid IP address"];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard add_to_whitelist", [$ipAddress, $description, $permanent, $expiry]);

        if (strpos($response, "OK") !== false) {
            return ["result" => "ok", "message" => "IP address added to whitelist successfully"];
        }
        return ["result" => "failed", "message" => "Failed to add IP to whitelist: ".trim($response)];
    }

    public function removeFromWhitelistAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $ipAddress = $this->request->getPost('ip_address', 'string', '');
        $reason    = $this->request->getPost('reason', 'string', 'Manual removal');

        if (empty($ipAddress) || !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return ["result" => "failed", "message" => "Invalid IP address"];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard remove_from_whitelist", [$ipAddress, $reason]);

        if (strpos($response, "OK") !== false) {
            return ["result" => "ok", "message" => "IP address removed from whitelist successfully"];
        }
        return ["result" => "failed", "message" => "Failed to remove IP from whitelist: ".trim($response)];
    }

    public function bulkBlockAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $ipList    = $this->request->getPost('ip_list', 'string', '');
        $duration  = $this->request->getPost('duration', 'int', 3600);
        $reason    = $this->request->getPost('reason', 'string', 'Bulk block');
        $blockType = $this->request->getPost('block_type', 'string', 'temporary');

        if (empty($ipList)) { return ["result" => "failed", "message" => "IP list is required"]; }

        $ips        = array_filter(array_map('trim', explode("\n", $ipList)));
        $validIps   = array();
        $invalidIps = array();

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) { $validIps[] = $ip; }
            else { $invalidIps[] = $ip; }
        }

        if (empty($validIps)) { return ["result" => "failed", "message" => "No valid IP addresses provided"]; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard bulk_block_ips", [json_encode($validIps), $duration, $reason, $blockType]);

        if (strpos($response, "OK") !== false) {
            return [
                "result"        => "ok",
                "message"       => count($validIps) . " IP addresses blocked successfully",
                "blocked_count" => count($validIps),
                "invalid_ips"   => $invalidIps
            ];
        }
        return ["result" => "failed", "message" => "Failed to block IP addresses: ".trim($response)];
    }

    public function bulkUnblockAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $ipList = $this->request->getPost('ip_list', 'string', '');
        $reason = $this->request->getPost('reason', 'string', 'Bulk unblock');

        if (empty($ipList)) { return ["result" => "failed", "message" => "IP list is required"]; }

        $ips        = array_filter(array_map('trim', explode("\n", $ipList)));
        $validIps   = array();
        $invalidIps = array();

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) { $validIps[] = $ip; }
            else { $invalidIps[] = $ip; }
        }

        if (empty($validIps)) { return ["result" => "failed", "message" => "No valid IP addresses provided"]; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard bulk_unblock_ips", [json_encode($validIps), $reason]);

        if (strpos($response, "OK") !== false) {
            return [
                "result"          => "ok",
                "message"         => count($validIps) . " IP addresses unblocked successfully",
                "unblocked_count" => count($validIps),
                "invalid_ips"     => $invalidIps
            ];
        }
        return ["result" => "failed", "message" => "Failed to unblock IP addresses: ".trim($response)];
    }

    public function clearExpiredAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard clear_expired_blocks");

        if (strpos($response, "OK") !== false) {
            $cleared = (int)trim(str_replace("OK:", "", $response));
            return ["result" => "ok", "message" => "Expired blocks cleared successfully", "cleared_count" => $cleared];
        }
        return ["result" => "failed", "message" => "Failed to clear expired blocks: ".trim($response)];
    }

    public function getStatsAction()
    {
        if (!$this->request->isGet()) { return []; }

        $period   = $this->request->getQuery('period', 'string', '24h');
        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_blocking_stats", [$period]);

        if ($response) {
            $stats = json_decode($response, true);
            if (is_array($stats)) { return $stats; }
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
        if (!$this->request->isGet()) { return ["result" => "failed", "message" => "GET required"]; }

        $format         = $this->request->getQuery('format', 'string', 'csv');
        $includeExpired = $this->request->getQuery('include_expired', 'boolean', false);

        $backend  = new Backend();
        $response = $backend->configdRun("webguard export_blocked_ips", [$format, $includeExpired]);

        if ($response) {
            $export = json_decode($response, true);
            if ($export !== null && isset($export['data'])) {
                return ["result" => "ok", "data" => $export['data'], "filename" => $export['filename'], "format" => $format];
            }
            return ["result" => "failed", "message" => "Failed to export blocked IPs"];
        }
        return ["result" => "failed", "message" => "No data to export"];
    }

    public function importBlockedAction()
    {
        if (!$this->request->isPost()) { return ["result" => "failed", "message" => "POST required"]; }

        $importData      = $this->request->getPost('import_data', 'string', '');
        $format          = $this->request->getPost('format', 'string', 'csv');
        $defaultDuration = $this->request->getPost('default_duration', 'int', 3600);
        $reason          = $this->request->getPost('reason', 'string', 'Imported block');

        if (empty($importData)) { return ["result" => "failed", "message" => "Import data is required"]; }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard import_blocked_ips", [$importData, $format, $defaultDuration, $reason]);

        if (strpos($response, "OK") !== false) {
            $importedCount = (int)trim(str_replace("OK:", "", $response));
            return ["result" => "ok", "message" => "Blocked IPs imported successfully", "imported_count" => $importedCount];
        }
        return ["result" => "failed", "message" => "Failed to import blocked IPs: ".trim($response)];
    }

    public function getIpHistoryAction($ip = null)
    {
        if (!$this->request->isGet() || empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["result" => "failed", "message" => "Invalid IP address"];
        }

        $backend  = new Backend();
        $response = $backend->configdRun("webguard get_ip_history", [$ip]);

        if ($response) {
            $history = json_decode($response, true);
            if (is_array($history)) {
                return ["result" => "ok", "ip_address" => $ip, "history" => $history];
            }
            return ["result" => "failed", "message" => "No history found for this IP"];
        }
        return ["result" => "failed", "message" => "No history found for this IP"];
    }
}
