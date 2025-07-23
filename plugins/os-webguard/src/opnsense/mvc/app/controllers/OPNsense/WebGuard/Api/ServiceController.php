<?php

/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Class ServiceController
 * @package OPNsense\WebGuard\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\\OPNsense\\WebGuard\\WebGuard';
    protected static $internalServiceTemplate = 'OPNsense/WebGuard';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'webguard';

    /**
     * Start WebGuard service
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard start");
            return [
                "response" => $response,
                "status" => "ok"
            ];
        }
        return ["status" => "failed"];
    }

    /**
     * Stop WebGuard service
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard stop");
            return [
                "response" => $response,
                "status" => "ok"
            ];
        }
        return ["status" => "failed"];
    }

    /**
     * Restart WebGuard service
     */
    public function restartAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard restart");
            return [
                "response" => $response,
                "status" => "ok"
            ];
        }
        return ["status" => "failed"];
    }

    /**
     * Get service status
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard status");
        
        $running = strpos($response, "is running") !== false;
        
        return [
            "status" => "ok",
            "response" => $response,
            "running" => $running
        ];
    }

    /**
     * List blocked IPs using webguard_control.sh
     */
    public function listBlockedAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard show_json blocked");
        
        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if ($decoded && !isset($decoded['error'])) {
                return [
                    'status' => 'ok',
                    'data' => $decoded
                ];
            }
        }
        
        return [
            'status' => 'error',
            'message' => 'Failed to retrieve blocked IPs',
            'data' => []
        ];
    }

    /**
     * List whitelist entries using webguard_control.sh
     */
    public function listWhitelistAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard show_json whitelist");
        
        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if ($decoded && !isset($decoded['error'])) {
                return [
                    'status' => 'ok',
                    'data' => $decoded
                ];
            }
        }
        
        return [
            'status' => 'error',
            'message' => 'Failed to retrieve whitelist',
            'data' => []
        ];
    }

    /**
     * Block IP address using webguard_control.sh
     */
    public function blockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            $duration = $this->request->getPost("duration", "3600");
            $reason = $this->request->getPost("reason", "Manual block");
            $blockType = $this->request->getPost("block_type", "manual");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['status' => 'error', 'message' => 'Invalid IP address format'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard block_ip", [$ip, $duration, $reason, $blockType]);
            
            if (strpos($response, 'OK:') !== false) {
                return ['status' => 'ok', 'message' => 'IP blocked successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response)];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Unblock IP address using webguard_control.sh
     */
    public function unblockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard unblock_ip", [$ip]);
            
            if (strpos($response, 'OK:') !== false) {
                return ['status' => 'ok', 'message' => 'IP unblocked successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response)];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Add IP to whitelist using webguard_control.sh
     */
    public function addWhitelistAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            $description = $this->request->getPost("description", "Manual whitelist");
            $permanent = $this->request->getPost("permanent", "1");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['status' => 'error', 'message' => 'Invalid IP address format'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard whitelist_ip", [$ip, $description, $permanent]);
            
            if (strpos($response, 'OK:') !== false) {
                return ['status' => 'ok', 'message' => 'IP whitelisted successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response)];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Remove IP from whitelist using webguard_control.sh
     */
    public function removeWhitelistAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard remove_whitelist", [$ip]);
            
            if (strpos($response, 'OK:') !== false) {
                return ['status' => 'ok', 'message' => 'IP removed from whitelist successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response)];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Bulk block IPs using webguard_control.sh
     */
    public function bulkBlockAction()
    {
        if ($this->request->isPost()) {
            $ipList = $this->request->getPost("ip_list");
            $duration = $this->request->getPost("duration", "3600");
            $reason = $this->request->getPost("reason", "Bulk block");
            $blockType = $this->request->getPost("block_type", "manual");
            
            if (empty($ipList)) {
                return ['status' => 'error', 'message' => 'IP list is required'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard bulk_block", [$ipList, $duration, $reason, $blockType]);
            
            if (strpos($response, 'OK:') !== false) {
                return ['status' => 'ok', 'message' => 'IPs blocked successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response)];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Clear expired blocks using webguard_control.sh
     */
    public function clearExpiredAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard clear_expired");
        
        if (strpos($response, 'OK:') !== false) {
            return ['status' => 'ok', 'message' => 'Expired blocks cleared successfully'];
        } else {
            return ['status' => 'error', 'message' => trim($response)];
        }
    }

    /**
     * Export blocked IPs using webguard_control.sh
     */
    public function exportBlockedAction()
    {
        $format = $this->request->get("format", "json");
        
        $backend = new Backend();
        $response = $backend->configdRun("webguard export_blocked", [$format]);
        
        if (!empty($response)) {
            $filename = 'webguard_blocked_' . date('Y-m-d_H-i-s') . '.' . $format;
            
            $contentType = $format === 'json' ? 'application/json' : 
                          ($format === 'csv' ? 'text/csv' : 'text/plain');
            
            $this->response->setHeader('Content-Type', $contentType);
            $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
            $this->response->setContent($response);
            
            return $this->response;
        }
        
        return ['status' => 'error', 'message' => 'Export failed'];
    }

    /**
     * Export whitelist using webguard_control.sh
     */
    public function exportWhitelistAction()
    {
        $format = $this->request->get("format", "json");
        
        $backend = new Backend();
        $response = $backend->configdRun("webguard export_whitelist", [$format]);
        
        if (!empty($response)) {
            $filename = 'webguard_whitelist_' . date('Y-m-d_H-i-s') . '.' . $format;
            
            $contentType = $format === 'json' ? 'application/json' : 
                          ($format === 'csv' ? 'text/csv' : 'text/plain');
            
            $this->response->setHeader('Content-Type', $contentType);
            $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
            $this->response->setContent($response);
            
            return $this->response;
        }
        
        return ['status' => 'error', 'message' => 'Export failed'];
    }

    /**
     * Get statistics using webguard_control.sh
     */
    public function getStatsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard get_stats");
        
        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if ($decoded) {
                return [
                    'status' => 'ok',
                    'data' => $decoded
                ];
            }
        }
        
        // Fallback stats
        return [
            'status' => 'ok',
            'data' => [
                'blocked_count' => 0,
                'whitelist_count' => 0,
                'active_blocks' => 0,
                'expired_blocks' => 0
            ]
        ];
    }

    /**
     * Add sample threats for testing
     */
    public function addSampleThreatsAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard add_sample_threats");
            
            if (strpos($response, 'OK:') !== false) {
                return ['status' => 'ok', 'message' => 'Sample threats added successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response)];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }
}