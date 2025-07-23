<?php

/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
     * @return array
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard start");
            return [
                "response" => $response,
                "status" => strpos($response, "started") !== false ? "ok" : "failed",
                "message" => "Starting WebGuard WAF Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Stop WebGuard service
     * @return array
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard stop");
            return [
                "response" => $response,
                "status" => strpos($response, "stopped") !== false ? "ok" : "failed",
                "message" => "Stopping WebGuard WAF Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Restart WebGuard service
     * @return array
     */
    public function restartAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard restart");
            return [
                "response" => $response,
                "status" => "ok",
                "message" => "Restarting WebGuard WAF Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard status");
        
        $lines = explode("\n", trim($response));
        $running = false;
        $pid = null;
        
        foreach ($lines as $line) {
            if (strpos($line, "is running") !== false || strpos($line, "started") !== false) {
                $running = true;
                if (preg_match('/PID (\d+)/', $line, $matches)) {
                    $pid = $matches[1];
                }
            } elseif (strpos($line, "is not running") !== false || strpos($line, "stopped") !== false) {
                $running = false;
            }
        }
        
        return [
            "status" => "ok",
            "response" => $response,
            "running" => $running,
            "pid" => $pid,
            "message" => "Getting WebGuard WAF engine status"
        ];
    }
    /**
     * Reconfigure and restart WebGuard service
     * @return array
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            
            // Generate new configuration first
            $backend->configdRun("template reload OPNsense/WebGuard");
            
            // Then restart the service
            $response = $backend->configdRun("webguard restart");
            
            // Mark configuration as clean
            $mdl = new \OPNsense\WebGuard\WebGuard();
            $mdl->configClean();
            
            return [
                "response" => $response,
                "status" => "ok",
                "message" => "Reconfiguring WebGuard WAF Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }
    /**
     * List blocked IPs
     * @return array
     */
    public function listBlockedAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard get_blocked_ips", ["1"]);
        
        // Parse JSON response from Python script
        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if ($decoded && !isset($decoded['error'])) {
                // Transform the response structure
                $data = [];
                if (isset($decoded['blocked_ips'])) {
                    foreach ($decoded['blocked_ips'] as $item) {
                        $data[] = [
                            'ip' => $item['ip_address'],
                            'address' => $item['ip_address'], // Alias for compatibility
                            'type' => strtoupper($item['block_type']),
                            'block_type' => $item['block_type'],
                            'blocked_since' => $item['blocked_since_iso'],
                            'expires' => $item['expires_at_iso'] ?: 'Never',
                            'expires_at' => $item['expires_at_iso'],
                            'reason' => $item['reason'],
                            'violations' => $item['violations'],
                            'expired' => $item['expired'],
                            'permanent' => $item['permanent']
                        ];
                    }
                }
                
                return [
                    'status' => 'ok',
                    'data' => $data,
                    'count' => count($data)
                ];
            }
        }
        
        return [
            'status' => 'error',
            'message' => 'Failed to retrieve blocked IPs',
            'data' => [],
            'count' => 0
        ];
    }

    /**
     * List whitelist entries
     * @return array
     */
    public function listWhitelistAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard get_whitelist", ["1", "50"]);
        
        // Parse JSON response from Python script
        if (!empty($response)) {
            $decoded = json_decode($response, true);
            if ($decoded && !isset($decoded['error'])) {
                // Transform the response structure
                $data = [];
                if (isset($decoded['whitelist'])) {
                    foreach ($decoded['whitelist'] as $item) {
                        $data[] = [
                            'ip' => $item['ip_address'],
                            'address' => $item['ip_address'], // Alias for compatibility
                            'description' => $item['description'] ?: 'Manual whitelist entry',
                            'added' => isset($item['added_at']) ? date('Y-m-d H:i:s', $item['added_at']) : date('Y-m-d H:i:s'),
                            'expires' => $item['expires_at'] ? date('Y-m-d H:i:s', $item['expires_at']) : 'Never',
                            'expires_at' => $item['expires_at'],
                            'permanent' => $item['permanent'],
                            'expired' => $item['expired']
                        ];
                    }
                }
                
                return [
                    'status' => 'ok',
                    'data' => $data,
                    'count' => count($data)
                ];
            }
        }
        
        return [
            'status' => 'error',
            'message' => 'Failed to retrieve whitelist',
            'data' => [],
            'count' => 0
        ];
    }

    /**
     * Block IP address
     * @return array
     */
    public function blockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            $duration = $this->request->getPost("duration", "3600");
            $reason = $this->request->getPost("reason", "Manual block");
            $blockType = $this->request->getPost("block_type", "temporary");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            // Validate IP address
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return ['status' => 'error', 'message' => 'Invalid IP address format'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard block_ip", [$ip, $duration, $reason, $blockType]);
            
            if (strpos($response, 'OK:') !== false || strpos($response, 'blocked') !== false) {
                return ['status' => 'ok', 'message' => 'IP blocked successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response) ?: 'Block operation failed'];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Unblock IP address
     * @return array
     */
    public function unblockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard unblock_ip", [$ip, "manual"]);
            
            if (strpos($response, 'OK:') !== false || strpos($response, 'unblocked') !== false) {
                return ['status' => 'ok', 'message' => 'IP unblocked successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response) ?: 'Unblock operation failed'];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Bulk block IP addresses
     * @return array
     */
    public function bulkBlockIPAction()
    {
        if ($this->request->isPost()) {
            $ipList = $this->request->getPost("ip_list");
            $duration = $this->request->getPost("duration", "3600");
            $reason = $this->request->getPost("reason", "Bulk block");
            $blockType = $this->request->getPost("block_type", "temporary");
            
            if (empty($ipList)) {
                return ['status' => 'error', 'message' => 'IP list is required'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard bulk_block_ips", [$ipList, $duration, $reason, $blockType]);
            
            if (strpos($response, 'OK:') !== false || strpos($response, 'blocked') !== false) {
                return ['status' => 'ok', 'message' => 'IPs blocked successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response) ?: 'Bulk block operation failed'];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Add IP to whitelist
     * @return array
     */
    public function whitelistIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip_address");
            $description = $this->request->getPost("description", "Manual whitelist");
            $permanent = $this->request->getPost("permanent", "1");
            $expiry = $this->request->getPost("expiry", "");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            // Validate IP address or CIDR
            if (!filter_var($ip, FILTER_VALIDATE_IP) && !$this->validateCIDR($ip)) {
                return ['status' => 'error', 'message' => 'Invalid IP address or CIDR format'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard add_to_whitelist", [$ip, $description, $permanent, $expiry]);
            
            if (strpos($response, 'OK:') !== false || strpos($response, 'added') !== false) {
                return ['status' => 'ok', 'message' => 'IP whitelisted successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response) ?: 'Whitelist operation failed'];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Bulk add IPs to whitelist
     * @return array
     */
    public function bulkWhitelistIPAction()
    {
        if ($this->request->isPost()) {
            $ipList = $this->request->getPost("ip_list");
            $description = $this->request->getPost("description", "Bulk whitelist");
            $permanent = $this->request->getPost("permanent", "1");
            
            if (empty($ipList)) {
                return ['status' => 'error', 'message' => 'IP list is required'];
            }
            
            // For bulk operations, we'll use the bulk_add command from manage_whitelist.py
            $backend = new Backend();
            
            // First, use the whitelist script directly with bulk_add command
            $escapedIpList = escapeshellarg($ipList);
            $escapedDescription = escapeshellarg($description);
            $permanentFlag = ($permanent === '1') ? 'true' : 'false';
            
            $command = "/usr/local/opnsense/scripts/OPNsense/WebGuard/manage_whitelist.py bulk_add {$escapedIpList} {$escapedDescription} {$permanentFlag}";
            $response = shell_exec($command . ' 2>&1');
            
            if (strpos($response, 'OK:') !== false || strpos($response, 'Added') !== false) {
                return ['status' => 'ok', 'message' => 'IPs whitelisted successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response) ?: 'Bulk whitelist operation failed'];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Remove IP from whitelist
     * @return array
     */
    public function removeWhitelistAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost("ip");
            
            if (empty($ip)) {
                return ['status' => 'error', 'message' => 'IP address is required'];
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard remove_from_whitelist", [$ip, "manual"]);
            
            if (strpos($response, 'OK:') !== false || strpos($response, 'removed') !== false) {
                return ['status' => 'ok', 'message' => 'IP removed from whitelist successfully'];
            } else {
                return ['status' => 'error', 'message' => trim($response) ?: 'Remove operation failed'];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Clear expired blocks
     * @return array
     */
    public function clearExpiredAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("webguard clear_expired_blocks");
        
        if (strpos($response, 'OK:') !== false || strpos($response, 'cleared') !== false || strpos($response, 'Removed') !== false) {
            return ['status' => 'ok', 'message' => 'Expired blocks cleared successfully'];
        } else {
            return ['status' => 'error', 'message' => trim($response) ?: 'Clear expired operation failed'];
        }
    }

    /**
     * Import blocked IPs
     * @return array
     */
    public function importBlockedAction()
    {
        if ($this->request->isPost()) {
            // Handle file upload
            $uploadedFiles = $this->request->getUploadedFiles();
            
            if (empty($uploadedFiles) || !isset($uploadedFiles['file'])) {
                return ['status' => 'error', 'message' => 'No file uploaded'];
            }
            
            $file = $uploadedFiles['file'];
            $format = $this->request->getPost("format", "csv");
            $mergeMode = $this->request->getPost("merge_mode", "add");
            
            // Save uploaded file temporarily
            $tempFile = '/tmp/webguard_import_' . time() . '.' . $format;
            $file->moveTo($tempFile);
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard import_blocked_ips", [$tempFile, $format, $mergeMode, "manual"]);
            
            // Clean up temp file
            @unlink($tempFile);
            
            if (strpos($response, 'error') === false && strpos($response, 'failed') === false) {
                return ['status' => 'ok', 'message' => 'Import completed successfully'];
            } else {
                return ['status' => 'error', 'message' => $response];
            }
        }
        
        return ['status' => 'error', 'message' => 'POST request required'];
    }

    /**
     * Export blocked IPs
     * @return array
     */
    public function exportBlockedAction()
    {
        $format = $this->request->get("format", "csv");
        $includeExpired = $this->request->get("include_expired", "0");
        $dateRange = $this->request->get("date_range", "all");
        
        $backend = new Backend();
        $response = $backend->configdRun("webguard export_blocked_ips", [$format, $includeExpired]);
        
        if (!empty($response)) {
            // Set appropriate headers for download
            $filename = 'webguard_blocked_ips_' . date('Y-m-d_H-i-s') . '.' . $format;
            
            $this->response->setHeader('Content-Type', $this->getContentType($format));
            $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
            $this->response->setContent($response);
            
            return $this->response;
        }
        
        return ['status' => 'error', 'message' => 'Export failed'];
    }

    /**
     * Get blocking statistics
     * @return array
     */
    public function getBlockingStatsAction()
    {
        $period = $this->request->get("period", "24h");
        
        $backend = new Backend();
        $response = $backend->configdRun("webguard get_blocking_stats", [$period]);
        
        // Parse and return stats
        $stats = [
            'total_blocks' => 0,
            'active_blocks' => 0,
            'expired_blocks' => 0,
            'manual_blocks' => 0,
            'auto_blocks' => 0
        ];
        
        if (!empty($response)) {
            $lines = explode("\n", trim($response));
            foreach ($lines as $line) {
                if (strpos($line, ':') !== false) {
                    list($key, $value) = explode(':', $line, 2);
                    $stats[trim($key)] = intval(trim($value));
                }
            }
        }
        
        return [
            'status' => 'ok',
            'data' => $stats
        ];
    }

    /**
     * Validate CIDR notation
     * @param string $cidr
     * @return bool
     */
    private function validateCIDR($cidr)
    {
        if (strpos($cidr, '/') === false) {
            return false;
        }
        
        list($ip, $mask) = explode('/', $cidr, 2);
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        $mask = intval($mask);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ($mask >= 0 && $mask <= 32);
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return ($mask >= 0 && $mask <= 128);
        }
        
        return false;
    }

    /**
     * Get content type for export format
     * @param string $format
     * @return string
     */
    private function getContentType($format)
    {
        switch ($format) {
            case 'json':
                return 'application/json';
            case 'xml':
                return 'application/xml';
            case 'csv':
                return 'text/csv';
            case 'txt':
            default:
                return 'text/plain';
        }
    }    
}