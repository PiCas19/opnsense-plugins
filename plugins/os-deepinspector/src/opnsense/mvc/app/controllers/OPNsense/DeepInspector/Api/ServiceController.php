<?php
/*
 * Copyright (C) 2025 Pierpaolo Casati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * API controller for service management
 *
 * Provides endpoints for controlling the Deep Packet Inspector service lifecycle,
 * IP blocking/whitelisting, and log management.
 *
 * @package OPNsense\DeepInspector\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\\OPNsense\\DeepInspector\\DeepInspector';
    protected static $internalServiceTemplate = 'OPNsense/DeepInspector';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'deepinspector';

    /**
     * Starts the Deep Packet Inspector service
     *
     * @return array Response with status and message
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector start");
            return [
                "response" => $response,
                "status" => strpos($response, "started") !== false ? "ok" : "failed",
                "message" => "Starting Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Stops the Deep Packet Inspector service
     *
     * @return array Response with status and message
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector stop");
            return [
                "response" => $response,
                "status" => strpos($response, "stopped") !== false ? "ok" : "failed",
                "message" => "Stopping Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Restarts the Deep Packet Inspector service
     *
     * @return array Response with status and message
     */
    public function restartAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector restart");
            return [
                "response" => $response,
                "status" => "ok",
                "message" => "Restarting Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Gets the Deep Packet Inspector service status
     *
     * Returns detailed status including PID and socket status.
     *
     * @return array Service status information
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector status");
        
        $lines = explode("\n", trim($response));
        $running = false;
        $pid = null;
        $socket_status = "unknown";
        
        foreach ($lines as $line) {
            // Check "is not running" BEFORE "is running" — "is not running" contains "is running" as substring
            if (stripos($line, "is not running") !== false || stripos($line, "stopped") !== false) {
                $running = false;
            } elseif (stripos($line, "is running") !== false || stripos($line, "started") !== false) {
                $running = true;
                if (preg_match('/pid\s+(\d+)/i', $line, $matches)) {
                    $pid = $matches[1];
                }
            } elseif (strpos($line, "Socket:") !== false) {
                $socket_status = strpos($line, "(active)") !== false ? "active" : "inactive";
            }
        }
        
        return [
            "status" => "ok",
            "response" => $response,
            "running" => $running,
            "pid" => $pid,
            "socket_status" => $socket_status,
            "message" => "Getting DPI engine status"
        ];
    }

    /**
     * Reconfigures and restarts the service
     *
     * Regenerates configuration from templates and restarts the service.
     *
     * @return array Response with status
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            
            // Generate new configuration first
            $backend->configdRun("template reload OPNsense/DeepInspector");
            
            // Then restart the service
            $response = $backend->configdRun("deepinspector restart");
            
            // Mark configuration as clean
            $mdl = new \OPNsense\DeepInspector\DeepInspector();
            $mdl->configClean();
            
            return [
                "response" => $response,
                "status" => "ok",
                "message" => "Reconfiguring Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Block an IP address using daemon
     * @return array
     */
    public function blockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdpRun("deepinspector", array("block_ip", $ip));
                
                return [
                    "status" => trim($response) === "OK" ? "ok" : "failed",
                    "response" => $response,
                    "message" => trim($response) === "OK" ? "IP address $ip blocked successfully" : "Failed to block IP: " . $response
                ];
            } else {
                return ["status" => "failed", "message" => "Invalid IP address format"];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Unblock an IP address using daemon
     * @return array
     */
    public function unblockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdpRun("deepinspector", array("unblock_ip", $ip));
                
                return [
                    "status" => trim($response) === "OK" ? "ok" : "failed",
                    "response" => $response,
                    "message" => trim($response) === "OK" ? "IP address $ip unblocked successfully" : "Failed to unblock IP: " . $response
                ];
            } else {
                return ["status" => "failed", "message" => "Invalid IP address format"];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Whitelist an IP address using daemon
     * @return array
     */
    public function whitelistIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdpRun("deepinspector", array("whitelist_ip", $ip));
                
                return [
                    "status" => trim($response) === "OK" ? "ok" : "failed",
                    "response" => $response,
                    "message" => trim($response) === "OK" ? "IP address $ip whitelisted successfully" : "Failed to whitelist IP: " . $response
                ];
            } else {
                return ["status" => "failed", "message" => "Invalid IP address format"];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Clear DeepInspector logs using daemon
     * @return array
     */
    public function clearLogsAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdpRun("deepinspector", array("clear_logs"));
            
            return [
                "status" => trim($response) === "OK" ? "ok" : "failed",
                "response" => $response,
                "message" => trim($response) === "OK" ? "Logs cleared successfully" : "Failed to clear logs"
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
        $response = $backend->configdpRun("deepinspector", array("list_blocked"));
        
        $ips = array_filter(explode("\n", trim($response)));
        
        return [
            "status" => "ok",
            "data" => $ips,
            "count" => count($ips),
            "message" => "Getting blocked IP list"
        ];
    }

    /**
     * List whitelisted IPs
     * @return array
     */
    public function listWhitelistAction()
    {
        $backend = new Backend();
        $response = $backend->configdpRun("deepinspector", array("list_whitelist"));
        
        $ips = array_filter(explode("\n", trim($response)));
        
        return [
            "status" => "ok",
            "data" => $ips,
            "count" => count($ips),
            "message" => "Getting whitelist IP list"
        ];
    }

    /**
     * Show JSON data for blocked or whitelisted IPs
     * @return array
     */
    public function showJsonAction()
    {
        $type = $this->request->getPost('type') ?: $this->request->getParam('type');
        
        if (!in_array($type, ['blocked', 'whitelist'])) {
            return ["status" => "failed", "message" => "Type must be 'blocked' or 'whitelist'"];
        }
        
        $backend = new Backend();
        $response = $backend->configdpRun("deepinspector", array("show_json", $type));
        
        // Try to decode JSON response
        $data = json_decode($response, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return [
                "status" => "ok",
                "data" => $data,
                "message" => "Getting $type IPs JSON data"
            ];
        }
        
        return [
            "status" => "ok",
            "response" => $response,
            "message" => "Getting $type IPs JSON data"
        ];
    }


    /**
     * Check IP status (blocked, whitelisted, or unknown)
     * @return array
     */
    public function checkIPStatusAction()
    {
        $ip = $this->request->getPost('ip') ?: $this->request->getParam('ip');
        
        if (empty($ip)) {
            return ["status" => "failed", "message" => "IP address is required"];
        }
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        
        $backend = new Backend();
        
        // Check blocked list
        $blockedResponse = $backend->configdpRun("deepinspector", array("list_blocked"));
        $blockedIPs = array_filter(explode("\n", trim($blockedResponse)));
        
        if (in_array($ip, $blockedIPs)) {
            return [
                "status" => "ok",
                "ip_status" => "blocked",
                "message" => "IP is in blocked list"
            ];
        }
        
        // Check whitelist
        $whitelistResponse = $backend->configdpRun("deepinspector", array("list_whitelist"));
        $whitelistIPs = array_filter(explode("\n", trim($whitelistResponse)));
        
        if (in_array($ip, $whitelistIPs)) {
            return [
                "status" => "ok",
                "ip_status" => "whitelisted",
                "message" => "IP is in whitelist"
            ];
        }
        
        return [
            "status" => "ok",
            "ip_status" => "unknown",
            "message" => "IP is not in any list"
        ];
    }

}