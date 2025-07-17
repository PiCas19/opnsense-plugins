<?php

/*
 * Copyright (C) 2025 OPNsense Project
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

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Class ServiceController
 * @package OPNsense\DeepInspector\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\\OPNsense\\DeepInspector\\DeepInspector';
    protected static $internalServiceTemplate = 'OPNsense/DeepInspector';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'deepinspector';

    /**
     * Start DeepInspector service
     * @return array
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector start");
            return [
                "response" => $response,
                "status" => trim($response) === "deepinspector started successfully" ? "ok" : "failed"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Stop DeepInspector service
     * @return array
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector stop");
            return [
                "response" => $response,
                "status" => trim($response) === "deepinspector stopped" ? "ok" : "failed"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Restart DeepInspector service
     * @return array
     */
    public function restartAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector restart");
            return [
                "response" => $response,
                "status" => "ok"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Reconfigure and restart DeepInspector service
     * @return array
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            
            // Generate new configuration first
            $backend->configdRun("template reload OPNsense/DeepInspector");
            
            // Then restart the service
            $response = $backend->configdRun("deepinspector reconfigure");
            
            // Mark configuration as clean
            $mdl = new \OPNsense\DeepInspector\DeepInspector();
            $mdl->configClean();
            
            return [
                "response" => $response,
                "status" => "ok",
                "message" => "Configuration applied and service restarted"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Get DeepInspector service status
     * @return array
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
            if (strpos($line, "is running as PID") !== false) {
                $running = true;
                if (preg_match('/PID (\d+)/', $line, $matches)) {
                    $pid = $matches[1];
                }
            } elseif (strpos($line, "Socket:") !== false) {
                $socket_status = strpos($line, "(active)") !== false ? "active" : "inactive";
            } elseif (strpos($line, "is not running") !== false) {
                $running = false;
            }
        }
        
        return [
            "status" => "ok",
            "response" => $response,
            "running" => $running,
            "pid" => $pid,
            "socket_status" => $socket_status
        ];
    }

    /**
     * Block an IP address
     * @return array
     */
    public function blockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("deepinspector block_ip " . escapeshellarg($ip));
                
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
     * Unblock an IP address
     * @return array
     */
    public function unblockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("deepinspector unblock_ip " . escapeshellarg($ip));
                
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
     * Whitelist an IP address
     * @return array
     */
    public function whitelistIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("deepinspector whitelist_ip " . escapeshellarg($ip));
                
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
     * Clear DeepInspector logs
     * @return array
     */
    public function clearLogsAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector clear_logs");
            
            return [
                "status" => "ok",
                "response" => $response,
                "message" => "Logs cleared successfully"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }
}