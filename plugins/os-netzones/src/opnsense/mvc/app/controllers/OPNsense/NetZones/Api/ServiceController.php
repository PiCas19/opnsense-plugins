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

namespace OPNsense\NetZones\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Class ServiceController
 * @package OPNsense\NetZones\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\\OPNsense\\NetZones\\NetZones';
    protected static $internalServiceTemplate = 'OPNsense/NetZones';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'netzones';

    /**
     * Start NetZones service
     * @return array
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdRun("netzones start");
                return [
                    "response" => $response,
                    "status" => trim((string)$response) === "netzones started successfully" ? "ok" : "failed"
                ];
            } catch (\Exception $e) {
                return ["status" => "failed", "message" => $e->getMessage()];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Stop NetZones service
     * @return array
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdRun("netzones stop");
                return [
                    "response" => $response,
                    "status" => trim((string)$response) === "netzones stopped" ? "ok" : "failed"
                ];
            } catch (\Exception $e) {
                return ["status" => "failed", "message" => $e->getMessage()];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Restart NetZones service
     * @return array
     */
    public function restartAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdRun("netzones restart");
                return ["response" => $response, "status" => "ok"];
            } catch (\Exception $e) {
                return ["status" => "failed", "message" => $e->getMessage()];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Reconfigure and restart NetZones service
     * @return array
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $backend->configdRun("template reload OPNsense/NetZones");
                $response = $backend->configdRun("netzones reconfigure");
                $mdl = new \OPNsense\NetZones\NetZones();
                $mdl->configClean();
                return [
                    "response" => $response,
                    "status" => "ok",
                    "message" => "Configuration applied and service restarted"
                ];
            } catch (\Exception $e) {
                return ["status" => "failed", "message" => $e->getMessage()];
            }
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Get NetZones service status
     * @return array
     */
    public function statusAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("netzones status");
        } catch (\Exception $e) {
            return [
                "status" => "ok",
                "running" => false,
                "pid" => null,
                "socket_status" => "unknown",
                "response" => ""
            ];
        }

        $lines = explode("\n", trim((string)$response));
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
     * Clear NetZones logs
     * @return array
     */
    public function clearLogsAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("netzones clear_logs");
            
            return [
                "status" => "ok",
                "response" => $response,
                "message" => "Logs cleared successfully"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }
}