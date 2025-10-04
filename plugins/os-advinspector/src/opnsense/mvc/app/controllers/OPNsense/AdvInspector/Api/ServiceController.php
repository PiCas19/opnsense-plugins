<?php
/*
 * Copyright (C) 205 Pieproalo Casati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
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

namespace OPNsense\AdvInspector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * API controller for service management
 *
 * Provides endpoints for controlling the Advanced Packet Inspector service
 * lifecycle and rule import/export operations.
 *
 * @package OPNsense\AdvInspector\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AdvInspector\Settings';
    protected static $internalServiceTemplate = 'OPNsense/AdvInspector';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'advinspector';

    /**
     * Start the packet inspection service
     *
     * @return array Response from service command
     */
    public function startAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector start");
        return array("response" => $response);
    }

    /**
     * Stop the packet inspection service
     *
     * @return array Response from service command
     */
    public function stopAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector stop");
        return array("response" => $response);
    }

    /**
     * Restart the packet inspection service
     *
     * @return array Response from service command
     */
    public function restartAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector restart");
        return array("response" => $response);
    }

    /**
     * Reconfigure the service with current settings
     *
     * @return array Response from service command
     */
    public function reconfigureAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector reconfigure");
        return array("response" => $response);
    }

    /**
     * Get current service status
     *
     * @return array Service status response
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector status");
        return array("response" => $response);
    }

    /**
     * Export current rules configuration
     *
     * @return array Export response
     */
    public function export_rulesAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector export_rules");
        return ["response" => $response];
    }

    /**
     * Import rules from JSON payload
     *
     * Validates and imports rules from base64-encoded JSON.
     *
     * @return array Import status
     */
    public function import_rulesAction()
    {
        $result = ["status" => "failed"];
        if ($this->request->isPost()) {
            $base64 = $this->request->getPost("content");
            if (!empty($base64)) {
                $json = base64_decode($base64);
                $parsed = json_decode($json, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    return ["status" => "error", "message" => "Invalid JSON format"];
                }
                if (isset($parsed["rules"]) && is_array($parsed["rules"])) {
                    $mdl = new \OPNsense\AdvInspector\Rules();
                    $mdl->rules->rule->clear();
                    foreach ($parsed["rules"] as $ruleData) {
                        $node = $mdl->rules->rule->Add();
                        foreach ($ruleData as $key => $value) {
                            if ($node->hasField($key)) {
                                $node->$key = $value;
                            }
                        }
                    }
                    $mdl->serializeToConfig();
                    \OPNsense\Core\Config::getInstance()->save();
                    (new Backend())->configdRun("advinspector export_rules");
                    return ["status" => "ok"];
                }
            }
        }
        return ["status" => "failed", "message" => "Missing POST content"];
    }


}