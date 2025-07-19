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

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\WebGuard\WebGuard;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Class SettingsController
 * @package OPNsense\WebGuard\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'webguard';
    protected static $internalModelClass = '\OPNsense\WebGuard\WebGuard';

    /**
     * Get WebGuard settings
     * @return array
     */
    public function getAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $mdlWebGuard = new WebGuard();
            $result['webguard'] = $mdlWebGuard->getNodes();
        }
        return $result;
    }

    /**
     * Update WebGuard settings
     * @return array
     */
    public function setAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $mdlWebGuard = new WebGuard();
            $mdlWebGuard->setNodes($this->request->getPost("webguard"));
            
            $validationMessages = $mdlWebGuard->performValidation();
            if (count($validationMessages) == 0) {
                // Save configuration
                $mdlWebGuard->serializeToConfig();
                Config::getInstance()->save();
                
                // Generate configuration file for engine
                $this->generateEngineConfig();
                
                $result["result"] = "saved";
            } else {
                $result["result"] = "failed";
                $result["validations"] = $validationMessages;
            }
        }
        return $result;
    }

    /**
     * Get service status
     * @return array
     */
    public function statusAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard status");
            $result['status'] = trim($response);
            
            // Get additional status information
            $stats = $this->getStatsAction();
            $result = array_merge($result, $stats);
        }
        return $result;
    }

    /**
     * Start WebGuard service
     * @return array
     */
    public function startAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard start");
            if (strpos($response, "OK") !== false) {
                $result["result"] = "ok";
            } else {
                $result["message"] = trim($response);
            }
        }
        return $result;
    }

    /**
     * Stop WebGuard service
     * @return array
     */
    public function stopAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard stop");
            if (strpos($response, "OK") !== false) {
                $result["result"] = "ok";
            } else {
                $result["message"] = trim($response);
            }
        }
        return $result;
    }

    /**
     * Restart WebGuard service
     * @return array
     */
    public function restartAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard restart");
            if (strpos($response, "OK") !== false) {
                $result["result"] = "ok";
            } else {
                $result["message"] = trim($response);
            }
        }
        return $result;
    }

    /**
     * Reload WebGuard configuration
     * @return array
     */
    public function reloadAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $this->generateEngineConfig();
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard reload");
            if (strpos($response, "OK") !== false) {
                $result["result"] = "ok";
            } else {
                $result["message"] = trim($response);
            }
        }
        return $result;
    }

    /**
     * Get WebGuard statistics
     * @return array
     */
    public function getStatsAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_stats");
            
            if (!empty($response)) {
                $stats = json_decode($response, true);
                if ($stats !== null) {
                    $result = $stats;
                } else {
                    $result = array(
                        'requests_analyzed' => 0,
                        'threats_blocked' => 0,
                        'ips_blocked' => 0,
                        'uptime' => 0,
                        'cpu_usage' => 0,
                        'memory_usage' => 0
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Export configuration
     * @return array
     */
    public function exportConfigAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isGet()) {
            $mdlWebGuard = new WebGuard();
            $config = $mdlWebGuard->getEngineConfig();
            
            $result = array(
                "result" => "ok",
                "config" => $config,
                "timestamp" => date('Y-m-d H:i:s')
            );
        }
        return $result;
    }

    /**
     * Import configuration
     * @return array
     */
    public function importConfigAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $configData = $this->request->getPost("config");
            
            if (!empty($configData)) {
                try {
                    $config = json_decode($configData, true);
                    if ($config !== null) {
                        $mdlWebGuard = new WebGuard();
                        
                        // Apply configuration
                        $this->applyImportedConfig($mdlWebGuard, $config);
                        
                        $validationMessages = $mdlWebGuard->performValidation();
                        if (count($validationMessages) == 0) {
                            $mdlWebGuard->serializeToConfig();
                            Config::getInstance()->save();
                            $this->generateEngineConfig();
                            
                            $result["result"] = "ok";
                        } else {
                            $result["validations"] = $validationMessages;
                        }
                    } else {
                        $result["message"] = "Invalid JSON configuration";
                    }
                } catch (Exception $e) {
                    $result["message"] = "Error importing configuration: " . $e->getMessage();
                }
            } else {
                $result["message"] = "No configuration data provided";
            }
        }
        return $result;
    }

    /**
     * Test WAF rules
     * @return array
     */
    public function testRulesAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $testUrl = $this->request->getPost("url");
            $testPayload = $this->request->getPost("payload");
            
            if (!empty($testUrl) && !empty($testPayload)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard test_rules", array($testUrl, $testPayload));
                
                $testResult = json_decode($response, true);
                if ($testResult !== null) {
                    $result = array(
                        "result" => "ok",
                        "test_result" => $testResult
                    );
                } else {
                    $result["message"] = "Failed to parse test results";
                }
            } else {
                $result["message"] = "URL and payload are required for testing";
            }
        }
        return $result;
    }

    /**
     * Update WAF rules from external sources
     * @return array
     */
    public function updateRulesAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard update_rules");
            
            if (strpos($response, "OK") !== false) {
                $result["result"] = "ok";
                $result["message"] = "WAF rules updated successfully";
            } else {
                $result["message"] = "Failed to update WAF rules: " . trim($response);
            }
        }
        return $result;
    }

    /**
     * Generate engine configuration file
     * @return void
     */
    private function generateEngineConfig()
    {
        $mdlWebGuard = new WebGuard();
        $config = $mdlWebGuard->getEngineConfig();
        
        $backend = new Backend();
        $backend->configdRun("webguard export_config", array(json_encode($config)));
    }

    /**
     * Apply imported configuration to model
     * @param WebGuard $model
     * @param array $config
     */
    private function applyImportedConfig($model, $config)
    {
        // Apply general settings
        if (isset($config['general'])) {
            foreach ($config['general'] as $key => $value) {
                if ($model->general->$key !== null) {
                    $model->general->$key = $value;
                }
            }
        }

        // Apply WAF settings
        if (isset($config['waf'])) {
            foreach ($config['waf'] as $key => $value) {
                if ($model->waf->$key !== null) {
                    $model->waf->$key = $value;
                }
            }
        }

        // Apply behavioral settings
        if (isset($config['behavioral'])) {
            foreach ($config['behavioral'] as $key => $value) {
                if ($model->behavioral->$key !== null) {
                    $model->behavioral->$key = $value;
                }
            }
        }

        // Apply covert channels settings
        if (isset($config['covert_channels'])) {
            foreach ($config['covert_channels'] as $key => $value) {
                if ($model->covert_channels->$key !== null) {
                    $model->covert_channels->$key = $value;
                }
            }
        }

        // Apply response settings
        if (isset($config['response'])) {
            foreach ($config['response'] as $key => $value) {
                if ($model->response->$key !== null) {
                    $model->response->$key = $value;
                }
            }
        }

        // Apply whitelist settings
        if (isset($config['whitelist'])) {
            foreach ($config['whitelist'] as $key => $value) {
                if ($model->whitelist->$key !== null) {
                    $model->whitelist->$key = $value;
                }
            }
        }
    }
}