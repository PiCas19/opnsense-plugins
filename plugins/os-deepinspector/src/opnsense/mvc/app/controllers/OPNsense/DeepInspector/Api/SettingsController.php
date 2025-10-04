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
use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * API controller for Deep Packet Inspector settings management
 *
 * Provides unified endpoints for retrieving and updating all DPI configuration
 * settings including general, protocol, detection, and advanced options.
 *
 * @package OPNsense\DeepInspector\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'deepinspector';
    protected static $internalModelClass = '\\OPNsense\\DeepInspector\\DeepInspector';

    /**
     * Get all Deep Packet Inspector settings
     *
     * Retrieves complete configuration including general, protocols, detection,
     * and advanced settings. Used by all form tabs to populate their fields.
     *
     * @return array Complete settings structure with all sections
     * @throws \ReflectionException when not bound to model
     */
    public function getAction()
    {
        $result = ['deepinspector' => []];
        $mdl = $this->getModel();
        
        if ($mdl !== null) {
            $nodes = $mdl->getNodes();
            
            $result['deepinspector'] = $this->flattenForUI($nodes);
        }
        
        return $result;
    }
    
    /**
     * Flatten complex model structure to simple key-value pairs for UI consumption
     *
     * Transforms the nested model structure returned by getNodes() into a flat
     * structure that OPNsense's form framework expects. Handles OptionField types
     * that return complex objects with 'value' and 'selected' properties by
     * extracting only the selected values as comma-separated strings.
     *
     * Example transformation:
     * Input:  ['mode' => ['passive' => ['selected' => 1], 'active' => ['selected' => 0]]]
     * Output: ['mode' => 'passive']
     *
     * Input:  ['interfaces' => ['lan' => ['selected' => 1], 'wan' => ['selected' => 1]]]
     * Output: ['interfaces' => 'lan,wan']
     *
     * @param array $nodes Raw nested structure from model's getNodes() method
     * @return array Flattened structure with selected values only
     */
    private function flattenForUI($nodes)
    {
        $flattened = [];
        
        foreach ($nodes as $section => $fields) {
            if (!is_array($fields)) {
                // Valore scalare, mantienilo così
                $flattened[$section] = $fields;
                continue;
            }
            
            $flattened[$section] = [];
            
            foreach ($fields as $fieldName => $fieldValue) {
                if (!is_array($fieldValue)) {
                    // Campo semplice (stringa, numero, ecc)
                    $flattened[$section][$fieldName] = $fieldValue;
                    continue;
                }
                
                // Verifica se è una struttura OptionField
                $hasSelectedStructure = false;
                foreach ($fieldValue as $item) {
                    if (is_array($item) && isset($item['selected'])) {
                        $hasSelectedStructure = true;
                        break;
                    }
                }
                
                if ($hasSelectedStructure) {
                    // Struttura OptionField con 'selected'
                    $selected = [];
                    foreach ($fieldValue as $optKey => $optData) {
                        if (is_array($optData) && 
                            isset($optData['selected']) && 
                            $optData['selected'] == 1) {
                            $selected[] = $optKey;
                        }
                    }
                    $flattened[$section][$fieldName] = implode(',', $selected);
                } else {
                    // Array semplice o struttura diversa, mantieni così
                    $flattened[$section][$fieldName] = $fieldValue;
                }
            }
        }
        
        return $flattened;
    }

    /**
     * check if changes to the deepinspector settings were made
     * @return array result
     */
    public function dirtyAction()
    {
        $result = array('status' => 'ok');
        $result['deepinspector']['dirty'] = $this->getModel()->configChanged();
        return $result;
    }


    /**
     * Set Deep Packet Inspector settings and apply changes
     *
     * Validates and saves all posted settings (general, protocols, detection, advanced).
     * Automatically triggers service reconfiguration after successful save.
     * Follows Zero Trust principles with strict validation.
     *
     * @return array Save result with validation messages if any
     */
    public function setAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
            // Set all posted data
            $mdl->setNodes($this->request->getPost("deepinspector"));
            $valMsgs = $mdl->performValidation();

            if ($valMsgs->count() > 0) {
                $result["validations"] = [];
                foreach ($valMsgs as $msg) {
                    $field = $msg->getField();
                    $result["validations"]["deepinspector." . $field] = $msg->getMessage();
                }
            } else {
                $mdl->serializeToConfig();
                Config::getInstance()->save();

                // Automatically reconfigure after save
                $backend = new Backend();
                $backend->configdRun('deepinspector reconfigure');

                // Clear the dirty flag
                $mdl->configClean();

                $result["result"] = "saved";
            }
        }
        return $result;
    }

     /**
     * Get DPI engine statistics for dashboard
     * @return array statistics data
     */
    public function statsAction()
    {
        $result = ["status" => "ok"];
        
        $statsFile = '/var/log/deepinspector/stats.json';
        $alertsFile = '/var/log/deepinspector/alerts.log';
        
        // Load statistics from file
        if (file_exists($statsFile)) {
            $statsData = @file_get_contents($statsFile);
            if ($statsData !== false) {
                $decodedStats = @json_decode($statsData, true);
                if ($decodedStats !== null) {
                    $result['data'] = $decodedStats;
                } else {
                    $result['data'] = $this->getDefaultStats();
                }
            } else {
                $result['data'] = $this->getDefaultStats();
            }
        } else {
            $result['data'] = $this->getDefaultStats();
        }
        
        // Load recent threats from alerts log
        $result['data']['recent_threats'] = $this->getRecentThreats($alertsFile);
        
        // Add system information
        $result['data']['system_info'] = $this->getSystemInfo();
        
        return $result;
    }
    
    /**
     * Get default statistics structure
     * @return array default stats
     */
    private function getDefaultStats()
    {
        return [
            'packets_analyzed' => 0,
            'threats_detected' => 0,
            'false_positives' => 0,
            'critical_alerts' => 0,
            'protocols_analyzed' => [
                'TCP' => 0,
                'UDP' => 0,
                'ICMP' => 0
            ],
            'threat_types' => [
                'malware' => 0,
                'command_injection' => 0,
                'sql_injection' => 0,
                'script_injection' => 0,
                'crypto_mining' => 0,
                'industrial_threat' => 0
            ],
            'performance' => [
                'cpu_usage' => 0,
                'memory_usage' => 0,
                'throughput_mbps' => 0,
                'latency_avg' => 0
            ],
            'industrial_stats' => [
                'modbus_packets' => 0,
                'dnp3_packets' => 0,
                'opcua_packets' => 0,
                'scada_alerts' => 0
            ],
            'timestamp' => date('c')
        ];
    }
    
    /**
     * Get recent threats from alerts log
     *
     * Returns only real threat data - no fallback values (Zero Trust principle).
     *
     * @param string $alertsFile path to alerts log file
     * @return array recent threats (empty if none)
     */
    private function getRecentThreats($alertsFile)
    {
        $recentThreats = [];

        if (file_exists($alertsFile)) {
            $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                $lines = array_slice($lines, -50); // Get last 50 lines

                foreach (array_reverse($lines) as $line) {
                    $threat = @json_decode($line, true);
                    // Only include threats with complete required data (Zero Trust)
                    if ($threat !== null &&
                        isset($threat['threat_type'], $threat['id'], $threat['timestamp'], $threat['source_ip'], $threat['destination_ip'])) {
                        $recentThreats[] = [
                            'id' => $threat['id'],
                            'timestamp' => $threat['timestamp'],
                            'source_ip' => $threat['source_ip'],
                            'destination_ip' => $threat['destination_ip'],
                            'threat_type' => $threat['threat_type'],
                            'severity' => $threat['severity'] ?? 'medium',
                            'protocol' => $threat['protocol'] ?? '',
                            'description' => $threat['description'] ?? '',
                            'industrial_context' => $threat['industrial_context'] ?? false
                        ];

                        // Limit to 20 most recent threats
                        if (count($recentThreats) >= 20) {
                            break;
                        }
                    }
                }
            }
        }

        return $recentThreats;
    }

    /**
     * Get system information
     * @return array system info
     */
    private function getSystemInfo()
    {
        $info = [
            'engine_version' => '1.0.0',
            'signatures_version' => 'Unknown',
            'uptime' => 'Unknown',
            'engine_status' => 'Unknown',
            'pid' => 'Unknown',
            'memory_usage' => 'Unknown',
            'cpu_usage' => 'Unknown'
        ];
        
        // Get status from backend (correct approach)
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector status");
        
        $lines = explode("\n", trim($response));
        $running = false;
        $pid = null;
        $memory_usage = null;
        
        foreach ($lines as $line) {
            if (strpos($line, "is running as PID") !== false) {
                $running = true;
                if (preg_match('/PID (\d+)/', $line, $matches)) {
                    $pid = $matches[1];
                }
            } elseif (strpos($line, "is not running") !== false) {
                $running = false;
            } elseif (strpos($line, "Memory usage:") !== false) {
                if (preg_match('/Memory usage:\s*(\d+(?:\.\d+)?)\s*MB/', $line, $matches)) {
                    $memory_usage = $matches[1] . "MB";
                }
            }
        }
        
        if ($running && $pid) {
            $info['engine_status'] = 'Active';
            $info['pid'] = $pid;
            $info['memory_usage'] = $memory_usage ?: 'Unknown';
            
            // Get additional process info
            $processInfo = $this->getProcessInfo($pid);
            $info['cpu_usage'] = $processInfo['cpu_usage'];
            $info['uptime'] = $processInfo['uptime'];
        } else {
            $info['engine_status'] = 'Inactive';
            $info['pid'] = 'N/A';
            $info['memory_usage'] = 'N/A';
            $info['cpu_usage'] = 'N/A';
            $info['uptime'] = 'N/A';
        }
        
        // Get signatures version
        $sigFile = '/usr/local/etc/deepinspector/signatures.json';
        if (file_exists($sigFile)) {
            $sigData = @file_get_contents($sigFile);
            if ($sigData !== false) {
                $sigJson = @json_decode($sigData, true);
                if ($sigJson !== null && isset($sigJson['version'])) {
                    $sigVersion = $sigJson['version'];
                    // If it's a date, format it as yyyy-mm-dd
                    if (strtotime($sigVersion) !== false) {
                        $info['signatures_version'] = date('Y-m-d', strtotime($sigVersion));
                    } else {
                        $info['signatures_version'] = $sigVersion;
                    }
                } else {
                    $info['signatures_version'] = date('Y-m-d'); // Current date as default
                }
            }
        }
        
        return $info;
    }
    
    /**
     * Get process information
     * @param string $pid
     * @return array
     */
    private function getProcessInfo($pid)
    {
        $cpu_usage = "Unknown";
        $uptime = "Unknown";
        
        try {
            // Get CPU usage
            $cpuCmd = "ps -o pcpu= -p " . escapeshellarg($pid);
            $cpuResult = @shell_exec($cpuCmd);
            if ($cpuResult !== null && $cpuResult !== false) {
                $cpuResult = trim($cpuResult);
                if ($cpuResult !== '' && is_numeric($cpuResult)) {
                    $cpu_usage = $cpuResult . "%";
                }
            }
            
            // Get uptime
            $uptimeCmd = "ps -o etime= -p " . escapeshellarg($pid);
            $uptimeResult = @shell_exec($uptimeCmd);
            if ($uptimeResult !== null && $uptimeResult !== false) {
                $uptimeResult = trim($uptimeResult);
                if ($uptimeResult !== '') {
                    $uptime = $uptimeResult;
                }
            }
        } catch (Exception $e) {
            // Ignore errors, keep default values
        }
        
        return [
            'cpu_usage' => $cpu_usage,
            'uptime' => $uptime
        ];
    }
}