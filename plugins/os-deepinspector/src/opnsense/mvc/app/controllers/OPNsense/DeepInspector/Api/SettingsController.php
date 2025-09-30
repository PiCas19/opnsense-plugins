<?php
/*
 * Copyright (C) 2025 DeepInspector
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

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * Class SettingsController
 *
 * Manages configuration settings and statistics retrieval for the DeepInspector DPI engine
 * within the OPNsense framework. Provides API endpoints for reading and updating configuration
 * sections (general, protocols, detection, advanced) and retrieving real-time engine statistics.
 *
 * This controller ensures that configuration changes are validated and applied correctly,
 * and that statistics reflect only real network traffic data, avoiding any fallback or default data.
 *
 * Key Features:
 * - Configuration retrieval for general, protocol, detection, and advanced settings
 * - Validation and persistence of configuration changes with automatic reconfiguration
 * - Real-time statistics retrieval from engine logs without fallback data
 * - Integration with OPNsense backend for system status and process information
 *
 * @package OPNsense\DeepInspector\Api
 * @author Pierpaolo Casati
 */
class SettingsController extends ApiMutableModelControllerBase
{
    /**
     * Internal model name for OPNsense framework integration
     *
     * Defines the model identifier used by the parent class to locate and instantiate
     * the DeepInspector configuration model.
     *
     * @var string Model identifier used by OPNsense framework
     */
    protected static $internalModelName = 'settings';

    /**
     * Full class path to the configuration model
     *
     * Specifies the complete namespace and class name of the Settings model
     * that contains the configuration structure and validation rules for DeepInspector.
     *
     * @var string Complete class path to Settings model
     */
    protected static $internalModelClass = '\OPNsense\DeepInspector\Settings';

    /**
     * Check if changes to the DeepInspector settings have been made
     *
     * Verifies if the configuration model has uncommitted changes (dirty state).
     * Returns the status of the configuration to indicate whether a save operation is needed.
     *
     * @api GET /api/deepinspector/settings/dirty
     *
     * @return array{status: string, deepinspector: array{dirty: bool}} Result indicating dirty state
     *
     * Response Format:
     * - status: "ok" for successful execution
     * - deepinspector.dirty: Boolean indicating if configuration has changed
     *
     * @example
     * GET /api/deepinspector/settings/dirty
     * Response: {
     *   "status": "ok",
     *   "deepinspector": {
     *     "dirty": true
     *   }
     * }
     */
    public function dirtyAction()
    {
        $result = ['status' => 'ok'];
        $result['deepinspector']['dirty'] = $this->getModel()->configChanged();
        return $result;
    }

    /**
     * Retrieve general settings for DeepInspector
     *
     * Returns the configuration nodes for the general section, including settings
     * such as service enablement, operating mode, and network interfaces.
     *
     * @api GET /api/deepinspector/settings/getGeneral
     *
     * @return array{deepinspector: object, result: string} General configuration nodes
     *
     * Response Format:
     * - deepinspector: Object containing general configuration settings
     * - result: "ok" for successful execution
     *
     * @throws \ReflectionException When model instantiation or node retrieval fails
     *
     * @example
     * GET /api/deepinspector/settings/getGeneral
     * Response: {
     *   "result": "ok",
     *   "deepinspector": {
     *     "enabled": "1",
     *     "mode": "active",
     *     "interfaces": "lan,wan"
     *   }
     * }
     */
    public function getGeneralAction()
    {
        return ['deepinspector' => $this->getModel()->general->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve protocol settings for DeepInspector
     *
     * Returns the configuration nodes for the protocols section, specifying
     * which protocols (e.g., HTTP, HTTPS, Modbus) are enabled for inspection.
     *
     * @api GET /api/deepinspector/settings/getProtocols
     *
     * @return array{deepinspector: object, result: string} Protocol configuration nodes
     *
     * Response Format:
     * - deepinspector: Object containing protocol configuration settings
     * - result: "ok" for successful execution
     *
     * @throws \ReflectionException When model instantiation or node retrieval fails
     *
     * @example
     * GET /api/deepinspector/settings/getProtocols
     * Response: {
     *   "result": "ok",
     *   "deepinspector": {
     *     "http_inspection": "1",
     *     "industrial_protocols": "1"
     *   }
     * }
     */
    public function getProtocolsAction()
    {
        return ['deepinspector' => $this->getModel()->protocols->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve detection settings for DeepInspector
     *
     * Returns the configuration nodes for the detection section, specifying
     * which detection mechanisms (e.g., malware, SQL injection) are enabled.
     *
     * @api GET /api/deepinspector/settings/getDetection
     *
     * @return array{deepinspector: object, result: string} Detection configuration nodes
     *
     * Response Format:
     * - deepinspector: Object containing detection configuration settings
     * - result: "ok" for successful execution
     *
     * @throws \ReflectionException When model instantiation or node retrieval fails
     *
     * @example
     * GET /api/deepinspector/settings/getDetection
     * Response: {
     *   "result": "ok",
     *   "deepinspector": {
     *     "virus_signatures": "1",
     *     "sql_injection": "1"
     *   }
     * }
     */
    public function getDetectionAction()
    {
        return ['deepinspector' => $this->getModel()->detection->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve advanced settings for DeepInspector
     *
     * Returns the configuration nodes for the advanced section, including
     * performance-related settings such as memory limits and thread counts.
     *
     * @api GET /api/deepinspector/settings/getAdvanced
     *
     * @return array{deepinspector: object, result: string} Advanced configuration nodes
     *
     * Response Format:
     * - deepinspector: Object containing advanced configuration settings
     * - result: "ok" for successful execution
     *
     * @throws \ReflectionException When model instantiation or node retrieval fails
     *
     * @example
     * GET /api/deepinspector/settings/getAdvanced
     * Response: {
     *   "result": "ok",
     *   "deepinspector": {
     *     "memory_limit": "1024",
     *     "thread_count": "4"
     *   }
     * }
     */
    public function getAdvancedAction()
    {
        return ['deepinspector' => $this->getModel()->advanced->getNodes(), 'result' => 'ok'];
    }

    /**
     * Update DeepInspector configuration settings
     *
     * Accepts configuration updates via POST requests, validates them against
     * the model constraints, and applies them to the system configuration.
     * Triggers automatic reconfiguration of the DeepInspector service upon success.
     *
     * @api POST /api/deepinspector/settings/set
     *
     * Request Body Format:
     * {
     *   "deepinspector": {
     *     "general": {
     *       "enabled": "1",
     *       "mode": "active",
     *       "interfaces": "lan,wan"
     *     },
     *     "protocols": {
     *       "http_inspection": "1"
     *     }
     *   }
     * }
     *
     * @return array{result: string, validations?: array<string, string>} Operation result
     *
     * Success Response:
     * - result: "saved" when configuration is successfully updated
     *
     * Validation Failure Response:
     * - result: "failed" when validation errors occur
     * - validations: Object mapping field paths to error messages
     *
     * Error Response:
     * - result: "failed" for other failure scenarios
     *
     * @throws \Exception When model operations or configuration saving fails
     *
     * @example
     * POST /api/deepinspector/settings/set
     * Content-Type: application/json
     * Body: {"deepinspector": {"general": {"enabled": "1"}}}
     * Response: {"result": "saved"}
     *
     * @example
     * POST /api/deepinspector/settings/set
     * Body: {"deepinspector": {"general": {"enabled": "invalid"}}}
     * Response: {
     *   "result": "failed",
     *   "validations": {
     *     "deepinspector.general.enabled": "Value must be 0 or 1"
     *   }
     * }
     */
    public function setAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
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
                $backend = new Backend();
                $backend->configdRun('deepinspector reconfigure');
                $mdl->configClean();
                $result["result"] = "saved";
            }
        }
        return $result;
    }

    /**
     * Retrieve DeepInspector engine statistics for dashboard
     *
     * Fetches real-time statistics from the DeepInspector engine, including packet analysis,
     * threat detection, and performance metrics. Returns only data from actual log files,
     * failing with an error if the required files are unavailable or invalid.
     *
     * @api GET /api/deepinspector/settings/stats
     *
     * @return array{status: string, data?: array, error?: string} Statistics data or error message
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" if data is unavailable
     * - data: Statistics and recent threats if available
     * - error: Error message if statistics or alerts cannot be retrieved
     *
     * @example
     * GET /api/deepinspector/settings/stats
     * Response: {
     *   "status": "ok",
     *   "data": {
     *     "packets_analyzed": 1000,
     *     "threats_detected": 5,
     *     "recent_threats": [
     *       {"id": "abc123", "threat_type": "malware", "severity": "critical"}
     *     ],
     *     "system_info": {
     *       "engine_status": "Active",
     *       "pid": "12345"
     *     }
     *   }
     * }
     *
     * @example
     * GET /api/deepinspector/settings/stats
     * Response: {
     *   "status": "failed",
     *   "error": "Statistics file /var/log/deepinspector/stats.json not found"
     * }
     */
    public function statsAction()
    {
        $result = ["status" => "ok"];
        $statsFile = '/var/log/deepinspector/stats.json';
        $alertsFile = '/var/log/deepinspector/alerts.log';

        // Load statistics from file
        if (!file_exists($statsFile)) {
            $result["status"] = "failed";
            $result["error"] = "Statistics file $statsFile not found";
            return $result;
        }

        $statsData = @file_get_contents($statsFile);
        if ($statsData === false) {
            $result["status"] = "failed";
            $result["error"] = "Failed to read statistics file $statsFile";
            return $result;
        }

        $decodedStats = @json_decode($statsData, true);
        if ($decodedStats === null) {
            $result["status"] = "failed";
            $result["error"] = "Invalid JSON in statistics file $statsFile";
            return $result;
        }

        $result['data'] = $decodedStats;
        $result['data']['recent_threats'] = $this->getRecentThreats($alertsFile);
        $result['data']['system_info'] = $this->getSystemInfo();

        return $result;
    }

    /**
     * Retrieve recent threats from alerts log
     *
     * Reads the last 50 lines from the alerts log file and extracts up to 20 recent threats.
     * Returns an empty array if the file is unavailable or empty.
     *
     * @param string $alertsFile Path to the alerts log file
     * @return array Recent threat entries
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
                    if ($threat !== null && isset($threat['threat_type'])) {
                        $recentThreats[] = [
                            'id' => isset($threat['id']) ? $threat['id'] : uniqid(),
                            'timestamp' => isset($threat['timestamp']) ? $threat['timestamp'] : date('c'),
                            'source_ip' => isset($threat['source_ip']) ? $threat['source_ip'] : 'Unknown',
                            'destination_ip' => isset($threat['destination_ip']) ? $threat['destination_ip'] : 'Unknown',
                            'threat_type' => $threat['threat_type'],
                            'severity' => isset($threat['severity']) ? $threat['severity'] : 'medium',
                            'protocol' => isset($threat['protocol']) ? $threat['protocol'] : 'Unknown',
                            'description' => isset($threat['description']) ? $threat['description'] : 'No description',
                            'industrial_context' => isset($threat['industrial_context']) ? $threat['industrial_context'] : false
                        ];

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
     * Retrieve system information for DeepInspector
     *
     * Collects runtime information about the DeepInspector engine, including status,
     * process ID, CPU and memory usage, and signatures version.
     *
     * @return array System information including engine status and resource usage
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

        $sigFile = '/usr/local/etc/deepinspector/signatures.json';
        if (file_exists($sigFile)) {
            $sigData = @file_get_contents($sigFile);
            if ($sigData !== false) {
                $sigJson = @json_decode($sigData, true);
                if ($sigJson !== null && isset($sigJson['version'])) {
                    $sigVersion = $sigJson['version'];
                    if (strtotime($sigVersion) !== false) {
                        $info['signatures_version'] = date('Y-m-d', strtotime($sigVersion));
                    } else {
                        $info['signatures_version'] = $sigVersion;
                    }
                }
            }
        }

        return $info;
    }

    /**
     * Retrieve process information for a given PID
     *
     * Collects CPU usage and uptime for the specified process ID using system commands.
     *
     * @param string $pid Process ID to query
     * @return array{cpu_usage: string, uptime: string} Process information
     */
    private function getProcessInfo($pid)
    {
        $cpu_usage = "Unknown";
        $uptime = "Unknown";

        try {
            $cpuCmd = "ps -o pcpu= -p " . escapeshellarg($pid);
            $cpuResult = @shell_exec($cpuCmd);
            if ($cpuResult !== null && $cpuResult !== false) {
                $cpuResult = trim($cpuResult);
                if ($cpuResult !== '' && is_numeric($cpuResult)) {
                    $cpu_usage = $cpuResult . "%";
                }
            }

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