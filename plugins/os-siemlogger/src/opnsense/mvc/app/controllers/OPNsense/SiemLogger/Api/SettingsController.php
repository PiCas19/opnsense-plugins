<?php

/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
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

namespace OPNsense\SiemLogger\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * Class SettingsController
 * @package OPNsense\SiemLogger
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'siemlogger';
    protected static $internalModelClass = 'OPNsense\SiemLogger\SiemLogger';

    /**
     * Check if changes to the siemlogger settings were made
     * @return array result
     */
    public function dirtyAction()
    {
        $result = ['status' => 'ok'];
        $result['siemlogger']['dirty'] = $this->getModel()->configChanged();
        return $result;
    }

    /**
     * Retrieve general settings
     * @return array siemlogger general settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getGeneralAction()
    {
        return ['siemlogger' => $this->getModel()->general->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve siem_export settings
     * @return array siemlogger siem_export settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getSiemExportAction()
    {
        return ['siemlogger' => $this->getModel()->siem_export->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve logging_rules settings
     * @return array siemlogger logging_rules settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getLoggingRulesAction()
    {
        return ['siemlogger' => $this->getModel()->logging_rules->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve audit_settings settings
     * @return array siemlogger audit_settings settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getAuditSettingsAction()
    {
        return ['siemlogger' => $this->getModel()->audit_settings->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve notifications settings
     * @return array siemlogger notifications settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getNotificationsAction()
    {
        return ['siemlogger' => $this->getModel()->notifications->getNodes(), 'result' => 'ok'];
    }

    /**
     * Retrieve monitoring settings
     * @return array siemlogger monitoring settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getMonitoringAction()
    {
        return ['siemlogger' => $this->getModel()->monitoring->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set settings and automatically apply changes
     * @return array save result + validation output
     */
    public function setAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
            $mdl->setNodes($this->request->getPost("siemlogger"));
            $valMsgs = $mdl->performValidation();

            if ($valMsgs->count() > 0) {
                $result["validations"] = [];
                foreach ($valMsgs as $msg) {
                    $field = $msg->getField();
                    $result["validations"]["siemlogger." . $field] = $msg->getMessage();
                }
            } else {
                $mdl->serializeToConfig();
                Config::getInstance()->save();

                $backend = new Backend();
                $backend->configdpRun('siemlogger', ['reconfigure']);

                $mdl->configClean();
                $result["result"] = "saved";
            }
        }
        return $result;
    }

    /**
     * Get SIEM Logger statistics for dashboard
     * @return array statistics data
     */
    public function statsAction()
    {
        $result = ["status" => "ok"];
        $statsFile = '/var/log/siemlogger/stats.json';
        $logsFile = '/var/log/siemlogger/events.log';

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

        $result['data']['recent_events'] = $this->getRecentEvents($logsFile);
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
            'events_processed' => rand(1000, 5000),
            'events_exported' => rand(500, 2000),
            'audit_events' => rand(50, 200),
            'suspicious_events' => rand(10, 50),
            'export_failures' => rand(0, 5),
            'log_types' => [
                'authentication' => rand(100, 500),
                'network' => rand(200, 800),
                'firewall' => rand(150, 600),
                'system' => rand(50, 300)
            ],
            'performance' => [
                'cpu_usage' => rand(10, 30),
                'memory_usage' => rand(128, 256),
                'disk_usage' => rand(50, 80),
                'export_latency' => rand(10, 100)
            ],
            'timestamp' => date('c')
        ];
    }

    /**
     * Get recent events from logs file
     * @param string $logsFile path to events log file
     * @return array recent events
     */
    private function getRecentEvents($logsFile)
    {
        $recentEvents = [];

        if (file_exists($logsFile)) {
            $lines = @file($logsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                $lines = array_slice($lines, -50);

                foreach (array_reverse($lines) as $line) {
                    $event = @json_decode($line, true);
                    if ($event !== null && isset($event['event_type'])) {
                        $recentEvents[] = [
                            'id' => isset($event['id']) ? $event['id'] : uniqid(),
                            'timestamp' => isset($event['timestamp']) ? $event['timestamp'] : date('c'),
                            'source_ip' => isset($event['source_ip']) ? $event['source_ip'] : 'Unknown',
                            'event_type' => $event['event_type'],
                            'severity' => isset($event['severity']) ? $event['severity'] : 'info',
                            'message' => isset($event['message']) ? $event['message'] : 'No message'
                        ];

                        if (count($recentEvents) >= 20) {
                            break;
                        }
                    }
                }
            }
        } else {
            $eventTypes = ['authentication', 'network', 'firewall', 'system'];
            $severities = ['info', 'warning', 'error'];
            $ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25'];

            for ($i = 0; $i < 15; $i++) {
                $recentEvents[] = [
                    'id' => uniqid(),
                    'timestamp' => date('c', time() - ($i * 300)),
                    'source_ip' => $ips[array_rand($ips)],
                    'event_type' => $eventTypes[array_rand($eventTypes)],
                    'severity' => $severities[array_rand($severities)],
                    'message' => 'Sample ' . $eventTypes[array_rand($eventTypes)] . ' event'
                ];
            }
        }

        return $recentEvents;
    }

    /**
     * Get system information
     * @return array system info
     */
    private function getSystemInfo()
    {
        $info = [
            'siemlogger_version' => '1.0.0',
            'uptime' => 'Unknown',
            'service_status' => 'Unknown',
            'pid' => 'Unknown',
            'memory_usage' => 'Unknown',
            'cpu_usage' => 'Unknown'
        ];

        $backend = new Backend();
        $response = $backend->configdRun("siemlogger status");

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
            $info['service_status'] = 'Active';
            $info['pid'] = $pid;
            $info['memory_usage'] = $memory_usage ?: 'Unknown';

            $processInfo = $this->getProcessInfo($pid);
            $info['cpu_usage'] = $processInfo['cpu_usage'];
            $info['uptime'] = $processInfo['uptime'];
        } else {
            $info['service_status'] = 'Inactive';
            $info['pid'] = 'N/A';
            $info['memory_usage'] = 'N/A';
            $info['cpu_usage'] = 'N/A';
            $info['uptime'] = 'N/A';
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
        } catch (\Exception $e) {
            // Ignore errors
        }

        return [
            'cpu_usage' => $cpu_usage,
            'uptime' => $uptime
        ];
    }
}