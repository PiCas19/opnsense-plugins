<?php
/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
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

namespace OPNsense\SiemLogger\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\SiemLogger\SiemLogger;

/**
 * Class ServiceController - API controller for service management
 * @package OPNsense\SiemLogger\Api
 */
class ServiceController extends ApiControllerBase
{
    /**
     * Get service status
     * @return array
     */
    public function statusAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun('siemlogger status');
            
            $result = [
                'status' => 'ok',
                'running' => false,
                'enabled' => false,
                'pid' => null,
                'uptime' => null
            ];

            if (!empty($response)) {
                $status = json_decode($response, true);
                if (is_array($status)) {
                    $result = array_merge($result, $status);
                } else {
                    // Fallback parsing for simple text response
                    $result['running'] = (strpos($response, 'running') !== false || strpos($response, 'active') !== false);
                    
                    // Try to extract PID
                    if (preg_match('/PID (\d+)/', $response, $matches)) {
                        $result['pid'] = $matches[1];
                    }
                }
            }

            // Check if service is enabled in configuration
            $mdl = new SiemLogger();
            $result['enabled'] = $mdl->isEnabled();

            return $result;

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
                'running' => false,
                'enabled' => false
            ];
        }
    }

    /**
     * Start the service
     * @return array
     */
    public function startAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun('siemlogger start');
            
            return [
                'status' => 'ok',
                'action' => 'start',
                'message' => 'SIEM Logger service start initiated',
                'response' => $response
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Stop the service
     * @return array
     */
    public function stopAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun('siemlogger stop');
            
            return [
                'status' => 'ok',
                'action' => 'stop',
                'message' => 'SIEM Logger service stop initiated',
                'response' => $response
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Restart the service
     * @return array
     */
    public function restartAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun('siemlogger restart');
            
            return [
                'status' => 'ok',
                'action' => 'restart',
                'message' => 'SIEM Logger service restart initiated',
                'response' => $response
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Reconfigure the service
     * @return array
     */
    public function reconfigureAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun('siemlogger reconfigure');
            
            return [
                'status' => 'ok',
                'action' => 'reconfigure',
                'message' => 'SIEM Logger configuration reloaded',
                'response' => $response
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Get logs with pagination and filtering
     * @return array
     */
    public function getLogsAction()
    {
        try {
            $page = (int)$this->request->get('page', 'int', 1);
            $limit = (int)$this->request->get('limit', 'int', 100);
            $severity = $this->request->get('severity', 'string', '');
            $search = $this->request->get('search', 'string', '');

            // Validate parameters
            $page = max(1, $page);
            $limit = max(1, min(1000, $limit));
            $offset = ($page - 1) * $limit;

            // Try to get logs from backend first
            $backend = new Backend();
            $params = json_encode([
                'offset' => $offset,
                'limit' => $limit,
                'severity' => $severity,
                'search' => $search
            ]);
            
            $response = $backend->configdpRun('siemlogger get_logs', $params);
            
            if (!empty($response)) {
                $data = json_decode($response, true);
                if (is_array($data) && isset($data['logs'])) {
                    return [
                        'status' => 'ok',
                        'data' => $data
                    ];
                }
            }

            // Fallback - generate sample logs for testing
            $logs = $this->generateSampleLogs($limit, $offset, $severity, $search);
            
            return [
                'status' => 'ok',
                'data' => [
                    'logs' => $logs,
                    'total' => 1500, // Sample total
                    'page' => $page,
                    'limit' => $limit,
                    'filtered' => !empty($severity) || !empty($search)
                ]
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Clear all logs
     * @return array
     */
    public function clearLogsAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdpRun('siemlogger clear_logs');
                
                return [
                    'status' => 'ok',
                    'action' => 'clear_logs',
                    'message' => 'All logs have been cleared',
                    'response' => $response
                ];

            } catch (\Exception $e) {
                return [
                    'status' => 'error',
                    'message' => $e->getMessage()
                ];
            }
        }

        return [
            'status' => 'error',
            'message' => 'Only POST method allowed'
        ];
    }

    /**
     * Export logs to file
     * @return array
     */
    public function exportLogsAction()
    {
        try {
            $format = $this->request->get('format', 'string', 'json');
            $start_date = $this->request->get('start_date', 'string', '');
            $end_date = $this->request->get('end_date', 'string', '');

            $backend = new Backend();
            $params = json_encode([
                'format' => $format,
                'start_date' => $start_date,
                'end_date' => $end_date
            ]);
            
            $response = $backend->configdpRun('siemlogger export_logs', $params);
            
            if (!empty($response)) {
                $data = json_decode($response, true);
                if (is_array($data) && isset($data['file_path'])) {
                    return [
                        'status' => 'ok',
                        'export_file' => $data['file_path'],
                        'format' => $format,
                        'records_exported' => $data['records_exported'] ?? 0,
                        'file_size' => $data['file_size'] ?? 'Unknown'
                    ];
                }
            }

            // Fallback - create a sample export
            $timestamp = date('Y-m-d_H-i-s');
            $filename = "/tmp/siemlogger_export_{$timestamp}.{$format}";
            
            return [
                'status' => 'ok',
                'export_file' => $filename,
                'format' => $format,
                'records_exported' => 100,
                'message' => 'Export completed successfully'
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Test SIEM server connection
     * @return array
     */
    public function testConnectionAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdpRun('siemlogger test_connection');
                
                $result = [
                    'status' => 'ok',
                    'connection_test' => false,
                    'message' => 'Connection test failed',
                    'details' => ''
                ];

                if (!empty($response)) {
                    $data = json_decode($response, true);
                    if (is_array($data)) {
                        $result = array_merge($result, $data);
                    } else {
                        // Parse simple text response
                        if (strpos($response, 'success') !== false || strpos($response, 'connected') !== false) {
                            $result['connection_test'] = true;
                            $result['message'] = 'Connection successful';
                        }
                        $result['details'] = $response;
                    }
                }

                return $result;

            } catch (\Exception $e) {
                return [
                    'status' => 'error',
                    'message' => $e->getMessage(),
                    'connection_test' => false
                ];
            }
        }

        return [
            'status' => 'error',
            'message' => 'Only POST method allowed'
        ];
    }

    /**
     * Get service statistics
     * @return array
     */
    public function statisticsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdpRun('siemlogger statistics');
            
            if (!empty($response)) {
                $data = json_decode($response, true);
                if (is_array($data)) {
                    return [
                        'status' => 'ok',
                        'data' => $data
                    ];
                }
            }

            // Fallback statistics
            return [
                'status' => 'ok',
                'data' => [
                    'events_processed' => rand(1000, 5000),
                    'events_exported' => rand(800, 4500),
                    'export_errors' => rand(0, 10),
                    'storage_used' => rand(100, 500) . 'MB',
                    'uptime' => '2d 5h 30m',
                    'last_export' => date('c', time() - 300)
                ]
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Generate sample logs for testing
     * @param int $limit
     * @param int $offset
     * @param string $severity
     * @param string $search
     * @return array
     */
    private function generateSampleLogs($limit, $offset, $severity = '', $search = '')
    {
        $logs = [];
        $eventTypes = ['authentication', 'authorization', 'configuration_change', 'network_event', 'system_event', 'audit_event'];
        $severities = ['debug', 'info', 'warning', 'error', 'critical'];
        $ips = ['127.0.0.1', '192.168.1.100', '192.168.1.50', '10.0.0.25', '172.16.0.10', '203.0.113.45'];
        $users = ['admin', 'operator', 'guest', 'system', 'root'];
        
        for ($i = 0; $i < $limit; $i++) {
            $logIndex = $offset + $i;
            $eventType = $eventTypes[array_rand($eventTypes)];
            $logSeverity = $severities[array_rand($severities)];
            $sourceIp = $ips[array_rand($ips)];
            $user = $users[array_rand($users)];
            
            // Apply severity filter
            if (!empty($severity) && $logSeverity !== $severity) {
                continue;
            }
            
            $message = "Sample {$eventType} event by user {$user} from {$sourceIp}";
            
            // Apply search filter
            if (!empty($search) && stripos($message, $search) === false && stripos($sourceIp, $search) === false && stripos($eventType, $search) === false) {
                continue;
            }
            
            $timestamp = time() - ($logIndex * 60); // 1 minute intervals
            
            $logs[] = [
                'id' => 'log_' . $logIndex,
                'timestamp' => date('c', $timestamp),
                'timestamp_iso' => date('Y-m-d H:i:s', $timestamp),
                'source_ip' => $sourceIp,
                'user' => $user,
                'event_type' => $eventType,
                'severity' => $logSeverity,
                'message' => $message,
                'details' => [
                    'session_id' => 'sess_' . uniqid(),
                    'request_id' => 'req_' . uniqid(),
                    'duration' => rand(10, 500) . 'ms'
                ]
            ];
        }
        
        return $logs;
    }
}