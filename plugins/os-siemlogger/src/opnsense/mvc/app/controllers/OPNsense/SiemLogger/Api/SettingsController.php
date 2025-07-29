<?php
/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
 * All rights reserved.
 */

namespace OPNsense\SiemLogger\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Backend;
use OPNsense\SiemLogger\SiemLogger;

/**
 * Class SettingsController - API controller for settings management
 * @package OPNsense\SiemLogger\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\SiemLogger\SiemLogger';
    protected static $internalModelName = 'siemlogger';

    /**
     * Get SIEM Logger configuration
     * @return array
     */
    public function getAction()
    {
        return $this->getBase('siemlogger', 'siemlogger');
    }

    /**
     * Set SIEM Logger configuration
     * @return array
     * @throws UserException
     */
    public function setAction()
    {
        return $this->setBase('siemlogger', 'siemlogger');
    }

    /**
     * Get system statistics
     * @return array
     */
    public function statsAction()
    {
        try {
            $mdl = new SiemLogger();
            $backend = new Backend();
            
            // Get basic stats
            $stats = [
                'total_events' => 0,
                'events_today' => 0,
                'export_errors' => 0,
                'disk_usage' => 0,
                'service_status' => 'unknown',
                'last_export' => null,
                'configuration_valid' => true,
                'recent_events' => []
            ];

            // Try to get real statistics from the backend/service
            try {
                $response = $backend->configdRun('siemlogger stats');
                if (!empty($response)) {
                    $backendStats = json_decode($response, true);
                    if (is_array($backendStats)) {
                        $stats = array_merge($stats, $backendStats);
                    }
                }
            } catch (\Exception $e) {
                // Backend not available, use defaults
                error_log("SIEM Logger stats backend error: " . $e->getMessage());
            }

            // Add configuration validation
            $issues = $mdl->validateConfiguration();
            $stats['configuration_valid'] = empty($issues);
            $stats['configuration_issues'] = $issues;

            return [
                'status' => 'ok',
                'data' => $stats
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Validate the current configuration
     * @return array
     */
    public function validateAction()
    {
        try {
            $mdl = new SiemLogger();
            $issues = $mdl->validateConfiguration();
            
            return [
                'status' => 'ok',
                'valid' => empty($issues),
                'issues' => $issues
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Get configuration summary
     * @return array
     */
    public function summaryAction()
    {
        try {
            $mdl = new SiemLogger();
            $summary = $mdl->getConfigurationSummary();
            
            return [
                'status' => 'ok',
                'data' => $summary
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }
}

/**
 * Class ServiceController - API controller for service management
 * @package OPNsense\SiemLogger\Api
 */
class ServiceController extends \OPNsense\Base\ApiControllerBase
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
                'enabled' => false
            ];

            if (!empty($response)) {
                $status = json_decode($response, true);
                if (is_array($status)) {
                    $result = array_merge($result, $status);
                } else {
                    // Fallback parsing for simple text response
                    $result['running'] = (strpos($response, 'running') !== false);
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
     * Get logs
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

            $backend = new Backend();
            $params = [
                'offset' => $offset,
                'limit' => $limit,
                'severity' => $severity,
                'search' => $search
            ];
            
            $response = $backend->configdRun('siemlogger logs', $params);
            
            if (!empty($response)) {
                $data = json_decode($response, true);
                if (is_array($data)) {
                    return [
                        'status' => 'ok',
                        'data' => $data
                    ];
                }
            }

            // Fallback if backend is not available
            return [
                'status' => 'ok',
                'data' => [
                    'logs' => [],
                    'total' => 0,
                    'page' => $page,
                    'limit' => $limit
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
     * Clear logs
     * @return array
     */
    public function clearLogsAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger clear_logs');
                
                return [
                    'status' => 'ok',
                    'action' => 'clear_logs',
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
     * Export logs
     * @return array
     */
    public function exportLogsAction()
    {
        try {
            $format = $this->request->get('format', 'string', 'json');
            $start_date = $this->request->get('start_date', 'string', '');
            $end_date = $this->request->get('end_date', 'string', '');

            $backend = new Backend();
            $params = [
                'format' => $format,
                'start_date' => $start_date,
                'end_date' => $end_date
            ];
            
            $response = $backend->configdRun('siemlogger export_logs', $params);
            
            if (!empty($response)) {
                $data = json_decode($response, true);
                if (is_array($data) && isset($data['file_path'])) {
                    // Return download information
                    return [
                        'status' => 'ok',
                        'export_file' => $data['file_path'],
                        'format' => $format,
                        'records_exported' => $data['records_exported'] ?? 0
                    ];
                }
            }

            return [
                'status' => 'error',
                'message' => 'Export failed or no data available'
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Test SIEM connection
     * @return array
     */
    public function testConnectionAction()
    {
        if ($this->request->isPost()) {
            try {
                $backend = new Backend();
                $response = $backend->configdRun('siemlogger test_connection');
                
                $result = [
                    'status' => 'ok',
                    'connection_test' => false,
                    'message' => 'Connection test failed'
                ];

                if (!empty($response)) {
                    $data = json_decode($response, true);
                    if (is_array($data)) {
                        $result = array_merge($result, $data);
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
}