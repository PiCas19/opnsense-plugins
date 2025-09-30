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

use OPNsense\Base\ApiControllerBase;
use OPNsense\ValidationCore\ValidationEngine;
use OPNsense\Base\Messages\MessageCollection;
use OPNsense\Base\Messages\Message;

/**
 * Class AlertsController
 * @package OPNsense\DeepInspector\Api
 */
class AlertsController extends ApiControllerBase
{
    /**
     * Validation engine instance for orchestrating validation logic
     *
     * @var ValidationEngine Centralized validation coordinator
     */
    private $validationEngine;

    /**
     * Initialize the AlertsController with validation engine
     *
     * Sets up the controller with the OPNsense framework integration and
     * initializes the validation engine for validating and filtering API request parameters.
     */
    public function __construct()
    {
        parent::__construct();
        $this->validationEngine = new ValidationEngine();
    }

    /**
     * Get alerts list with filtering and pagination
     * @return array alerts list
     */
    public function listAction()
    {
        $result = ["status" => "ok"];

        try {
            // Extract filter parameters
            $filterData = $this->extractFilterData();
            
            // Validate filter parameters
            $messages = $this->performValidation($filterData, false, 'alerts');
            if ($messages->hasErrors()) {
                $result["status"] = "error";
                $result["message"] = "Validation failed: " . implode("; ", array_map('strval', $messages->getMessages()));
                $result["data"] = [];
                $result["pagination"] = [
                    'page' => 1,
                    'limit' => 50,
                    'total' => 0,
                    'pages' => 0
                ];
                return $result;
            }

            $alertsFile = '/var/log/deepinspector/alerts.log';
            $filteredAlerts = [];

            // Apply validated parameters
            $page = max(1, (int)$filterData['filters']['page']);
            $limit = max(1, min(500, (int)$filterData['filters']['limit'])); // Limit between 1-500

            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $fileContent = file_get_contents($alertsFile);
                if ($fileContent !== false) {
                    $lines = explode("\n", trim($fileContent));
                    $rawAlerts = [];

                    // Parse alerts
                    foreach ($lines as $lineNumber => $line) {
                        $line = trim($line);
                        if (empty($line)) continue;

                        try {
                            $alert = json_decode($line, true);
                            if (json_last_error() !== JSON_ERROR_NONE) {
                                error_log("DeepInspector: JSON decode error on line " . ($lineNumber + 1) . ": " . json_last_error_msg());
                                continue;
                            }

                            if ($alert && is_array($alert)) {
                                $rawAlerts[] = [
                                    'id' => $alert['id'] ?? uniqid(),
                                    'timestamp' => $alert['timestamp'] ?? date('c'),
                                    'source_ip' => $alert['source_ip'] ?? 'Unknown',
                                    'source_port' => $alert['source_port'] ?? null,
                                    'destination_ip' => $alert['destination_ip'] ?? 'Unknown',
                                    'destination_port' => $alert['destination_port'] ?? null,
                                    'threat_type' => $alert['threat_type'] ?? 'Unknown',
                                    'severity' => $alert['severity'] ?? 'medium',
                                    'protocol' => $alert['protocol'] ?? 'Unknown',
                                    'description' => $alert['description'] ?? 'No description',
                                    'industrial_context' => $alert['industrial_context'] ?? false,
                                    'zero_trust_triggered' => $alert['zero_trust_triggered'] ?? false,
                                    'detection_method' => $alert['detection_method'] ?? 'Unknown'
                                ];
                            }
                        } catch (\Exception $e) {
                            error_log("DeepInspector: Error processing alert line " . ($lineNumber + 1) . ": " . $e->getMessage());
                            continue;
                        }
                    }

                    // Filter alerts using ValidationEngine
                    $filterData['alerts'] = $rawAlerts;
                    $filteredMessages = $this->validationEngine->validate($filterData, false, 'alerts');

                    if ($filteredMessages->hasErrors()) {
                        $result["status"] = "error";
                        $result["message"] = "Alert filtering failed: " . implode("; ", array_map('strval', $filteredMessages->getMessages()));
                        $result["data"] = [];
                        $result["pagination"] = [
                            'page' => 1,
                            'limit' => $limit,
                            'total' => 0,
                            'pages' => 0
                        ];
                        return $result;
                    }

                    // Assume AlertFilterValidator stores filtered alerts in filterData['filtered_alerts']
                    $filteredAlerts = $filterData['filtered_alerts'] ?? [];

                    // Sort by timestamp (newest first)
                    usort($filteredAlerts, function($a, $b) {
                        $timeA = strtotime($a['timestamp']);
                        $timeB = strtotime($b['timestamp']);
                        return $timeB - $timeA;
                    });

                    // Apply pagination
                    $totalAlerts = count($filteredAlerts);
                    $offset = ($page - 1) * $limit;
                    $paginatedAlerts = array_slice($filteredAlerts, $offset, $limit);

                    $result["data"] = $paginatedAlerts;
                    $result["pagination"] = [
                        'page' => $page,
                        'limit' => $limit,
                        'total' => $totalAlerts,
                        'pages' => max(1, ceil($totalAlerts / $limit))
                    ];
                } else {
                    error_log("DeepInspector: Could not read alerts file: $alertsFile");
                    $result["data"] = [];
                    $result["pagination"] = [
                        'page' => 1,
                        'limit' => $limit,
                        'total' => 0,
                        'pages' => 0
                    ];
                    $result["message"] = "Could not read alerts file";
                }
            } else {
                $result["data"] = [];
                $result["pagination"] = [
                    'page' => 1,
                    'limit' => $limit,
                    'total' => 0,
                    'pages' => 0
                ];
                if (!file_exists($alertsFile)) {
                    $result["message"] = "Alerts file does not exist";
                } else {
                    $result["message"] = "Alerts file is not readable";
                }
            }

        } catch (\Exception $e) {
            error_log("DeepInspector: Error in listAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving alerts: " . $e->getMessage();
            $result["data"] = [];
            $result["pagination"] = [
                'page' => 1,
                'limit' => 50,
                'total' => 0,
                'pages' => 0
            ];
        } catch (\Error $e) {
            error_log("DeepInspector: Fatal error in listAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Fatal error retrieving alerts";
            $result["data"] = [];
            $result["pagination"] = [
                'page' => 1,
                'limit' => 50,
                'total' => 0,
                'pages' => 0
            ];
        }

        return $result;
    }

    /**
     * Perform validation of filter parameters using ValidationCore
     *
     * Delegates validation to the validation engine with the specified scope.
     * This method ensures that filter parameters are validated consistently
     * with the OPNsense validation framework.
     *
     * @param array $filterData Filter data to validate
     * @param bool $validateFullModel Whether to perform full validation
     * @param string $scope Validation scope to control validator selection
     * @return MessageCollection Validation results
     */
    private function performValidation(array $filterData, bool $validateFullModel = false, string $scope = 'alerts'): MessageCollection
    {
        $messages = new MessageCollection();

        try {
            // Execute validation engine with specified scope
            $validationMessages = $this->validationEngine->validate($filterData, $validateFullModel, $scope);

            // Merge validation results
            foreach ($validationMessages as $validationMessage) {
                $messages->appendMessage($validationMessage);
            }

        } catch (\Exception $e) {
            // Handle validation engine errors
            error_log("DeepInspector validation engine error: " . $e->getMessage());
            $messages->appendMessage(new Message(
                gettext('Internal validation error occurred. Please check filter parameters and try again.'),
                'filters.validation_engine'
            ));
        }

        return $messages;
    }

    /**
     * Extract filter parameters from request for validation
     *
     * Transforms request parameters into a structured array suitable for
     * validation and filtering by the ValidationEngine.
     *
     * @return array Structured filter data
     */
    private function extractFilterData(): array
    {
        return [
            'filters' => [
                'severity' => (string)$this->request->get('severity', 'all'),
                'type' => (string)$this->request->get('type', 'all'),
                'time' => (string)$this->request->get('time', '24h'),
                'source' => (string)$this->request->get('source', ''),
                'page' => (string)$this->request->get('page', '1'),
                'limit' => (string)$this->request->get('limit', '50')
            ]
        ];
    }

    /**
     * Get threat details by ID
     * @param string|null $threatId threat identifier
     * @return array threat details
     */
    public function threatDetailsAction($threatId = null)
    {
        $result = ["status" => "failed"];

        if (empty($threatId)) {
            $threatId = $this->request->get('id');
        }

        if (empty($threatId)) {
            $result["message"] = "Threat ID is required";
            return $result;
        }

        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';

            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $fileContent = file_get_contents($alertsFile);
                if ($fileContent !== false) {
                    $lines = explode("\n", trim($fileContent));

                    foreach ($lines as $line) {
                        $line = trim($line);
                        if (empty($line)) continue;

                        try {
                            $alert = json_decode($line, true);
                            if (json_last_error() === JSON_ERROR_NONE && $alert && isset($alert['id']) && $alert['id'] === $threatId) {
                                $result["status"] = "ok";
                                $result["data"] = [
                                    'id' => $alert['id'],
                                    'threat_id' => $alert['id'],
                                    'timestamp' => $alert['timestamp'],
                                    'source_ip' => $alert['source_ip'],
                                    'source_port' => $alert['source_port'] ?? null,
                                    'destination_ip' => $alert['destination_ip'],
                                    'destination_port' => $alert['destination_port'] ?? null,
                                    'threat_type' => $alert['threat_type'],
                                    'severity' => $alert['severity'],
                                    'protocol' => $alert['protocol'],
                                    'description' => $alert['description'],
                                    'detection_method' => $alert['detection_method'] ?? 'Unknown',
                                    'method' => $alert['detection_method'] ?? 'Unknown',
                                    'pattern' => $alert['pattern'] ?? 'N/A',
                                    'industrial_context' => $alert['industrial_context'] ?? false,
                                    'industrial_protocol' => $alert['industrial_protocol'] ?? null,
                                    'zero_trust_triggered' => $alert['zero_trust_triggered'] ?? false,
                                    'status' => 'active',
                                    'first_seen' => $alert['timestamp'],
                                    'last_seen' => $alert['timestamp'],
                                    'interface' => $alert['interface'] ?? null,
                                    'packet_data' => $alert['packet_data'] ?? null
                                ];
                                break;
                            }
                        } catch (\Exception $e) {
                            continue; // Skip malformed lines
                        }
                    }
                }
            }

            if ($result["status"] === "failed") {
                $result["message"] = "Threat not found";
            }

        } catch (\Exception $e) {
            error_log("DeepInspector: Error in threatDetailsAction: " . $e->getMessage());
            $result["message"] = "Error retrieving threat details: " . $e->getMessage();
        }

        return $result;
    }

    /**
     * Get all alerts with pagination (alias for listAction)
     * @return array alerts list
     */
    public function getAllAction()
    {
        return $this->listAction();
    }

    /**
     * Get alert statistics
     * @return array alert statistics
     */
    public function getStatsAction()
    {
        $result = ["status" => "ok"];

        try {
            $alertsFile = '/var/log/deepinspector/alerts.log';
            $stats = [
                'total_alerts' => 0,
                'critical_alerts' => 0,
                'high_alerts' => 0,
                'medium_alerts' => 0,
                'low_alerts' => 0,
                'industrial_alerts' => 0,
                'threat_types' => [],
                'top_sources' => [],
                'hourly_distribution' => []
            ];

            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $fileContent = file_get_contents($alertsFile);
                if ($fileContent !== false) {
                    $lines = explode("\n", trim($fileContent));
                    $threatTypes = [];
                    $sources = [];
                    $hourly = [];

                    foreach ($lines as $line) {
                        $line = trim($line);
                        if (empty($line)) continue;

                        try {
                            $alert = json_decode($line, true);
                            if (json_last_error() === JSON_ERROR_NONE && $alert) {
                                $stats['total_alerts']++;

                                // Count by severity
                                $severity = $alert['severity'] ?? 'medium';
                                switch ($severity) {
                                    case 'critical':
                                        $stats['critical_alerts']++;
                                        break;
                                    case 'high':
                                        $stats['high_alerts']++;
                                        break;
                                    case 'medium':
                                        $stats['medium_alerts']++;
                                        break;
                                    case 'low':
                                        $stats['low_alerts']++;
                                        break;
                                }

                                // Count industrial alerts
                                if ($alert['industrial_context'] ?? false) {
                                    $stats['industrial_alerts']++;
                                }

                                // Count threat types
                                $threatType = $alert['threat_type'] ?? 'unknown';
                                $threatTypes[$threatType] = ($threatTypes[$threatType] ?? 0) + 1;

                                // Count source IPs
                                $sourceIP = $alert['source_ip'] ?? 'unknown';
                                $sources[$sourceIP] = ($sources[$sourceIP] ?? 0) + 1;

                                // Count by hour
                                $timestamp = $alert['timestamp'] ?? date('c');
                                $hour = date('H', strtotime($timestamp));
                                $hourly[$hour] = ($hourly[$hour] ?? 0) + 1;
                            }
                        } catch (\Exception $e) {
                            continue; // Skip malformed lines
                        }
                    }

                    // Sort and limit results
                    arsort($threatTypes);
                    arsort($sources);
                    ksort($hourly);

                    $stats['threat_types'] = array_slice($threatTypes, 0, 10, true);
                    $stats['top_sources'] = array_slice($sources, 0, 10, true);
                    $stats['hourly_distribution'] = $hourly;
                }
            }

            $result["data"] = $stats;

        } catch (\Exception $e) {
            error_log("DeepInspector: Error in getStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving alert statistics: " . $e->getMessage();
            $result["data"] = $stats; // Return empty stats structure
        }

        return $result;
    }
}