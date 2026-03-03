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
use OPNsense\Core\Backend;

/**
 * Class StatisticsController
 *
 * Provides API endpoints for retrieving DeepInspector statistical data,
 * including security, traffic, blocking, industrial, and suspicious packet statistics.
 *
 * @package OPNsense\DeepInspector\Api
 */
class StatisticsController extends ApiControllerBase
{
    /**
     * Get comprehensive security statistics
     *
     * Reads from DeepInspector logs to build an aggregated view of
     * threats detected, blocked events, severity breakdown, and detection accuracy.
     *
     * @return array JSON-serializable response containing statistics data
     */
    public function getSecurityStatsAction()
    {
        $result = ["status" => "ok"];

        try {
            $timeRange = $this->request->get('timeRange') ?: 'last24h';
            $timeLimit = $this->calculateTimeLimit($timeRange);

            $alertsFile = '/var/log/deepinspector/alerts.log';
            $threatsFile = '/var/log/deepinspector/threats.log';
            $engineFile = '/var/log/deepinspector/engine.log';

            $securityStats = [
                'total_threats_detected' => 0,
                'threats_blocked' => 0,
                'threats_by_severity' => [
                    'critical' => 0,
                    'high' => 0,
                    'medium' => 0,
                    'low' => 0
                ],
                'threats_by_type' => [],
                'top_threat_sources' => [],
                'blocked_ips' => [],
                'malicious_patterns' => [],
                'industrial_threats' => 0,
                'zero_trust_violations' => 0,
                'false_positives' => 0,
                'detection_accuracy' => 0
            ];

            // Process alerts file
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $this->processAlertsForStats($alertsFile, $securityStats, $timeLimit);
            }

            // Process threats file
            if (file_exists($threatsFile) && is_readable($threatsFile)) {
                $this->processThreatsForStats($threatsFile, $securityStats, $timeLimit);
            }

            // Calculate detection accuracy
            $total_detections = $securityStats['total_threats_detected'] + $securityStats['false_positives'];
            if ($total_detections > 0) {
                $securityStats['detection_accuracy'] = round(
                    ($securityStats['total_threats_detected'] / $total_detections) * 100, 2
                );
            }

            $result['data'] = $securityStats;

        } catch (Exception $e) {
            error_log("DeepInspector: Error in getSecurityStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving security statistics";
            $result["data"] = $this->getEmptySecurityStats();
        }

        return $result;
    }
    
    /**
     * Get network traffic statistics
     *
     * Extracts protocol, bandwidth, packet size distribution, and connection
     * state data from DeepInspector logs.
     *
     * @return array JSON-serializable response containing traffic statistics
     */
    public function getTrafficStatsAction()
    {
        $result = ["status" => "ok"];

        try {
            $timeRange = $this->request->get('timeRange') ?: 'last24h';
            $timeLimit = $this->calculateTimeLimit($timeRange);

            $engineFile = '/var/log/deepinspector/engine.log';
            $latencyFile = '/var/log/deepinspector/latency.log';

            $trafficStats = [
                'total_packets_analyzed' => 0,
                'total_bytes_analyzed' => 0,
                'protocols_analyzed' => [],
                'traffic_by_hour' => [],
                'top_destinations' => [],
                'bandwidth_usage' => [],
                'packet_sizes' => [
                    'small' => 0,   // < 64 bytes
                    'medium' => 0,  // 64-1500 bytes
                    'large' => 0    // > 1500 bytes
                ],
                'connection_states' => [
                    'established' => 0,
                    'syn_sent' => 0,
                    'syn_recv' => 0,
                    'fin_wait' => 0,
                    'closed' => 0
                ]
            ];

            // Process engine log for traffic data
            if (file_exists($engineFile) && is_readable($engineFile)) {
                $this->processEngineLogForTraffic($engineFile, $trafficStats, $timeLimit);
            }

            // Process latency data
            if (file_exists($latencyFile) && is_readable($latencyFile)) {
                $this->processLatencyData($latencyFile, $trafficStats, $timeLimit);
            }

            $result['data'] = $trafficStats;

        } catch (Exception $e) {
            error_log("DeepInspector: Error in getTrafficStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving traffic statistics";
            $result["data"] = $this->getEmptyTrafficStats();
        }

        return $result;
    }
    
    /**
     * Get blocking statistics and actions taken
     *
     * Provides counts and historical data for blocked IPs and connections,
     * including time-based statistics and reasons for blocking.
     *
     * @return array JSON-serializable response with blocking metrics
     */
    public function getBlockingStatsAction()
    {
        $result = ["status" => "ok"];

        try {
            $timeRange = $this->request->get('timeRange') ?: 'last24h';
            $timeLimit = $this->calculateTimeLimit($timeRange);

            $backend = new Backend();

            $blockingStats = [
                'total_ips_blocked' => 0,
                'total_connections_blocked' => 0,
                'blocking_reasons' => [],
                'blocked_by_timeframe' => [
                    'last_hour' => 0,
                    'last_6h' => 0,
                    'last_24h' => 0,
                    'last_7d' => 0
                ],
                'top_blocked_sources' => [],
                'blocking_effectiveness' => 0,
                'whitelist_bypasses' => 0,
                'auto_unblocked' => 0
            ];

            // Get blocked IPs list
            $blockedResponse = $backend->configdpRun("deepinspector", array("list_blocked"));
            $blockedIPs = array_filter(explode("\n", trim($blockedResponse)));
            $blockingStats['total_ips_blocked'] = count($blockedIPs);

            // Process blocking history from alerts
            $alertsFile = '/var/log/deepinspector/alerts.log';
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $this->processBlockingHistory($alertsFile, $blockingStats, $timeLimit);
            }

            $result['data'] = $blockingStats;

        } catch (Exception $e) {
            error_log("DeepInspector: Error in getBlockingStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving blocking statistics";
            $result["data"] = $this->getEmptyBlockingStats();
        }

        return $result;
    }
    
    /**
     * Get industrial protocol statistics
     *
     * Focused on ICS/SCADA traffic and alerts, including protocol detection,
     * industrial threats, unauthorized commands, and protocol violations.
     *
     * @return array JSON-serializable response containing industrial statistics
     */
    public function getIndustrialStatsAction()
    {
        $result = ["status" => "ok"];

        try {
            $timeRange = $this->request->get('timeRange') ?: 'last24h';
            $timeLimit = $this->calculateTimeLimit($timeRange);

            $industrialStats = [
                'protocols_detected' => [
                    'modbus' => 0,
                    'dnp3' => 0,
                    'opcua' => 0,
                    'bacnet' => 0,
                    'ethernetip' => 0
                ],
                'industrial_threats' => 0,
                'scada_anomalies' => 0,
                'unauthorized_commands' => 0,
                'protocol_violations' => 0,
                'device_fingerprints' => [],
                'control_systems_identified' => [],
                'critical_operations_monitored' => 0
            ];

            // Process industrial-specific logs
            $alertsFile = '/var/log/deepinspector/alerts.log';
            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $this->processIndustrialData($alertsFile, $industrialStats, $timeLimit);
            }

            $result['data'] = $industrialStats;

        } catch (Exception $e) {
            error_log("DeepInspector: Error in getIndustrialStatsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving industrial statistics";
            $result["data"] = $this->getEmptyIndustrialStats();
        }

        return $result;
    }
    
    /**
     * Get suspicious packet analysis
     *
     * Filters recent alerts for packets deemed suspicious based on severity
     * and timeframe, returning enriched details for security analysis.
     *
     * @return array JSON-serializable response containing suspicious packet data
     */
    public function getSuspiciousPacketsAction()
    {
        $result = ["status" => "ok"];

        try {
            $timeFilter = $this->request->get('timeRange') ?: '24h';
            $severityFilter = $this->request->get('severity') ?: 'all';
            $limit = max(1, min(100, intval($this->request->get('limit') ?: 50)));

            $suspiciousPackets = [];
            $alertsFile = '/var/log/deepinspector/alerts.log';

            if (file_exists($alertsFile) && is_readable($alertsFile)) {
                $timeLimit = $this->calculateTimeLimit($timeFilter);
                $suspiciousPackets = $this->extractSuspiciousPackets($alertsFile, $timeLimit, $severityFilter, $limit);
            }

            $highRiskCount = 0;
            foreach ($suspiciousPackets as $packet) {
                if (in_array($packet['risk_level'], ['critical', 'high'])) {
                    $highRiskCount++;
                }
            }

            $result['data'] = [
                'packets' => $suspiciousPackets,
                'total_count' => count($suspiciousPackets),
                'high_risk_count' => $highRiskCount,
                'patterns_detected' => $this->getDetectedPatterns($suspiciousPackets)
            ];

        } catch (Exception $e) {
            error_log("DeepInspector: Error in getSuspiciousPacketsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving suspicious packets";
            $result["data"] = [
                'packets' => [],
                'total_count' => 0,
                'high_risk_count' => 0,
                'patterns_detected' => []
            ];
        }

        return $result;
    }

    /**
     * Get packet details by ID
     *
     * Retrieves detailed information about a specific packet from the alerts log.
     *
     * @return array JSON-serializable response containing packet details
     */
    public function getPacketDetailsAction()
    {
        $result = ["status" => "ok"];

        try {
            $packetId = $this->request->get('packetId');

            if (empty($packetId)) {
                $result["status"] = "error";
                $result["message"] = "Packet ID is required";
                return $result;
            }

            $alertsFile = '/var/log/deepinspector/alerts.log';

            if (!file_exists($alertsFile) || !is_readable($alertsFile)) {
                $result["status"] = "error";
                $result["message"] = "Alerts log not available";
                return $result;
            }

            $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!$lines) {
                $result["status"] = "error";
                $result["message"] = "No data available";
                return $result;
            }

            // Search for packet by ID
            foreach (array_reverse($lines) as $line) {
                $alert = json_decode(trim($line), true);
                if (!$alert) continue;

                $alertId = $alert['id'] ?? '';
                if ($alertId === $packetId) {
                    $result['data'] = [
                        'id' => $alert['id'] ?? $packetId,
                        'timestamp' => $alert['timestamp'] ?? date('c'),
                        'source_ip' => $alert['source_ip'] ?? 'Unknown',
                        'source_port' => $alert['source_port'] ?? null,
                        'destination_ip' => $alert['destination_ip'] ?? 'Unknown',
                        'destination_port' => $alert['destination_port'] ?? null,
                        'protocol' => $alert['protocol'] ?? 'Unknown',
                        'threat_type' => $alert['threat_type'] ?? 'Unknown',
                        'risk_level' => $alert['severity'] ?? 'medium',
                        'pattern_matched' => $alert['pattern'] ?? 'N/A',
                        'payload_size' => $alert['payload_size'] ?? 0,
                        'flags' => $alert['flags'] ?? [],
                        'industrial_context' => $alert['industrial_context'] ?? false,
                        'description' => $alert['description'] ?? 'Suspicious packet detected',
                        'action_taken' => $alert['action'] ?? 'logged',
                        'confidence_score' => $alert['confidence'] ?? 75
                    ];
                    return $result;
                }
            }

            $result["status"] = "error";
            $result["message"] = "Packet not found";

        } catch (Exception $e) {
            error_log("DeepInspector: Error in getPacketDetailsAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error retrieving packet details";
        }

        return $result;
    }

    /**
     * Export statistics report in various formats
     *
     * Generates and exports a comprehensive statistics report in PDF, CSV, or JSON format.
     *
     * @return array JSON-serializable response containing exported report data
     */
    public function exportReportAction()
    {
        $result = ["status" => "ok"];

        try {
            $format = $this->request->get('format') ?: 'json';
            $timeRange = $this->request->get('timeRange') ?: 'last24h';
            $reportType = $this->request->get('reportType') ?: 'comprehensive';

            // Collect all statistics data
            $reportData = [
                'generated_at' => date('Y-m-d H:i:s'),
                'time_range' => $timeRange,
                'report_type' => $reportType,
                'security_stats' => [],
                'traffic_stats' => [],
                'blocking_stats' => [],
                'industrial_stats' => []
            ];

            // Get security stats
            $securityResult = $this->getSecurityStatsAction();
            if ($securityResult['status'] === 'ok') {
                $reportData['security_stats'] = $securityResult['data'];
            }

            // Get blocking stats
            $blockingResult = $this->getBlockingStatsAction();
            if ($blockingResult['status'] === 'ok') {
                $reportData['blocking_stats'] = $blockingResult['data'];
            }

            // Get traffic stats if needed
            if (in_array($reportType, ['traffic', 'comprehensive'])) {
                $trafficResult = $this->getTrafficStatsAction();
                if ($trafficResult['status'] === 'ok') {
                    $reportData['traffic_stats'] = $trafficResult['data'];
                }
            }

            // Get industrial stats if needed
            if (in_array($reportType, ['industrial', 'comprehensive'])) {
                $industrialResult = $this->getIndustrialStatsAction();
                if ($industrialResult['status'] === 'ok') {
                    $reportData['industrial_stats'] = $industrialResult['data'];
                }
            }

            // Generate export based on format
            switch (strtolower($format)) {
                case 'json':
                    $result['data'] = [
                        'content' => json_encode($reportData, JSON_PRETTY_PRINT),
                        'filename' => 'deepinspector_report_' . date('Ymd_His') . '.json'
                    ];
                    break;

                case 'csv':
                    $csvContent = $this->generateCSVReport($reportData);
                    $result['data'] = [
                        'content' => $csvContent,
                        'filename' => 'deepinspector_report_' . date('Ymd_His') . '.csv'
                    ];
                    break;

                default:
                    $result["status"] = "error";
                    $result["message"] = "Unsupported export format";
            }

        } catch (Exception $e) {
            error_log("DeepInspector: Error in exportReportAction: " . $e->getMessage());
            $result["status"] = "error";
            $result["message"] = "Error exporting report";
        }

        return $result;
    }
    
    /**
     * Process alerts file for security statistics
     *
     * Iterates over recent alerts and aggregates metrics such as severity,
     * threat types, sources, industrial context, and patterns.
     *
     * @param string $alertsFile Path to the alerts log file
     * @param array  $stats Reference to security statistics array
     * @param int    $timeLimit UNIX timestamp lower bound (0 for no filter)
     * @return void
     */
    private function processAlertsForStats($alertsFile, &$stats, $timeLimit = 0)
    {
        $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;

        $threatTypes = [];
        $threatSources = [];
        $blockedIPs = [];
        $patterns = [];

        foreach (array_slice($lines, -1000) as $line) {
            $alert = json_decode(trim($line), true);
            if (!$alert) continue;

            // Apply time filter
            if ($timeLimit > 0) {
                $alertTime = strtotime($alert['timestamp'] ?? '');
                if ($alertTime === false || $alertTime < $timeLimit) continue;
            }

            $stats['total_threats_detected']++;

            // Count by severity
            $severity = $alert['severity'] ?? 'medium';
            if (isset($stats['threats_by_severity'][$severity])) {
                $stats['threats_by_severity'][$severity]++;
            }

            // Count by type
            $threatType = $alert['threat_type'] ?? 'unknown';
            $threatTypes[$threatType] = ($threatTypes[$threatType] ?? 0) + 1;

            // Track sources
            $sourceIP = $alert['source_ip'] ?? 'unknown';
            $threatSources[$sourceIP] = ($threatSources[$sourceIP] ?? 0) + 1;

            // Industrial context
            if ($alert['industrial_context'] ?? false) {
                $stats['industrial_threats']++;
            }

            // Zero trust violations
            if ($alert['zero_trust_triggered'] ?? false) {
                $stats['zero_trust_violations']++;
            }

            // Pattern tracking
            if (isset($alert['pattern'])) {
                $patterns[$alert['pattern']] = ($patterns[$alert['pattern']] ?? 0) + 1;
            }

            // Check if blocked
            if (isset($alert['action']) && $alert['action'] === 'blocked') {
                $stats['threats_blocked']++;
                $blockedIPs[$sourceIP] = true;
            }

            // False positives
            if (isset($alert['false_positive']) && $alert['false_positive'] === true) {
                $stats['false_positives']++;
            }
        }

        // Sort and limit results
        arsort($threatTypes);
        arsort($threatSources);
        arsort($patterns);

        $stats['threats_by_type'] = array_slice($threatTypes, 0, 10, true);
        $stats['top_threat_sources'] = array_slice($threatSources, 0, 10, true);
        $stats['blocked_ips'] = array_keys($blockedIPs);
        $stats['malicious_patterns'] = array_slice($patterns, 0, 10, true);
    }
    
    /**
     * Process threats file for additional security statistics
     *
     * Parses threats log to update false positives and refine threat types.
     *
     * @param string $threatsFile Path to the threats log file
     * @param array  $stats Reference to security statistics array
     * @param int    $timeLimit UNIX timestamp lower bound (0 for no filter)
     * @return void
     */
    private function processThreatsForStats($threatsFile, &$stats, $timeLimit = 0)
    {
        $lines = file($threatsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;

        foreach (array_slice($lines, -1000) as $line) {
            $threat = json_decode(trim($line), true);
            if (!$threat) continue;

            // Apply time filter
            if ($timeLimit > 0) {
                $threatTime = strtotime($threat['timestamp'] ?? '');
                if ($threatTime === false || $threatTime < $timeLimit) continue;
            }

            // Update false positives
            if (isset($threat['false_positive']) && $threat['false_positive'] === true) {
                $stats['false_positives']++;
            }

            // Update threat types
            $threatType = $threat['threat_type'] ?? 'unknown';
            $stats['threats_by_type'][$threatType] = ($stats['threats_by_type'][$threatType] ?? 0) + 1;

            // Update source IPs
            $sourceIP = $threat['source_ip'] ?? 'unknown';
            $stats['top_threat_sources'][$sourceIP] = ($stats['top_threat_sources'][$sourceIP] ?? 0) + 1;

            // Update patterns
            if (isset($threat['pattern'])) {
                $stats['malicious_patterns'][$threat['pattern']] = ($stats['malicious_patterns'][$threat['pattern']] ?? 0) + 1;
            }

            // Check if blocked
            if (isset($threat['action']) && $threat['action'] === 'blocked') {
                $stats['threats_blocked']++;
                $stats['blocked_ips'][$sourceIP] = true;
            }
        }

        // Sort and limit results
        arsort($stats['threats_by_type']);
        $stats['threats_by_type'] = array_slice($stats['threats_by_type'], 0, 10, true);
        arsort($stats['top_threat_sources']);
        $stats['top_threat_sources'] = array_slice($stats['top_threat_sources'], 0, 10, true);
        arsort($stats['malicious_patterns']);
        $stats['malicious_patterns'] = array_slice($stats['malicious_patterns'], 0, 10, true);
        $stats['blocked_ips'] = array_keys($stats['blocked_ips']);
    }

    /**
     * Process engine log for traffic statistics
     *
     * Parses engine log to extract packet counts, bytes, protocols, and connection states.
     *
     * @param string $engineFile Path to the engine log file
     * @param array  $stats Reference to traffic statistics array
     * @param int    $timeLimit UNIX timestamp lower bound (0 for no filter)
     * @return void
     */
    private function processEngineLogForTraffic($engineFile, &$stats, $timeLimit = 0)
    {
        $lines = file($engineFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;

        foreach (array_slice($lines, -1000) as $line) {
            $entry = json_decode(trim($line), true);
            if (!$entry) continue;

            // Apply time filter
            $timestamp = strtotime($entry['timestamp'] ?? '');
            if ($timeLimit > 0) {
                if ($timestamp === false || $timestamp < $timeLimit) continue;
            }

            // Update packet and byte counts
            $stats['total_packets_analyzed'] += $entry['packet_count'] ?? 1;
            $stats['total_bytes_analyzed'] += $entry['bytes'] ?? 0;

            // Update protocols
            $protocol = strtolower($entry['protocol'] ?? 'unknown');
            $stats['protocols_analyzed'][$protocol] = ($stats['protocols_analyzed'][$protocol] ?? 0) + 1;

            // Update traffic by hour
            if ($timestamp !== false) {
                $hour = date('Y-m-d H:00:00', $timestamp);
                $stats['traffic_by_hour'][$hour] = ($stats['traffic_by_hour'][$hour] ?? 0) + ($entry['bytes'] ?? 0);
            }

            // Update top destinations
            $destIP = $entry['destination_ip'] ?? 'unknown';
            $stats['top_destinations'][$destIP] = ($stats['top_destinations'][$destIP] ?? 0) + ($entry['bytes'] ?? 0);

            // Update packet sizes
            $packetSize = $entry['packet_size'] ?? 0;
            if ($packetSize < 64) {
                $stats['packet_sizes']['small']++;
            } elseif ($packetSize <= 1500) {
                $stats['packet_sizes']['medium']++;
            } else {
                $stats['packet_sizes']['large']++;
            }

            // Update connection states
            $state = strtolower($entry['connection_state'] ?? 'unknown');
            if (isset($stats['connection_states'][$state])) {
                $stats['connection_states'][$state]++;
            }
        }

        // Sort and limit results
        arsort($stats['protocols_analyzed']);
        $stats['protocols_analyzed'] = array_slice($stats['protocols_analyzed'], 0, 10, true);
        arsort($stats['traffic_by_hour']);
        $stats['traffic_by_hour'] = array_slice($stats['traffic_by_hour'], 0, 24, true);
        arsort($stats['top_destinations']);
        $stats['top_destinations'] = array_slice($stats['top_destinations'], 0, 10, true);
    }

    /**
     * Process latency data for traffic statistics
     *
     * Parses latency log to update bandwidth usage and latency metrics.
     *
     * @param string $latencyFile Path to the latency log file
     * @param array  $stats Reference to traffic statistics array
     * @param int    $timeLimit UNIX timestamp lower bound (0 for no filter)
     * @return void
     */
    private function processLatencyData($latencyFile, &$stats, $timeLimit = 0)
    {
        $lines = file($latencyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;

        foreach (array_slice($lines, -1000) as $line) {
            $entry = json_decode(trim($line), true);
            if (!$entry) continue;

            // Update bandwidth usage
            $timestamp = strtotime($entry['timestamp'] ?? '');
            if ($timestamp !== false) {
                // Apply time filter
                if ($timeLimit > 0 && $timestamp < $timeLimit) continue;

                $hour = date('Y-m-d H:00:00', $timestamp);
                $bandwidth = $entry['bandwidth_bps'] ?? 0;
                $stats['bandwidth_usage'][$hour] = ($stats['bandwidth_usage'][$hour] ?? 0) + $bandwidth;
            }
        }

        // Sort and limit bandwidth usage
        arsort($stats['bandwidth_usage']);
        $stats['bandwidth_usage'] = array_slice($stats['bandwidth_usage'], 0, 24, true);
    }

    /**
     * Process blocking history from alerts
     *
     * Parses alerts log to extract blocking reasons, timeframes, and sources.
     *
     * @param string $alertsFile Path to the alerts log file
     * @param array  $stats Reference to blocking statistics array
     * @param int    $timeLimit UNIX timestamp lower bound (0 for no filter)
     * @return void
     */
    private function processBlockingHistory($alertsFile, &$stats, $timeLimit = 0)
    {
        $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;

        $now = time();
        $timeframes = [
            'last_hour' => $now - 3600,
            'last_6h' => $now - (6 * 3600),
            'last_24h' => $now - 86400,
            'last_7d' => $now - (7 * 86400)
        ];

        foreach (array_slice($lines, -1000) as $line) {
            $alert = json_decode(trim($line), true);
            if (!$alert || !isset($alert['action']) || $alert['action'] !== 'blocked') continue;

            // Apply time filter
            $timestamp = strtotime($alert['timestamp'] ?? '');
            if ($timeLimit > 0) {
                if ($timestamp === false || $timestamp < $timeLimit) continue;
            }

            // Update blocking reasons
            $reason = $alert['reason'] ?? 'unknown';
            $stats['blocking_reasons'][$reason] = ($stats['blocking_reasons'][$reason] ?? 0) + 1;

            // Update blocked sources
            $sourceIP = $alert['source_ip'] ?? 'unknown';
            $stats['top_blocked_sources'][$sourceIP] = ($stats['top_blocked_sources'][$sourceIP] ?? 0) + 1;

            // Update timeframe counts
            if ($timestamp !== false) {
                foreach ($timeframes as $key => $limit) {
                    if ($timestamp >= $limit) {
                        $stats['blocked_by_timeframe'][$key]++;
                    }
                }
            }

            // Update connection blocked count
            $stats['total_connections_blocked']++;

            // Check for whitelist bypasses or auto-unblocked
            if (isset($alert['whitelist_bypass']) && $alert['whitelist_bypass'] === true) {
                $stats['whitelist_bypasses']++;
            }
            if (isset($alert['auto_unblocked']) && $alert['auto_unblocked'] === true) {
                $stats['auto_unblocked']++;
            }
        }

        // Calculate blocking effectiveness
        $totalBlocks = $stats['total_connections_blocked'];
        if ($totalBlocks > 0) {
            $stats['blocking_effectiveness'] = round(
                (($totalBlocks - $stats['whitelist_bypasses']) / $totalBlocks) * 100, 2
            );
        }

        // Sort and limit results
        arsort($stats['blocking_reasons']);
        $stats['blocking_reasons'] = array_slice($stats['blocking_reasons'], 0, 10, true);
        arsort($stats['top_blocked_sources']);
        $stats['top_blocked_sources'] = array_slice($stats['top_blocked_sources'], 0, 10, true);
    }

    /**
     * Process industrial-specific data from alerts
     *
     * Parses alerts log to extract ICS/SCADA-related metrics.
     *
     * @param string $alertsFile Path to the alerts log file
     * @param array  $stats Reference to industrial statistics array
     * @param int    $timeLimit UNIX timestamp lower bound (0 for no filter)
     * @return void
     */
    private function processIndustrialData($alertsFile, &$stats, $timeLimit = 0)
    {
        $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return;

        foreach (array_slice($lines, -1000) as $line) {
            $alert = json_decode(trim($line), true);
            if (!$alert || !isset($alert['industrial_context']) || !$alert['industrial_context']) continue;

            // Apply time filter
            if ($timeLimit > 0) {
                $alertTime = strtotime($alert['timestamp'] ?? '');
                if ($alertTime === false || $alertTime < $timeLimit) continue;
            }

            // Update protocol counts
            $protocol = strtolower($alert['protocol'] ?? 'unknown');
            if (isset($stats['protocols_detected'][$protocol])) {
                $stats['protocols_detected'][$protocol]++;
            }

            // Update threat and anomaly counts
            if (isset($alert['threat_type'])) {
                $stats['industrial_threats']++;
            }
            if (isset($alert['anomaly_detected']) && $alert['anomaly_detected'] === true) {
                $stats['scada_anomalies']++;
            }

            // Update unauthorized commands and protocol violations
            if (isset($alert['unauthorized_command']) && $alert['unauthorized_command'] === true) {
                $stats['unauthorized_commands']++;
            }
            if (isset($alert['protocol_violation']) && $alert['protocol_violation'] === true) {
                $stats['protocol_violations']++;
            }

            // Update device fingerprints
            if (isset($alert['device_fingerprint'])) {
                $fingerprint = $alert['device_fingerprint'];
                $stats['device_fingerprints'][$fingerprint] = ($stats['device_fingerprints'][$fingerprint] ?? 0) + 1;
            }

            // Update control systems
            if (isset($alert['control_system'])) {
                $system = $alert['control_system'];
                $stats['control_systems_identified'][$system] = ($stats['control_systems_identified'][$system] ?? 0) + 1;
            }

            // Update critical operations
            if (isset($alert['critical_operation']) && $alert['critical_operation'] === true) {
                $stats['critical_operations_monitored']++;
            }
        }

        // Sort and limit results
        arsort($stats['device_fingerprints']);
        $stats['device_fingerprints'] = array_slice($stats['device_fingerprints'], 0, 10, true);
        arsort($stats['control_systems_identified']);
        $stats['control_systems_identified'] = array_slice($stats['control_systems_identified'], 0, 10, true);
    }
    
    /**
     * Extract suspicious packets with details
     *
     * Scans alert log entries in reverse chronological order, applying
     * time and severity filters, and builds structured packet data.
     *
     * @param string $alertsFile Path to the alerts log file
     * @param int $timeLimit UNIX timestamp lower bound
     * @param string $severityFilter Severity filter ('critical', 'high', etc. or 'all')
     * @param int $limit Maximum number of packets to return
     * @return array List of suspicious packets with metadata
     */
    private function extractSuspiciousPackets($alertsFile, $timeLimit, $severityFilter, $limit)
    {
        $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) return [];
        
        $packets = [];
        
        foreach (array_reverse(array_slice($lines, -500)) as $line) {
            $alert = json_decode(trim($line), true);
            if (!$alert) continue;
            
            // Time filter
            if ($timeLimit > 0) {
                $alertTime = strtotime($alert['timestamp'] ?? '');
                if ($alertTime === false || $alertTime < $timeLimit) continue;
            }
            
            // Severity filter
            if ($severityFilter !== 'all') {
                $alertSeverity = $alert['severity'] ?? 'medium';
                if ($alertSeverity !== $severityFilter) continue;
            }
            
            $packets[] = [
                'id' => $alert['id'] ?? uniqid(),
                'timestamp' => $alert['timestamp'] ?? date('c'),
                'source_ip' => $alert['source_ip'] ?? 'Unknown',
                'source_port' => $alert['source_port'] ?? null,
                'destination_ip' => $alert['destination_ip'] ?? 'Unknown',
                'destination_port' => $alert['destination_port'] ?? null,
                'protocol' => $alert['protocol'] ?? 'Unknown',
                'threat_type' => $alert['threat_type'] ?? 'Unknown',
                'risk_level' => $alert['severity'] ?? 'medium',
                'pattern_matched' => $alert['pattern'] ?? 'N/A',
                'payload_size' => $alert['payload_size'] ?? 0,
                'flags' => $alert['flags'] ?? [],
                'industrial_context' => $alert['industrial_context'] ?? false,
                'description' => $alert['description'] ?? 'Suspicious packet detected',
                'action_taken' => $alert['action'] ?? 'logged',
                'confidence_score' => $alert['confidence'] ?? 75
            ];
            
            if (count($packets) >= $limit) break;
        }
        
        return $packets;
    }
    
    /**
     * Get detected patterns summary
     *
     * Aggregates and counts recurring detection patterns among suspicious packets.
     *
     * @param array $packets List of suspicious packets
     * @return array Top 5 detected patterns with counts
     */
    private function getDetectedPatterns($packets)
    {
        $patterns = [];
        
        foreach ($packets as $packet) {
            $pattern = $packet['pattern_matched'];
            if ($pattern !== 'N/A') {
                $patterns[$pattern] = ($patterns[$pattern] ?? 0) + 1;
            }
        }
        
        arsort($patterns);
        return array_slice($patterns, 0, 5, true);
    }
    
    /**
     * Calculate time limit based on filter
     *
     * Converts relative filter values (e.g. 'today', '7d', '15m') to UNIX timestamps.
     * @param string $timeFilter Time filter string
     * @return int Corresponding UNIX timestamp cutoff
     */
    private function calculateTimeLimit($timeFilter)
    {
        $now = time();

        switch (strtolower($timeFilter)) {
            case 'last15m':
                return $now - (15 * 60);      
            case 'last30m':
                return $now - (30 * 60);     
            case 'last1h':
                return $now - 3600;           
            case 'last24h':
                return $now - 86400;    
            case 'last7d':
                return $now - (7 * 86400);
            case 'last30d':
                return $now - (30 * 86400);    
            case 'last90d':
                return $now - (90 * 86400);    
            case 'last1y':
                return $now - (365 * 86400);  
            case 'today':
                return strtotime('today midnight'); 
            case 'thisweek':
                return strtotime('monday this week midnight');
            default:
                return 0;
        }
    }
    
    /**
     * Get empty security stats structure
     *
     * @return array Empty security stats template
     */
    private function getEmptySecurityStats()
    {
        return [
            'total_threats_detected' => 0,
            'threats_blocked' => 0,
            'threats_by_severity' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
            'threats_by_type' => [],
            'top_threat_sources' => [],
            'blocked_ips' => [],
            'malicious_patterns' => [],
            'industrial_threats' => 0,
            'zero_trust_violations' => 0,
            'false_positives' => 0,
            'detection_accuracy' => 0
        ];
    }
    
    /**
     * Get empty traffic stats structure
     *
     * @return array Empty traffic stats template
     */
    private function getEmptyTrafficStats()
    {
        return [
            'total_packets_analyzed' => 0,
            'total_bytes_analyzed' => 0,
            'protocols_analyzed' => [],
            'traffic_by_hour' => [],
            'top_destinations' => [],
            'bandwidth_usage' => [],
            'packet_sizes' => ['small' => 0, 'medium' => 0, 'large' => 0],
            'connection_states' => ['established' => 0, 'syn_sent' => 0, 'syn_recv' => 0, 'fin_wait' => 0, 'closed' => 0]
        ];
    }
    
    /**
     * Get empty blocking stats structure
     *
     * @return array Empty blocking stats template
     */
    private function getEmptyBlockingStats()
    {
        return [
            'total_ips_blocked' => 0,
            'total_connections_blocked' => 0,
            'blocking_reasons' => [],
            'blocked_by_timeframe' => ['last_hour' => 0, 'last_6h' => 0, 'last_24h' => 0, 'last_7d' => 0],
            'top_blocked_sources' => [],
            'blocking_effectiveness' => 0,
            'whitelist_bypasses' => 0,
            'auto_unblocked' => 0
        ];
    }
    
    /**
     * Get empty industrial stats structure
     *
     * @return array Empty industrial stats template
     */
    private function getEmptyIndustrialStats()
    {
        return [
            'protocols_detected' => ['modbus' => 0, 'dnp3' => 0, 'opcua' => 0, 'bacnet' => 0, 'ethernetip' => 0],
            'industrial_threats' => 0,
            'scada_anomalies' => 0,
            'unauthorized_commands' => 0,
            'protocol_violations' => 0,
            'device_fingerprints' => [],
            'control_systems_identified' => [],
            'critical_operations_monitored' => 0
        ];
    }

    /**
     * Generate CSV report from statistics data
     *
     * Converts collected statistics into CSV format for export.
     *
     * @param array $reportData The statistics data to convert
     * @return string CSV-formatted report content
     */
    private function generateCSVReport($reportData)
    {
        $csv = [];

        // Header
        $csv[] = "DeepInspector Statistics Report";
        $csv[] = "Generated: " . $reportData['generated_at'];
        $csv[] = "Time Range: " . $reportData['time_range'];
        $csv[] = "Report Type: " . $reportData['report_type'];
        $csv[] = "";

        // Security Statistics
        if (!empty($reportData['security_stats'])) {
            $csv[] = "SECURITY STATISTICS";
            $csv[] = "Metric,Value";
            $stats = $reportData['security_stats'];
            $csv[] = "Total Threats Detected," . ($stats['total_threats_detected'] ?? 0);
            $csv[] = "Threats Blocked," . ($stats['threats_blocked'] ?? 0);
            $csv[] = "Detection Accuracy," . ($stats['detection_accuracy'] ?? 0) . "%";
            $csv[] = "Industrial Threats," . ($stats['industrial_threats'] ?? 0);
            $csv[] = "Zero Trust Violations," . ($stats['zero_trust_violations'] ?? 0);
            $csv[] = "False Positives," . ($stats['false_positives'] ?? 0);
            $csv[] = "";

            // Severity breakdown
            if (!empty($stats['threats_by_severity'])) {
                $csv[] = "Threats by Severity";
                $csv[] = "Severity,Count";
                foreach ($stats['threats_by_severity'] as $severity => $count) {
                    $csv[] = ucfirst($severity) . "," . $count;
                }
                $csv[] = "";
            }

            // Threat types
            if (!empty($stats['threats_by_type'])) {
                $csv[] = "Threats by Type";
                $csv[] = "Type,Count";
                foreach ($stats['threats_by_type'] as $type => $count) {
                    $csv[] = $type . "," . $count;
                }
                $csv[] = "";
            }
        }

        // Blocking Statistics
        if (!empty($reportData['blocking_stats'])) {
            $csv[] = "BLOCKING STATISTICS";
            $csv[] = "Metric,Value";
            $stats = $reportData['blocking_stats'];
            $csv[] = "Total IPs Blocked," . ($stats['total_ips_blocked'] ?? 0);
            $csv[] = "Total Connections Blocked," . ($stats['total_connections_blocked'] ?? 0);
            $csv[] = "Blocking Effectiveness," . ($stats['blocking_effectiveness'] ?? 0) . "%";
            $csv[] = "Auto Unblocked," . ($stats['auto_unblocked'] ?? 0);
            $csv[] = "Whitelist Bypasses," . ($stats['whitelist_bypasses'] ?? 0);
            $csv[] = "";
        }

        // Traffic Statistics
        if (!empty($reportData['traffic_stats'])) {
            $csv[] = "TRAFFIC STATISTICS";
            $csv[] = "Metric,Value";
            $stats = $reportData['traffic_stats'];
            $csv[] = "Total Packets Analyzed," . ($stats['total_packets_analyzed'] ?? 0);
            $csv[] = "Total Bytes Analyzed," . ($stats['total_bytes_analyzed'] ?? 0);
            $csv[] = "";
        }

        // Industrial Statistics
        if (!empty($reportData['industrial_stats'])) {
            $csv[] = "INDUSTRIAL STATISTICS";
            $csv[] = "Metric,Value";
            $stats = $reportData['industrial_stats'];
            $csv[] = "Industrial Threats," . ($stats['industrial_threats'] ?? 0);
            $csv[] = "SCADA Anomalies," . ($stats['scada_anomalies'] ?? 0);
            $csv[] = "Unauthorized Commands," . ($stats['unauthorized_commands'] ?? 0);
            $csv[] = "Protocol Violations," . ($stats['protocol_violations'] ?? 0);
            $csv[] = "";

            // Protocol breakdown
            if (!empty($stats['protocols_detected'])) {
                $csv[] = "Protocols Detected";
                $csv[] = "Protocol,Count";
                foreach ($stats['protocols_detected'] as $protocol => $count) {
                    $csv[] = strtoupper($protocol) . "," . $count;
                }
                $csv[] = "";
            }
        }

        return implode("\n", $csv);
    }

    /**
     * GeoIP lookup for a list of IP addresses
     *
     * GET /api/deepinspector/statistics/geoip?ips=1.2.3.4,5.6.7.8
     *
     * - Filters out private/loopback IPs (returns null for those)
     * - Uses a 24-hour file cache at /tmp/deepinspector_geoip_cache.json
     * - Calls ip-api.com/batch for uncached IPs (max 100 per request)
     * - Handles HTTP 429 rate limiting gracefully
     *
     * @return array { status, data: { ip: {lat,lon,country,countryCode}|null }, rate_limited }
     */
    public function geoipAction()
    {
        $ipsParam = $this->request->get('ips') ?: '';
        if (empty($ipsParam)) {
            return ["status" => "ok", "data" => [], "rate_limited" => false];
        }

        $requestedIPs = array_unique(array_filter(
            array_map('trim', explode(',', $ipsParam)),
            function ($ip) { return filter_var($ip, FILTER_VALIDATE_IP) !== false; }
        ));

        // Cap at 100
        $requestedIPs = array_slice($requestedIPs, 0, 100);

        if (empty($requestedIPs)) {
            return ["status" => "ok", "data" => [], "rate_limited" => false];
        }

        $cacheFile = '/tmp/deepinspector_geoip_cache.json';
        $cacheTTL  = 86400; // 24 hours
        $now       = time();

        // Load cache
        $cache = [];
        if (file_exists($cacheFile) && is_readable($cacheFile)) {
            $raw = file_get_contents($cacheFile);
            if ($raw !== false) {
                $decoded = json_decode($raw, true);
                if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                    $cache = $decoded;
                }
            }
        }

        $result      = [];
        $toFetch     = [];
        $rateLimited = false;

        foreach ($requestedIPs as $ip) {
            if ($this->isPrivateIP($ip)) {
                $result[$ip] = null;
                continue;
            }

            if (isset($cache[$ip]) && ($now - ($cache[$ip]['cached_at'] ?? 0)) < $cacheTTL) {
                $result[$ip] = $cache[$ip]['data'];
            } else {
                $toFetch[] = $ip;
            }
        }

        if (!empty($toFetch)) {
            $batchPayload = [];
            foreach ($toFetch as $ip) {
                $batchPayload[] = ["query" => $ip, "fields" => "status,message,country,countryCode,lat,lon,query"];
            }

            $ch = curl_init('http://ip-api.com/batch?fields=status,message,country,countryCode,lat,lon,query');
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => json_encode($batchPayload),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json']
            ]);

            $response   = curl_exec($ch);
            $httpCode   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 429) {
                $rateLimited = true;
                // Return whatever we have from cache for uncached IPs
                foreach ($toFetch as $ip) {
                    $result[$ip] = isset($cache[$ip]) ? $cache[$ip]['data'] : null;
                }
            } elseif ($response !== false && $httpCode === 200) {
                $geoData = json_decode($response, true);
                if (json_last_error() === JSON_ERROR_NONE && is_array($geoData)) {
                    foreach ($geoData as $entry) {
                        $ip = $entry['query'] ?? null;
                        if (!$ip) continue;

                        if (($entry['status'] ?? '') === 'success') {
                            $data = [
                                'lat'         => $entry['lat'],
                                'lon'         => $entry['lon'],
                                'country'     => $entry['country'] ?? '',
                                'countryCode' => $entry['countryCode'] ?? ''
                            ];
                            $result[$ip]  = $data;
                            $cache[$ip]   = ['data' => $data, 'cached_at' => $now];
                        } else {
                            $result[$ip] = null;
                        }
                    }

                    // Save updated cache
                    @file_put_contents($cacheFile, json_encode($cache));
                }
            } else {
                // Network error — return nulls for uncached IPs
                foreach ($toFetch as $ip) {
                    $result[$ip] = isset($cache[$ip]) ? $cache[$ip]['data'] : null;
                }
            }
        }

        return [
            "status"       => "ok",
            "data"         => $result,
            "rate_limited" => $rateLimited
        ];
    }

    /**
     * Checks whether an IP is private, loopback, or link-local
     *
     * @param string $ip
     * @return bool
     */
    private function isPrivateIP($ip)
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
}