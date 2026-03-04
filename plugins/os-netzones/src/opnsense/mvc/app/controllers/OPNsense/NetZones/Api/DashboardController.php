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

use OPNsense\Base\ApiControllerBase;
use OPNsense\NetZones\NetZones;

/**
 * Class DashboardController
 * @package OPNsense\NetZones\Api
 */
class DashboardController extends ApiControllerBase
{
    private const DECISIONS_LOG = '/var/log/netzones_decisions.log';
    private const SERVICE_LOG = '/var/log/netzones.log';
    private const STATS_FILE = '/var/run/netzones_stats.json';
    private const SOCKET_PATH = '/var/run/netzones.sock';

    /**
     * Get dashboard statistics
     * @return array
     */
    public function statsAction()
    {
        $this->sessionClose();
        
        try {
            // Load service statistics if available
            $serviceStats = $this->loadServiceStats();
            
            // Load activity statistics from log
            $activityStats = $this->calculateActivityStats();
            
            // Load zone/policy counts from model
            $modelStats = $this->getModelStats();
            
            // Combine statistics
            $stats = array_merge($serviceStats, $activityStats, $modelStats);
            
            return [
                'status' => 'ok',
                'data' => $stats
            ];
            
        } catch (\Throwable $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to get stats: ' . $e->getMessage(),
                'data' => $this->getDefaultStats()
            ];
        }
    }

    /**
     * Get recent decision logs
     * @return array
     */
    public function logsListAction()
    {
        $this->sessionClose();
        
        $result = [
            'status' => 'ok', 
            'data' => [],
            'total' => 0
        ];

        if (!file_exists(self::DECISIONS_LOG)) {
            return $result;
        }

        $lines = @file(self::DECISIONS_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return [
                'status' => 'error', 
                'message' => 'Unable to read log file',
                'data' => [],
                'total' => 0
            ];
        }

        // Get most recent entries (last 100)
        $lines = array_slice($lines, -100);
        $result['total'] = count($lines);

        foreach (array_reverse($lines) as $line) {
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                continue;
            }

            $result['data'][] = [
                'timestamp' => $this->formatTimestamp($entry['timestamp'] ?? ''),
                'src' => htmlspecialchars($entry['src_ip'] ?? $entry['source_ip'] ?? 'unknown', ENT_QUOTES, 'UTF-8'),
                'dst' => htmlspecialchars($entry['dst_ip'] ?? $entry['destination_ip'] ?? 'unknown', ENT_QUOTES, 'UTF-8'),
                'protocol' => htmlspecialchars(strtoupper($entry['protocol'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'),
                'decision' => htmlspecialchars(strtoupper($entry['decision'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'),
                'port' => htmlspecialchars($entry['port'] ?? 'N/A', ENT_QUOTES, 'UTF-8'),
                'source_zone' => htmlspecialchars($entry['source_zone'] ?? 'UNKNOWN', ENT_QUOTES, 'UTF-8'),
                'destination_zone' => htmlspecialchars($entry['destination_zone'] ?? 'UNKNOWN', ENT_QUOTES, 'UTF-8'),
                'processing_time_ms' => (float)($entry['processing_time_ms'] ?? 0),
                'cached' => (bool)($entry['cached'] ?? false)
            ];
        }

        return $result;
    }

    /**
     * Get traffic patterns for charts
     * @return array
     */
    public function trafficPatternsAction()
    {
        $this->sessionClose();
        
        $hours = (int)($this->request->get('hours', 'int', 24));
        $hours = min($hours, 168); // Max 1 week
        
        try {
            $patterns = $this->analyzeTrafficPatterns($hours);
            
            return [
                'status' => 'ok',
                'data' => $patterns
            ];
            
        } catch (\Throwable $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to get traffic patterns: ' . $e->getMessage(),
                'data' => ['hourly' => [], 'by_protocol' => [], 'by_decision' => []]
            ];
        }
    }

    /**
     * Get zone relationships for visualization
     * @return array
     */
    public function zoneRelationshipsAction()
    {
        $this->sessionClose();
        
        try {
            $mdl = new NetZones();
            $relationships = [];
            $zones = [];
            
            // Get all active zones (UUID -> Name mapping)
            foreach ($mdl->zone->iterateItems() as $zone) {
                if ((string)$zone->enabled === "1") {
                    $zones[(string)$zone->getAttributes()["uuid"]] = (string)$zone->name;
                }
            }
            
            // Get all active policies and resolve zone names
            foreach ($mdl->inter_zone_policy->iterateItems() as $policy) {
                if ((string)$policy->enabled === "1") {
                    $srcUuid = (string)$policy->source_zone;
                    $dstUuid = (string)$policy->destination_zone;
                    
                    // Only include policies where both zones exist and are active
                    if (isset($zones[$srcUuid]) && isset($zones[$dstUuid])) {
                        $relationships[] = [
                            'source_zone' => $zones[$srcUuid],        // Zone NAME not UUID
                            'destination_zone' => $zones[$dstUuid],   // Zone NAME not UUID
                            'action' => (string)$policy->action,
                            'protocol' => (string)$policy->protocol ?: 'any',
                            'priority' => (int)$policy->priority ?: 100,
                            'name' => (string)$policy->name ?: 'Unnamed Policy'
                        ];
                    }
                }
            }
            
            return [
                'status' => 'ok',
                'relationships' => $relationships,
                'zones' => array_values($zones),  // Just zone names
                'total_relationships' => count($relationships)
            ];
            
        } catch (\Throwable $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to get zone relationships: ' . $e->getMessage(),
                'relationships' => [],
                'zones' => []
            ];
        }
    }

    // ===== PRIVATE HELPER METHODS =====

    private function getDefaultStats()
    {
        return [
            'zones' => ['total' => 0, 'active' => 0],
            'policies' => ['total' => 0, 'active' => 0],
            'total_events' => 0,
            'allow_events' => 0,
            'block_events' => 0,
            'last_hour_count' => 0,
            'top_protocols' => [],
            'service_running' => false
        ];
    }

    private function loadServiceStats()
    {
        $stats = [
            'service_running' => false,
            'uptime' => 0,
            'requests_processed' => 0,
            'decisions_pass' => 0,  // Allineato al modello XML
            'decisions_block' => 0,
            'decisions_reject' => 0,
            'cache_hits' => 0,
            'cache_misses' => 0
        ];

        if (file_exists(self::STATS_FILE)) {
            try {
                $serviceData = json_decode(file_get_contents(self::STATS_FILE), true);
                if (is_array($serviceData)) {
                    $stats = array_merge($stats, $serviceData);
                    $stats['service_running'] = file_exists(self::SOCKET_PATH);
                }
            } catch (\Throwable $e) {
                error_log("NetZones: Error loading service stats: " . $e->getMessage());
            }
        }

        return $stats;
    }

    private function calculateActivityStats()
    {
        $stats = [
            'total_events' => 0,
            'allow_events' => 0,
            'pass_events' => 0,  // Allineato al modello XML
            'block_events' => 0,
            'reject_events' => 0,
            'last_hour_count' => 0,
            'top_protocols' => [],
            'top_zones' => [],
            'avg_processing_time' => 0
        ];

        if (!file_exists(self::DECISIONS_LOG)) {
            return $stats;
        }

        $lines = @file(self::DECISIONS_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return $stats;
        }

        $oneHourAgo = time() - 3600;
        $protocols = [];
        $zones = [];
        $processingTimes = [];

        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                continue;
            }

            $stats['total_events']++;
            
            $decision = strtolower($entry['decision'] ?? '');
            switch ($decision) {
                case 'allow':
                case 'pass':
                    $stats['allow_events']++;
                    $stats['pass_events']++;
                    break;
                case 'block':
                    $stats['block_events']++;
                    break;
                case 'reject':
                    $stats['reject_events']++;
                    break;
            }

            // Count events in last hour
            $timestamp = strtotime($entry['timestamp'] ?? '');
            if ($timestamp && $timestamp > $oneHourAgo) {
                $stats['last_hour_count']++;
            }

            // Collect protocol statistics
            $protocol = $entry['protocol'] ?? 'unknown';
            $protocols[$protocol] = ($protocols[$protocol] ?? 0) + 1;

            // Collect zone statistics
            $srcZone = $entry['source_zone'] ?? 'UNKNOWN';
            $dstZone = $entry['destination_zone'] ?? 'UNKNOWN';
            $zones[$srcZone] = ($zones[$srcZone] ?? 0) + 1;
            if ($srcZone !== $dstZone) {
                $zones[$dstZone] = ($zones[$dstZone] ?? 0) + 1;
            }

            // Collect processing times
            if (isset($entry['processing_time_ms']) && is_numeric($entry['processing_time_ms'])) {
                $processingTimes[] = (float)$entry['processing_time_ms'];
            }
        }

        // Top protocols
        arsort($protocols);
        $stats['top_protocols'] = array_slice($protocols, 0, 10, true);

        // Top zones
        arsort($zones);
        $stats['top_zones'] = array_slice($zones, 0, 10, true);

        // Average processing time
        if (!empty($processingTimes)) {
            $stats['avg_processing_time'] = array_sum($processingTimes) / count($processingTimes);
        }

        return $stats;
    }

    private function getModelStats()
    {
        try {
            $mdl = new NetZones();
            
            $totalZones = 0;
            $activeZones = 0;
            $totalPolicies = 0;
            $activePolicies = 0;
            
            // Count zones
            foreach ($mdl->zone->iterateItems() as $zone) {
                $totalZones++;
                if ((string)$zone->enabled === "1") {
                    $activeZones++;
                }
            }
            
            // Count policies
            foreach ($mdl->inter_zone_policy->iterateItems() as $policy) {
                $totalPolicies++;
                if ((string)$policy->enabled === "1") {
                    $activePolicies++;
                }
            }
            
            return [
                'zones' => [
                    'total' => $totalZones,
                    'active' => $activeZones
                ],
                'policies' => [
                    'total' => $totalPolicies,
                    'active' => $activePolicies
                ]
            ];
        } catch (\Throwable $e) {
            return [
                'zones' => ['total' => 0, 'active' => 0],
                'policies' => ['total' => 0, 'active' => 0]
            ];
        }
    }

    private function analyzeTrafficPatterns($hours)
    {
        $patterns = [
            'hourly' => [],
            'by_protocol' => [],
            'by_decision' => [],
            'by_zone_pair' => []
        ];

        if (!file_exists(self::DECISIONS_LOG)) {
            return $patterns;
        }

        $lines = @file(self::DECISIONS_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return $patterns;
        }

        $cutoffTime = time() - ($hours * 3600);
        $hourlyData = [];

        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                continue;
            }

            $timestamp = strtotime($entry['timestamp'] ?? '');
            if (!$timestamp || $timestamp < $cutoffTime) {
                continue;
            }

            // Hourly data
            $hour = date('Y-m-d H:00', $timestamp);
            $hourlyData[$hour] = ($hourlyData[$hour] ?? 0) + 1;

            // Protocol data
            $protocol = $entry['protocol'] ?? 'unknown';
            $patterns['by_protocol'][$protocol] = ($patterns['by_protocol'][$protocol] ?? 0) + 1;

            // Decision data
            $decision = $entry['decision'] ?? 'unknown';
            $patterns['by_decision'][$decision] = ($patterns['by_decision'][$decision] ?? 0) + 1;

            // Zone pair data
            $srcZone = $entry['source_zone'] ?? 'UNKNOWN';
            $dstZone = $entry['destination_zone'] ?? 'UNKNOWN';
            $zonePair = "{$srcZone} → {$dstZone}";
            $patterns['by_zone_pair'][$zonePair] = ($patterns['by_zone_pair'][$zonePair] ?? 0) + 1;
        }

        // Fill missing hours with 0
        for ($i = 0; $i < $hours; $i++) {
            $hour = date('Y-m-d H:00', time() - ($i * 3600));
            if (!isset($hourlyData[$hour])) {
                $hourlyData[$hour] = 0;
            }
        }

        ksort($hourlyData);
        $patterns['hourly'] = $hourlyData;

        return $patterns;
    }

    private function formatTimestamp($timestamp)
    {
        if (empty($timestamp)) {
            return 'N/A';
        }

        try {
            $time = strtotime($timestamp);
            if ($time === false) {
                return $timestamp;
            }
            return date('H:i:s', $time);
        } catch (\Throwable $e) {
            return $timestamp;
        }
    }
}