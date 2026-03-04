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
 * Class ManagementController
 * @package OPNsense\NetZones\Api
 */
class ManagementController extends ApiControllerBase
{
    private $decisionsLog = '/var/log/netzones_decisions.log';
    private $statsFile    = '/var/run/netzones_stats.json';
    private $socketPath   = '/var/run/netzones.sock';

    // ===== DASHBOARD API METHODS =====

    /**
     * Dashboard statistics
     * @return array
     */
    public function dashboardStatsAction()
    {
        try {
            $stats = array_merge(
                $this->loadServiceStats(),
                $this->calcActivityStats(),
                $this->calcModelStats()
            );
            return ['status' => 'ok', 'data' => $stats];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage(), 'data' => $this->defaultStats()];
        }
    }

    /**
     * Recent decision log entries
     * @return array
     */
    public function dashboardLogsAction()
    {
        try {
            $result = ['status' => 'ok', 'data' => [], 'total' => 0];
            if (!file_exists($this->decisionsLog)) {
                return $result;
            }
            $lines = @file($this->decisionsLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!is_array($lines)) {
                return $result;
            }
            $lines = array_slice($lines, -100);
            $result['total'] = count($lines);
            foreach (array_reverse($lines) as $line) {
                $e = json_decode($line, true);
                if (!is_array($e)) {
                    continue;
                }
                $ts = isset($e['timestamp']) ? strtotime($e['timestamp']) : false;
                $result['data'][] = [
                    'timestamp'          => ($ts ? date('H:i:s', $ts) : 'N/A'),
                    'src'                => htmlspecialchars(isset($e['src_ip']) ? $e['src_ip'] : (isset($e['source_ip']) ? $e['source_ip'] : 'unknown'), ENT_QUOTES, 'UTF-8'),
                    'dst'                => htmlspecialchars(isset($e['dst_ip']) ? $e['dst_ip'] : (isset($e['destination_ip']) ? $e['destination_ip'] : 'unknown'), ENT_QUOTES, 'UTF-8'),
                    'protocol'           => htmlspecialchars(strtoupper(isset($e['protocol']) ? $e['protocol'] : 'unknown'), ENT_QUOTES, 'UTF-8'),
                    'decision'           => htmlspecialchars(strtoupper(isset($e['decision']) ? $e['decision'] : 'unknown'), ENT_QUOTES, 'UTF-8'),
                    'port'               => htmlspecialchars(isset($e['port']) ? $e['port'] : 'N/A', ENT_QUOTES, 'UTF-8'),
                    'source_zone'        => htmlspecialchars(isset($e['source_zone']) ? $e['source_zone'] : 'UNKNOWN', ENT_QUOTES, 'UTF-8'),
                    'destination_zone'   => htmlspecialchars(isset($e['destination_zone']) ? $e['destination_zone'] : 'UNKNOWN', ENT_QUOTES, 'UTF-8'),
                    'processing_time_ms' => (float)(isset($e['processing_time_ms']) ? $e['processing_time_ms'] : 0),
                    'cached'             => (bool)(isset($e['cached']) ? $e['cached'] : false)
                ];
            }
            return $result;
        } catch (\Throwable $e) {
            return ['status' => 'ok', 'data' => [], 'total' => 0];
        }
    }

    /**
     * Zone relationships for dashboard visualization
     * @return array
     */
    public function dashboardZoneRelationshipsAction()
    {
        try {
            $mdl   = new NetZones();
            $zones = [];
            foreach ($mdl->zone->iterateItems() as $zone) {
                if ((string)$zone->enabled === "1") {
                    $zones[(string)$zone->getAttributes()["uuid"]] = (string)$zone->name;
                }
            }
            $relationships = [];
            foreach ($mdl->inter_zone_policy->iterateItems() as $policy) {
                if ((string)$policy->enabled === "1") {
                    $src = (string)$policy->source_zone;
                    $dst = (string)$policy->destination_zone;
                    if (isset($zones[$src]) && isset($zones[$dst])) {
                        $relationships[] = [
                            'source_zone'      => $zones[$src],
                            'destination_zone' => $zones[$dst],
                            'action'           => (string)$policy->action,
                            'protocol'         => (string)$policy->protocol ?: 'any',
                            'priority'         => (int)$policy->priority ?: 100,
                            'name'             => (string)$policy->name ?: 'Unnamed Policy'
                        ];
                    }
                }
            }
            return [
                'status'              => 'ok',
                'relationships'       => $relationships,
                'zones'               => array_values($zones),
                'total_relationships' => count($relationships)
            ];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage(), 'relationships' => [], 'zones' => []];
        }
    }

    /**
     * Traffic patterns for dashboard charts
     * @return array
     */
    public function dashboardTrafficPatternsAction()
    {
        $hours = min((int)($this->request->getPost('hours', 'int', 24)), 168);
        try {
            return ['status' => 'ok', 'data' => $this->calcTrafficPatterns($hours)];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage(),
                    'data' => ['hourly' => [], 'by_protocol' => [], 'by_decision' => []]];
        }
    }

    // ===== DASHBOARD PRIVATE HELPERS =====

    private function defaultStats()
    {
        return [
            'zones'           => ['total' => 0, 'active' => 0],
            'policies'        => ['total' => 0, 'active' => 0],
            'total_events'    => 0,
            'allow_events'    => 0,
            'block_events'    => 0,
            'last_hour_count' => 0,
            'top_protocols'   => [],
            'service_running' => false
        ];
    }

    private function loadServiceStats()
    {
        $s = ['service_running' => false, 'uptime' => 0, 'requests_processed' => 0,
              'decisions_pass' => 0, 'decisions_block' => 0, 'decisions_reject' => 0,
              'cache_hits' => 0, 'cache_misses' => 0];
        if (file_exists($this->statsFile)) {
            $d = json_decode(@file_get_contents($this->statsFile), true);
            if (is_array($d)) {
                $s = array_merge($s, $d);
                $s['service_running'] = file_exists($this->socketPath);
            }
        }
        return $s;
    }

    private function calcActivityStats()
    {
        $s = ['total_events' => 0, 'allow_events' => 0, 'block_events' => 0, 'reject_events' => 0,
              'last_hour_count' => 0, 'top_protocols' => [], 'top_zones' => [], 'avg_processing_time' => 0];
        if (!file_exists($this->decisionsLog)) {
            return $s;
        }
        $lines = @file($this->decisionsLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return $s;
        }
        $oneHourAgo = time() - 3600;
        $protocols = [];
        $zones = [];
        $times = [];
        foreach ($lines as $line) {
            $e = json_decode($line, true);
            if (!is_array($e)) {
                continue;
            }
            $s['total_events']++;
            switch (strtolower($e['decision'] ?? '')) {
                case 'allow': case 'pass': $s['allow_events']++; break;
                case 'block':              $s['block_events']++; break;
                case 'reject':             $s['reject_events']++; break;
            }
            $ts = strtotime($e['timestamp'] ?? '');
            if ($ts && $ts > $oneHourAgo) {
                $s['last_hour_count']++;
            }
            $proto = $e['protocol'] ?? 'unknown';
            $protocols[$proto] = ($protocols[$proto] ?? 0) + 1;
            $sz = $e['source_zone'] ?? 'UNKNOWN';
            $dz = $e['destination_zone'] ?? 'UNKNOWN';
            $zones[$sz] = ($zones[$sz] ?? 0) + 1;
            if ($sz !== $dz) {
                $zones[$dz] = ($zones[$dz] ?? 0) + 1;
            }
            if (isset($e['processing_time_ms']) && is_numeric($e['processing_time_ms'])) {
                $times[] = (float)$e['processing_time_ms'];
            }
        }
        arsort($protocols);
        $s['top_protocols'] = array_slice($protocols, 0, 10, true);
        arsort($zones);
        $s['top_zones'] = array_slice($zones, 0, 10, true);
        if (!empty($times)) {
            $s['avg_processing_time'] = array_sum($times) / count($times);
        }
        return $s;
    }

    private function calcModelStats()
    {
        try {
            $mdl = new NetZones();
            $tz = 0; $az = 0; $tp = 0; $ap = 0;
            foreach ($mdl->zone->iterateItems() as $z) {
                $tz++;
                if ((string)$z->enabled === "1") { $az++; }
            }
            foreach ($mdl->inter_zone_policy->iterateItems() as $p) {
                $tp++;
                if ((string)$p->enabled === "1") { $ap++; }
            }
            return ['zones' => ['total' => $tz, 'active' => $az],
                    'policies' => ['total' => $tp, 'active' => $ap]];
        } catch (\Throwable $e) {
            return ['zones' => ['total' => 0, 'active' => 0], 'policies' => ['total' => 0, 'active' => 0]];
        }
    }

    private function calcTrafficPatterns($hours)
    {
        $p = ['hourly' => [], 'by_protocol' => [], 'by_decision' => [], 'by_zone_pair' => []];
        if (!file_exists($this->decisionsLog)) {
            return $p;
        }
        $lines = @file($this->decisionsLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return $p;
        }
        $cutoff = time() - ($hours * 3600);
        $hourly = [];
        foreach ($lines as $line) {
            $e = json_decode($line, true);
            if (!is_array($e)) {
                continue;
            }
            $ts = strtotime($e['timestamp'] ?? '');
            if (!$ts || $ts < $cutoff) {
                continue;
            }
            $h = date('Y-m-d H:00', $ts);
            $hourly[$h] = ($hourly[$h] ?? 0) + 1;
            $proto = $e['protocol'] ?? 'unknown';
            $p['by_protocol'][$proto] = ($p['by_protocol'][$proto] ?? 0) + 1;
            $dec = $e['decision'] ?? 'unknown';
            $p['by_decision'][$dec] = ($p['by_decision'][$dec] ?? 0) + 1;
            $pair = ($e['source_zone'] ?? 'UNKNOWN') . ' → ' . ($e['destination_zone'] ?? 'UNKNOWN');
            $p['by_zone_pair'][$pair] = ($p['by_zone_pair'][$pair] ?? 0) + 1;
        }
        for ($i = 0; $i < $hours; $i++) {
            $h = date('Y-m-d H:00', time() - ($i * 3600));
            if (!isset($hourly[$h])) {
                $hourly[$h] = 0;
            }
        }
        ksort($hourly);
        $p['hourly'] = $hourly;
        return $p;
    }

    // ===== ZONE MANAGEMENT METHODS =====

    /**
     * Get list of zones for dropdowns
     * @return array
     */
    public function getZoneListAction()
    {
        try {
            $mdl = new NetZones();
            $zones = [];
            
            foreach ($mdl->zone->iterateItems() as $zone) {
                if ((string)$zone->enabled === "1") {
                    $zones[] = [
                        'value' => (string)$zone->getAttributes()["uuid"],
                        'text' => (string)$zone->name
                    ];
                }
            }
            
            return [
                'status' => 'ok',
                'zones' => $zones
            ];
            
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to get zone list: ' . $e->getMessage()
            ];
        }
    }


    public function getZoneMapAction()
    {
        $result = [];
        $mdl = new NetZones();
        
        foreach ($mdl->zone->iterateItems() as $zone) {
            if ((string)$zone->enabled === "1") {
                $result[(string)$zone->getAttributes()["uuid"]] = (string)$zone->name;
            }
        }
        
        return $result;
    }

    /**
     * Get zone mapping information
     * @return array
     */
    public function getZoneMappingAction()
    {
        try {
            $mdl = new NetZones();
            $zones = [];
            
            foreach ($mdl->zone->iterateItems() as $zone) {
                if ((string)$zone->enabled === "1") {
                    $zones[] = [
                        "uuid" => (string)$zone->getAttributes()["uuid"],
                        "name" => (string)$zone->name,
                        "description" => (string)$zone->description,
                        "subnets" => explode(",", (string)$zone->subnets),
                        "interface" => explode(",", (string)$zone->interface),
                        "default_action" => (string)$zone->default_action,
                        "priority" => (int)$zone->priority,
                        "log_traffic" => (string)$zone->log_traffic === "1"
                    ];
                }
            }
            
            return [
                "status" => "ok",
                "zones" => $zones
            ];
            
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => "Failed to get zone mapping: " . $e->getMessage()
            ];
        }
    }

    /**
     * Get policy mapping information
     * @return array
     */
    public function getPolicyMappingAction()
    {
        try {
            $mdl = new NetZones();
            $policies = [];
            
            foreach ($mdl->inter_zone_policy->iterateItems() as $policy) {
                if ((string)$policy->enabled === "1") {
                    $policies[] = [
                        "uuid" => (string)$policy->getAttributes()["uuid"],
                        "name" => (string)$policy->name,
                        "description" => (string)$policy->description,
                        "source_zone" => (string)$policy->source_zone,
                        "destination_zone" => (string)$policy->destination_zone,
                        "action" => (string)$policy->action,
                        "protocol" => (string)$policy->protocol,
                        "source_port" => (string)$policy->source_port,
                        "destination_port" => (string)$policy->destination_port,
                        "priority" => (int)$policy->priority,
                        "log_traffic" => (string)$policy->log_traffic === "1"
                    ];
                }
            }
            
            return [
                "status" => "ok",
                "policies" => $policies
            ];
            
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => "Failed to get policy mapping: " . $e->getMessage()
            ];
        }
    }

    /**
     * Get all network interfaces for dropdown
     * @return array
     */
    public function getInterfacesAction()
    {
        try {
            $interfaces = [];
            
            // Get interfaces from config
            $config = \OPNsense\Core\Config::getInstance()->object();
            
            if (isset($config->interfaces)) {
                foreach ($config->interfaces->children() as $interfaceKey => $interfaceData) {
                    if (isset($interfaceData->descr)) {
                        $interfaces[] = [
                            'value' => $interfaceKey,
                            'text' => (string)$interfaceData->descr . ' (' . $interfaceKey . ')'
                        ];
                    } else {
                        $interfaces[] = [
                            'value' => $interfaceKey,
                            'text' => $interfaceKey
                        ];
                    }
                }
            }
            
            return [
                'status' => 'ok',
                'interfaces' => $interfaces
            ];
            
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to get interfaces: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Validate CIDR subnet format
     * @return array
     */
    public function validateSubnetAction()
    {
        if ($this->request->isPost()) {
            $subnet = $this->request->getPost("subnet", "string", "");
            
            if (empty($subnet)) {
                return [
                    "status" => "error",
                    "message" => "Subnet cannot be empty"
                ];
            }
            
            // Validate CIDR format
            if (preg_match('#^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$#', $subnet)) {
                // Additional validation for IP range
                list($ip, $mask) = explode('/', $subnet);
                $ipParts = explode('.', $ip);
                
                $valid = true;
                foreach ($ipParts as $part) {
                    if ((int)$part > 255) {
                        $valid = false;
                        break;
                    }
                }
                
                if ($valid && (int)$mask >= 0 && (int)$mask <= 32) {
                    return [
                        "status" => "ok",
                        "message" => "Valid CIDR format"
                    ];
                }
            }
            
            return [
                "status" => "error",
                "message" => "Invalid CIDR format. Use format like 192.168.1.0/24"
            ];
        }
        
        return [
            "status" => "error",
            "message" => "POST method required"
        ];
    }

    /**
     * Check for conflicting subnets
     * @return array
     */
    public function checkSubnetConflictsAction()
    {
        if ($this->request->isPost()) {
            $subnet = $this->request->getPost("subnet", "string", "");
            $excludeUuid = $this->request->getPost("excludeUuid", "string", "");
            
            if (empty($subnet)) {
                return [
                    "status" => "error",
                    "message" => "Subnet required"
                ];
            }
            
            try {
                $mdl = new NetZones();
                $conflicts = [];
                
                foreach ($mdl->zone->iterateItems() as $zone) {
                    if ((string)$zone->enabled === "1" && 
                        (string)$zone->getAttributes()["uuid"] !== $excludeUuid) {
                        
                        $existingSubnets = explode(',', (string)$zone->subnets);
                        foreach ($existingSubnets as $existingSubnet) {
                            $existingSubnet = trim($existingSubnet);
                            if ($this->subnetsOverlap($subnet, $existingSubnet)) {
                                $conflicts[] = [
                                    "zone_name" => (string)$zone->name,
                                    "conflicting_subnet" => $existingSubnet
                                ];
                            }
                        }
                    }
                }
                
                return [
                    "status" => "ok",
                    "conflicts" => $conflicts,
                    "has_conflicts" => !empty($conflicts)
                ];
                
            } catch (\Exception $e) {
                return [
                    "status" => "error",
                    "message" => "Failed to check conflicts: " . $e->getMessage()
                ];
            }
        }
        
        return [
            "status" => "error",
            "message" => "POST method required"
        ];
    }

    /**
     * Get zone statistics
     * @return array
     */
    public function getZoneStatsAction()
    {
        try {
            $mdl = new NetZones();
            $stats = [
                "total_zones" => 0,
                "enabled_zones" => 0,
                "disabled_zones" => 0,
                "total_policies" => 0,
                "enabled_policies" => 0,
                "disabled_policies" => 0
            ];
            
            // Count zones
            foreach ($mdl->zone->iterateItems() as $zone) {
                $stats["total_zones"]++;
                if ((string)$zone->enabled === "1") {
                    $stats["enabled_zones"]++;
                } else {
                    $stats["disabled_zones"]++;
                }
            }
            
            // Count policies
            foreach ($mdl->inter_zone_policy->iterateItems() as $policy) {
                $stats["total_policies"]++;
                if ((string)$policy->enabled === "1") {
                    $stats["enabled_policies"]++;
                } else {
                    $stats["disabled_policies"]++;
                }
            }
            
            return [
                "status" => "ok",
                "stats" => $stats
            ];
            
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => "Failed to get statistics: " . $e->getMessage()
            ];
        }
    }

    /**
     * Helper method to check if two subnets overlap
     * @param string $subnet1
     * @param string $subnet2
     * @return bool
     */
    private function subnetsOverlap($subnet1, $subnet2)
    {
        if (strpos($subnet1, '/') === false || strpos($subnet2, '/') === false) {
            return false;
        }
        
        list($ip1, $mask1) = explode('/', $subnet1);
        list($ip2, $mask2) = explode('/', $subnet2);
        
        $ip1Long = ip2long($ip1);
        $ip2Long = ip2long($ip2);
        
        if ($ip1Long === false || $ip2Long === false) {
            return false;
        }
        
        $mask1Long = (0xFFFFFFFF << (32 - $mask1)) & 0xFFFFFFFF;
        $mask2Long = (0xFFFFFFFF << (32 - $mask2)) & 0xFFFFFFFF;
        
        $network1 = $ip1Long & $mask1Long;
        $network2 = $ip2Long & $mask2Long;
        
        // Check if one network contains the other
        $minMask = min($mask1, $mask2);
        $maskLong = (0xFFFFFFFF << (32 - $minMask)) & 0xFFFFFFFF;
        
        return ($network1 & $maskLong) === ($network2 & $maskLong);
    }
}