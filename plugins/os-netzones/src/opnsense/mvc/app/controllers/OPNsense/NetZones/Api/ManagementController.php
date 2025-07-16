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