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

namespace OPNsense\NetZones;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Config;

/**
 * Class NetZones
 * @package OPNsense\NetZones
 */
class NetZones extends BaseModel
{
    /**
     * {@inheritdoc}
     */
    public function performValidation($validateFullModel = false)
    {
        // Standard model validations
        $messages = parent::performValidation($validateFullModel);
        $all_nodes = $this->getFlatNodes();
        
        // Get configured interfaces for validation
        $interfaceSubnets = $this->getConfiguredInterfaces();
        
        foreach ($all_nodes as $key => $node) {
            if ($validateFullModel || $node->isFieldChanged()) {
                $parentNode = $node->getParentNode();
                
                // Perform plugin specific validations
                switch ($parentNode->getInternalXMLTagName()) {
                    case 'zone':
                        $this->validateZoneNode($node, $key, $messages, $interfaceSubnets);
                        break;
                    case 'inter_zone_policy':
                        $this->validatePolicyNode($node, $key, $messages);
                        break;
                }
            }
        }
        
        // Check for subnet overlaps if validating full model
        if ($validateFullModel) {
            $overlapMessages = $this->validateSubnetOverlaps();
            foreach ($overlapMessages as $message) {
                $messages->appendMessage($message);
            }
        }
        
        return $messages;
    }

    /**
     * Validate zone node fields
     */
    private function validateZoneNode($node, $key, $messages, $interfaceSubnets)
    {
        $parentNode = $node->getParentNode();
        
        switch ($node->getInternalXMLTagName()) {
            case 'subnets':
                $this->validateSubnets($node, $key, $messages, $interfaceSubnets, $parentNode);
                break;
        }
    }

    /**
     * Validate policy node fields
     */
    private function validatePolicyNode($node, $key, $messages)
    {
        $parentNode = $node->getParentNode();
        
        switch ($node->getInternalXMLTagName()) {
            case 'destination_zone':
                // Controlla che source e destination non siano uguali
                if (!empty((string)$node) && (string)$node === (string)$parentNode->source_zone) {
                    $messages->appendMessage(new Message(
                        gettext("Source and destination zones cannot be the same"),
                        $key
                    ));
                }
                break;
        }
    }

    /**
     * Validate subnet fields
     */
    private function validateSubnets($node, $key, $messages, $interfaceSubnets, $parentNode)
    {
        $subnets = explode(',', (string)$node);
        $interfaces = explode(',', (string)$parentNode->interface);
        
        foreach ($subnets as $subnet) {
            $subnet = trim($subnet);
            if (empty($subnet)) {
                continue;
            }
            
            // Validate CIDR format
            if (!preg_match('#^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$#', $subnet)) {
                $messages->appendMessage(new Message(
                    gettext("Invalid CIDR subnet format: $subnet"),
                    $key
                ));
                continue;
            }
            
            // Validate subnet is within interface ranges
            $valid = false;
            foreach ($interfaces as $iface) {
                $iface = trim($iface);
                if (!isset($interfaceSubnets[$iface])) {
                    continue;
                }
                
                if ($this->subnetInRange($subnet, $interfaceSubnets[$iface])) {
                    $valid = true;
                    break;
                }
            }
            
            if (!$valid && !empty($interfaces)) {
                $messages->appendMessage(new Message(
                    gettext("Subnet $subnet does not match assigned interface ranges"),
                    $key
                ));
            }
        }
    }

    /**
     * Get configured interfaces from system config
     */
    private function getConfiguredInterfaces()
    {
        $cfg = Config::getInstance()->object();
        $interfaceSubnets = [];
        
        // Get all configured interfaces
        if (isset($cfg->interfaces)) {
            foreach ($cfg->interfaces->children() as $ifname => $ifcfg) {
                $ip = (string)($ifcfg->ipaddr ?? '');
                $cidr = (string)($ifcfg->subnet ?? '');
                if (filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($cidr)) {
                    $interfaceSubnets[$ifname] = "$ip/$cidr";
                }
            }
        }
        
        return $interfaceSubnets;
    }

    /**
     * Check if subnet is within range
     */
    private function subnetInRange($child, $parent)
    {
        try {
            // Simple CIDR validation - can be enhanced with proper IP library
            list($childNetwork, $childMask) = explode('/', $child);
            list($parentNetwork, $parentMask) = explode('/', $parent);
            
            $childLong = ip2long($childNetwork);
            $parentLong = ip2long($parentNetwork);
            
            if ($childLong === false || $parentLong === false) {
                return false;
            }
            
            $childMaskBits = (0xFFFFFFFF << (32 - $childMask)) & 0xFFFFFFFF;
            $parentMaskBits = (0xFFFFFFFF << (32 - $parentMask)) & 0xFFFFFFFF;
            
            return ($childLong & $parentMaskBits) === ($parentLong & $parentMaskBits) && $childMask >= $parentMask;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Validate subnet overlaps between zones
     */
    public function validateSubnetOverlaps()
    {
        $messages = [];
        $subnets = [];
        
        foreach ($this->zone->iterateItems() as $zone) {
            $uuid = $zone->getAttributes()["uuid"] ?? uniqid();
            $zoneName = (string)$zone->name;
            $zoneSubnets = explode(',', (string)$zone->subnets);
            
            foreach ($zoneSubnets as $subnet) {
                $subnet = trim($subnet);
                if (empty($subnet)) {
                    continue;
                }
                
                // Check overlaps with other zones
                foreach ($subnets as $existingSubnet => $existingZone) {
                    if ($this->subnetsOverlap($subnet, $existingSubnet)) {
                        $messages[] = new Message(
                            gettext("Subnet $subnet in zone '$zoneName' overlaps with subnet $existingSubnet in zone '$existingZone'"),
                            "zone.{$uuid}.subnets"
                        );
                    }
                }
                
                $subnets[$subnet] = $zoneName;
            }
        }
        
        return $messages;
    }

    /**
     * Check if two subnets overlap
     */
    private function subnetsOverlap($subnet1, $subnet2)
    {
        try {
            list($network1, $mask1) = explode('/', $subnet1);
            list($network2, $mask2) = explode('/', $subnet2);
            
            $long1 = ip2long($network1);
            $long2 = ip2long($network2);
            
            if ($long1 === false || $long2 === false) {
                return false;
            }
            
            $mask1Bits = (0xFFFFFFFF << (32 - $mask1)) & 0xFFFFFFFF;
            $mask2Bits = (0xFFFFFFFF << (32 - $mask2)) & 0xFFFFFFFF;
            
            $network1Masked = $long1 & $mask1Bits;
            $network2Masked = $long2 & $mask2Bits;
            
            // Check if networks overlap
            $minMask = min($mask1, $mask2);
            $minMaskBits = (0xFFFFFFFF << (32 - $minMask)) & 0xFFFFFFFF;
            
            return ($network1Masked & $minMaskBits) === ($network2Masked & $minMaskBits);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Mark configuration as changed when data is pushed back to the config
     */
    public function serializeToConfig($validateFullModel = false, $disable_validation = false)
    {
        @touch("/tmp/netzones.dirty");
        return parent::serializeToConfig($validateFullModel, $disable_validation);
    }

    /**
     * Get configuration state
     * @return bool
     */
    public function configChanged()
    {
        return file_exists("/tmp/netzones.dirty");
    }

    /**
     * Mark configuration as consistent with the running config
     * @return bool
     */
    public function configClean()
    {
        return @unlink("/tmp/netzones.dirty");
    }

    /**
     * Check if zone has dependent policies
     * @param string $zoneUuid
     * @return bool
     */
    public function isZoneReferenced($zoneUuid)
    {
        foreach ($this->inter_zone_policy->iterateItems() as $policy) {
            if ((string)$policy->source_zone === $zoneUuid || (string)$policy->destination_zone === $zoneUuid) {
                return true;
            }
        }
        return false;
    }
}