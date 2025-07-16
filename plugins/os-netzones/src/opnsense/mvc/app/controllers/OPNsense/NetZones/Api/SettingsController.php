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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

/**
 * Class SettingsController
 * @package OPNsense\NetZones\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'netzones';
    protected static $internalModelClass = 'OPNsense\NetZones\NetZones';

    /**
     * Check if changes to the NetZones settings were made
     * @return array result
     */
    public function dirtyAction()
    {
        $result = array('status' => 'ok');
        $result['netzones']['dirty'] = $this->getModel()->configChanged();
        return $result;
    }

    /**
     * Get available interfaces for templates
     * @return array
     */
    private function getAvailableInterfaces()
    {
        $interfaces = [];
        $config = Config::getInstance()->object();
        
        if (isset($config->interfaces)) {
            foreach ($config->interfaces->children() as $interfaceKey => $interfaceData) {
                // Includi solo interfacce abilitate
                if (!isset($interfaceData->enable) || (string)$interfaceData->enable !== "0") {
                    $description = isset($interfaceData->descr) ? (string)$interfaceData->descr : $interfaceKey;
                    $interfaces[] = [
                        'key' => $interfaceKey,
                        'description' => $description,
                        'display' => $description . ' (' . $interfaceKey . ')'
                    ];
                }
            }
        }
        
        return $interfaces;
    }

    /**
     * Get interfaces list for API
     * @return array
     */
    public function getInterfacesAction()
    {
        try {
            $interfaces = $this->getAvailableInterfaces();
            
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
     * Retrieve zone settings or return defaults
     * @param $uuid item unique id
     * @return array NetZones zone content
     * @throws \ReflectionException when not bound to model
     */
    public function getZoneAction($uuid = null)
    {
        return $this->getBase("zone", "zone", $uuid);
    }

    /**
     * Update zone with given properties
     * @param string $uuid internal id
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function setZoneAction($uuid)
    {
        return $this->setBase("zone", "zone", $uuid);
    }

    /**
     * Add zone with given properties
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function addZoneAction()
    {
        return $this->addBase("zone", "zone");
    }

    /**
     * Delete zone by uuid
     * @param string $uuid internal id
     * @return array save status
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function delZoneAction($uuid)
    {
        return $this->delBase("zone", $uuid);
    }

    /**
     * Search NetZones zones
     * @return array list of found zones
     * @throws \ReflectionException when not bound to model
     */
    public function searchZoneAction()
    {
        return $this->searchBase(
            "zone",
            array("enabled", "name", "description", "default_action", "priority"),
            "name"
        );
    }

    /**
     * Toggle zone defined by uuid (enable/disable)
     * @param $uuid zone internal id
     * @param $enabled desired state enabled(1)/disabled(1), leave empty for toggle
     * @return array save result
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function toggleZoneAction($uuid, $enabled = null)
    {
        return $this->toggleBase("zone", $uuid, $enabled);
    }

    /**
     * Retrieve inter-zone policy settings or return defaults
     * @param $uuid item unique id
     * @return array NetZones policy content
     * @throws \ReflectionException when not bound to model
     */
    public function getPolicyAction($uuid = null)
    {
        return $this->getBase("inter_zone_policy", "inter_zone_policy", $uuid);
    }

    /**
     * Update inter-zone policy with given properties
     * @param string $uuid internal id
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function setPolicyAction($uuid)
    {
        return $this->setBase("inter_zone_policy", "inter_zone_policy", $uuid);
    }

    /**
     * Add inter-zone policy with given properties
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function addPolicyAction()
    {
        return $this->addBase("inter_zone_policy", "inter_zone_policy");
    }

    /**
     * Delete inter-zone policy by uuid
     * @param string $uuid internal id
     * @return array save status
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function delPolicyAction($uuid)
    {
        return $this->delBase("inter_zone_policy", $uuid);
    }

    /**
     * Search NetZones inter-zone policies
     * @return array list of found policies
     * @throws \ReflectionException when not bound to model
     */
    public function searchPolicyAction()
    {
        return $this->searchBase(
            "inter_zone_policy",
            array("enabled", "name", "description", "source_zone", "destination_zone", "action", "priority"),
            "name"
        );
    }

    /**
     * Toggle inter-zone policy defined by uuid (enable/disable)
     * @param $uuid policy internal id
     * @param $enabled desired state enabled(1)/disabled(1), leave empty for toggle
     * @return array save result
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function togglePolicyAction($uuid, $enabled = null)
    {
        return $this->toggleBase("inter_zone_policy", $uuid, $enabled);
    }

    /**
     * Get predefined zone templates (corretto per il modello XML)
     * @return array list of available templates
     */
    public function getZoneTemplatesAction()
    {
        // Get available interfaces per template realistici
        $availableInterfaces = $this->getAvailableInterfaces();
        $interfaceKeys = array_column($availableInterfaces, 'key');
        $defaultInterface = !empty($interfaceKeys) ? $interfaceKeys[0] : 'lan';
        
        $templates = [
            'lan' => [
                'name' => 'LAN',
                'description' => 'Local Area Network - Trusted internal network',
                'default_action' => 'pass',
                'priority' => 100,
                'log_traffic' => false,
                'suggested_subnets' => '192.168.1.0/24',
                'suggested_interface' => in_array('lan', $interfaceKeys) ? 'lan' : $defaultInterface
            ],
            'dmz' => [
                'name' => 'DMZ',
                'description' => 'Demilitarized Zone - Semi-trusted network for public services',
                'default_action' => 'block',
                'priority' => 200,
                'log_traffic' => true,
                'suggested_subnets' => '192.168.100.0/24',
                'suggested_interface' => in_array('opt1', $interfaceKeys) ? 'opt1' : $defaultInterface
            ],
            'guest' => [
                'name' => 'GUEST',
                'description' => 'Guest Network - Isolated network for visitors',
                'default_action' => 'block',
                'priority' => 300,
                'log_traffic' => true,
                'suggested_subnets' => '192.168.200.0/24',
                'suggested_interface' => in_array('opt2', $interfaceKeys) ? 'opt2' : $defaultInterface
            ],
            'wan' => [
                'name' => 'WAN',
                'description' => 'Wide Area Network - External untrusted network',
                'default_action' => 'block',
                'priority' => 999,
                'log_traffic' => true,
                'suggested_subnets' => '0.0.0.0/0',
                'suggested_interface' => in_array('wan', $interfaceKeys) ? 'wan' : $defaultInterface
            ],
            'iot' => [
                'name' => 'IOT',
                'description' => 'Internet of Things - Isolated network for IoT devices',
                'default_action' => 'block',
                'priority' => 400,
                'log_traffic' => true,
                'suggested_subnets' => '192.168.50.0/24',
                'suggested_interface' => in_array('opt3', $interfaceKeys) ? 'opt3' : $defaultInterface
            ],
            'servers' => [
                'name' => 'SERVERS',
                'description' => 'Server Network - Dedicated network for servers',
                'default_action' => 'pass',
                'priority' => 150,
                'log_traffic' => true,
                'suggested_subnets' => '192.168.10.0/24',
                'suggested_interface' => in_array('opt4', $interfaceKeys) ? 'opt4' : $defaultInterface
            ]
        ];

        return [
            'status' => 'ok',
            'templates' => $templates,
            'available_interfaces' => $availableInterfaces
        ];
    }

    /**
     * Create zone from predefined template (con validazione migliorata)
     * @param string $templateId template identifier
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function createZoneFromTemplateAction($templateId)
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'validations' => ['POST method required']];
        }

        $templatesResponse = $this->getZoneTemplatesAction();
        $templates = $templatesResponse['templates'];
        $availableInterfaces = $templatesResponse['available_interfaces'];

        if (!isset($templates[$templateId])) {
            return ['result' => 'failed', 'validations' => ['Template not found']];
        }

        $template = $templates[$templateId];
        $mdl = $this->getModel();
        
        // Get custom data from request
        $customName = $this->request->getPost("name", "string", $template['name']);
        $customDescription = $this->request->getPost("description", "string", $template['description']);
        $customSubnets = $this->request->getPost("subnets", "string", $template['suggested_subnets']);
        $customInterface = $this->request->getPost("interface", "string", $template['suggested_interface']);

        // Pre-validazione dei dati
        if (empty($customName)) {
            return ['result' => 'failed', 'validations' => ['Zone name is required']];
        }

        if (empty($customSubnets)) {
            return ['result' => 'failed', 'validations' => ['Subnets are required']];
        }

        if (empty($customInterface)) {
            return ['result' => 'failed', 'validations' => ['Interface is required']];
        }

        // Get available interfaces per template realistici
        $availableInterfaces = $this->getAvailableInterfaces();
        $interfaceKeys = array_column($availableInterfaces, 'key');

        // Controlla se l'interfaccia esiste
        if (!in_array($customInterface, $interfaceKeys)) {
            return [
                'result' => 'failed', 
                'validations' => [
                    "Interface '$customInterface' does not exist. Available interfaces: " . 
                    implode(', ', array_map(function($iface) { 
                        return $iface['display']; 
                    }, $availableInterfaces))
                ]
            ];
        }

        // Controlla formato CIDR
        $subnets = explode(',', $customSubnets);
        foreach ($subnets as $subnet) {
            $subnet = trim($subnet);
            if (!empty($subnet) && !preg_match('#^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$#', $subnet)) {
                return [
                    'result' => 'failed', 
                    'validations' => ["Invalid CIDR format: '$subnet'. Use format like 192.168.1.0/24"]
                ];
            }
        }

        // Controlla se il nome zona è unico
        foreach ($mdl->zone->iterateItems() as $existingZone) {
            if ((string)$existingZone->name === $customName) {
                return [
                    'result' => 'failed', 
                    'validations' => ["Zone name '$customName' already exists"]
                ];
            }
        }

        try {
            $newZone = $mdl->zone->Add();
            $newZone->name = $customName;
            $newZone->description = $customDescription;
            $newZone->subnets = $customSubnets;
            $newZone->interface = $customInterface;
            $newZone->default_action = $template['default_action'];
            $newZone->log_traffic = $template['log_traffic'] ? "1" : "0";
            $newZone->priority = (string)$template['priority'];
            $newZone->enabled = "1";

            $valMsgs = $mdl->performValidation();
            if (count($valMsgs) == 0) {
                $mdl->serializeToConfig();
                Config::getInstance()->save();
                return [
                    'result' => 'saved', 
                    'uuid' => $newZone->getAttributes()["uuid"],
                    'message' => "Zone '$customName' created successfully"
                ];
            } else {
                // Remove the added zone if validation fails
                $mdl->zone->del($newZone->getAttributes()["uuid"]);
                
                // Convert validation messages to array
                $validationErrors = [];
                foreach ($valMsgs as $field => $message) {
                    $validationErrors[] = "$field: $message";
                }
                
                return ['result' => 'failed', 'validations' => $validationErrors];
            }
        } catch (\Exception $e) {
            return [
                'result' => 'failed', 
                'validations' => ['Error creating zone: ' . $e->getMessage()]
            ];
        }
    }
}