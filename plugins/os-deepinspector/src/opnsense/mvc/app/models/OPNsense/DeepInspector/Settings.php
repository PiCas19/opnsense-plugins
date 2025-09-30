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

namespace OPNsense\DeepInspector;

use OPNsense\Base\BaseModel;
use OPNsense\ValidationCore\ValidationEngine;
use OPNsense\Base\Messages\MessageCollection;
use OPNsense\Base\Messages\Message;

/**
 * Class Settings
 *
 * Configuration model for the DeepInspector plugin that implements clean
 * validation architecture using the ValidationCore library. This model serves as the
 * data layer for system configuration while delegating validation logic to
 * specialized validator classes for maintainability and extensibility.
 *
 * @package OPNsense\DeepInspector
 */
class Settings extends BaseModel
{
    /**
     * Validation engine instance for orchestrating validation logic
     *
     * @var ValidationEngine Centralized validation coordinator
     */
    private $validationEngine;

    /**
     * Initialize the Settings model and validation engine
     */
    public function __construct()
    {
        parent::__construct();
        $this->validationEngine = new ValidationEngine();
    }

    /**
     * Perform comprehensive configuration validation using ValidationCore
     *
     * Delegates validation logic to specialized validator classes via the validation engine.
     *
     * @param bool $validateFullModel Whether to validate entire model or only changed fields
     * @param string $scope Validation scope to control which validators are executed
     * @return MessageCollection Complete validation results
     */
    public function performValidation($validateFullModel = false, $scope = 'all'): MessageCollection
    {
        $messages = parent::performValidation($validateFullModel);

        try {
            $configurationData = $this->extractConfigurationData();
            $validationMessages = $this->validationEngine->validate($configurationData, $validateFullModel, $scope);

            foreach ($validationMessages as $validationMessage) {
                $messages->appendMessage($validationMessage);
            }
        } catch (\Exception $e) {
            error_log("DeepInspector validation engine error: " . $e->getMessage());
            $messages->appendMessage(new Message(
                gettext('Internal validation error occurred. Please check configuration and try again.'),
                'general.validation_engine'
            ));
        }

        return $messages;
    }

    /**
     * Extract configuration data from OPNsense model for validator consumption
     *
     * @return array Structured configuration data
     * @throws \RuntimeException When model data extraction fails
     */
    private function extractConfigurationData(): array
    {
        try {
            return [
                'general' => [
                    'enabled' => (string)$this->general->enabled,
                    'interfaces' => (string)$this->general->interfaces,
                    'performance_profile' => (string)$this->general->performance_profile,
                    'mode' => (string)$this->general->mode,
                    'trusted_networks' => (string)$this->general->trusted_networks,
                    'deep_scan_ports' => (string)$this->general->deep_scan_ports,
                    'max_packet_size' => (string)$this->general->max_packet_size,
                    'ssl_inspection' => (string)$this->general->ssl_inspection,
                    'malware_detection' => (string)$this->general->malware_detection,
                    'archive_extraction' => (string)$this->general->archive_extraction,
                    'anomaly_detection' => (string)$this->general->anomaly_detection,
                    'low_latency_mode' => (string)$this->general->low_latency_mode,
                    'industrial_mode' => (string)$this->general->industrial_mode,
                    'log_level' => (string)$this->general->log_level,
                    '_field_changes' => $this->extractFieldChanges('general')
                ],
                'protocols' => [
                    'http_inspection' => (string)$this->protocols->http_inspection,
                    'https_inspection' => (string)$this->protocols->https_inspection,
                    'ftp_inspection' => (string)$this->protocols->ftp_inspection,
                    'smtp_inspection' => (string)$this->protocols->smtp_inspection,
                    'dns_inspection' => (string)$this->protocols->dns_inspection,
                    'industrial_protocols' => (string)$this->protocols->industrial_protocols,
                    'p2p_detection' => (string)$this->protocols->p2p_detection,
                    'voip_inspection' => (string)$this->protocols->voip_inspection,
                    'custom_protocols' => (string)$this->protocols->custom_protocols,
                    '_field_changes' => $this->extractFieldChanges('protocols')
                ],
                'detection' => [
                    'virus_signatures' => (string)$this->detection->virus_signatures,
                    'trojan_detection' => (string)$this->detection->trojan_detection,
                    'crypto_mining' => (string)$this->detection->crypto_mining,
                    'data_exfiltration' => (string)$this->detection->data_exfiltration,
                    'command_injection' => (string)$this->detection->command_injection,
                    'sql_injection' => (string)$this->detection->sql_injection,
                    'script_injection' => (string)$this->detection->script_injection,
                    'suspicious_downloads' => (string)$this->detection->suspicious_downloads,
                    'phishing_detection' => (string)$this->detection->phishing_detection,
                    'botnet_detection' => (string)$this->detection->botnet_detection,
                    'steganography_detection' => (string)$this->detection->steganography_detection,
                    'zero_day_heuristics' => (string)$this->detection->zero_day_heuristics,
                    '_field_changes' => $this->extractFieldChanges('detection')
                ],
                'advanced' => [
                    'signature_updates' => (string)$this->advanced->signature_updates,
                    'update_interval' => (string)$this->advanced->update_interval,
                    'threat_intelligence_feeds' => (string)$this->advanced->threat_intelligence_feeds,
                    'custom_signatures' => (string)$this->advanced->custom_signatures,
                    'quarantine_enabled' => (string)$this->advanced->quarantine_enabled,
                    'quarantine_path' => (string)$this->advanced->quarantine_path,
                    'memory_limit' => (string)$this->advanced->memory_limit,
                    'thread_count' => (string)$this->advanced->thread_count,
                    'packet_buffer_size' => (string)$this->advanced->packet_buffer_size,
                    'analysis_timeout' => (string)$this->advanced->analysis_timeout,
                    'bypass_trusted_networks' => (string)$this->advanced->bypass_trusted_networks,
                    'industrial_optimization' => (string)$this->advanced->industrial_optimization,
                    'scada_protocols' => (string)$this->advanced->scada_protocols,
                    'plc_protocols' => (string)$this->advanced->plc_protocols,
                    'latency_threshold' => (string)$this->advanced->latency_threshold,
                    '_field_changes' => $this->extractFieldChanges('advanced')
                ]
            ];
        } catch (\Exception $e) {
            throw new \RuntimeException(
                'Failed to extract configuration data for validation: ' . $e->getMessage()
            );
        }
    }

    /**
     * Extract field change information for incremental validation
     *
     * @param string $section Configuration section (general, protocols, detection, advanced)
     * @return array Field change tracking data
     */
    private function extractFieldChanges(string $section): array
    {
        $changes = [];
        try {
            $sectionNode = $this->$section;
            foreach ($sectionNode->getAttributes() as $field => $value) {
                if (method_exists($sectionNode->$field, 'isFieldChanged')) {
                    $changes[$field] = $sectionNode->$field->isFieldChanged();
                }
            }
        } catch (\Exception $e) {
            error_log("DeepInspector field change detection failed for section $section: " . $e->getMessage());
        }
        return $changes;
    }

    /**
     * Mark configuration as changed when data is pushed back to the config
     */
    public function serializeToConfig($validateFullModel = false, $disable_validation = false)
    {
        @touch("/tmp/deepinspector.dirty");
        return parent::serializeToConfig($validateFullModel, $disable_validation);
    }

    /**
     * Get configuration state
     * @return bool
     */
    public function configChanged()
    {
        return file_exists("/tmp/deepinspector.dirty");
    }

    /**
     * Mark configuration as consistent with the running config
     * @return bool
     */
    public function configClean()
    {
        return @unlink("/tmp/deepinspector.dirty");
    }

    /**
     * Get summary of current configuration for dashboard
     */
    public function getConfigSummary()
    {
        $summary = [
            'enabled' => (string)$this->general->enabled === "1",
            'mode' => (string)$this->general->mode,
            'performance_profile' => (string)$this->general->performance_profile,
            'interfaces_count' => count(explode(',', (string)$this->general->interfaces)),
            'ssl_inspection' => (string)$this->general->ssl_inspection === "1",
            'enabled_protocols' => 0,
            'enabled_detections' => 0
        ];

        $protocols = ['http_inspection', 'https_inspection', 'ftp_inspection', 'smtp_inspection', 'dns_inspection', 'industrial_protocols'];
        foreach ($protocols as $protocol) {
            if ((string)$this->protocols->$protocol === "1") {
                $summary['enabled_protocols']++;
            }
        }

        $detections = ['virus_signatures', 'trojan_detection', 'crypto_mining', 'data_exfiltration', 'command_injection', 'sql_injection', 'script_injection'];
        foreach ($detections as $detection) {
            if ((string)$this->detection->$detection === "1") {
                $summary['enabled_detections']++;
            }
        }

        return $summary;
    }

    /**
     * Get industrial recommendations for optimization
     */
    public function getIndustrialRecommendations()
    {
        return [
            'performance_profile' => 'industrial',
            'low_latency_mode' => '1',
            'industrial_mode' => '1',
            'latency_threshold' => '50',
            'mode' => 'active',
            'ssl_inspection' => '0',
            'archive_extraction' => '0'
        ];
    }

    /**
     * Export configuration for the DPI engine
     */
    public function exportForEngine()
    {
        $config = [
            'general' => [
                'enabled' => (string)$this->general->enabled === "1",
                'mode' => (string)$this->general->mode,
                'interfaces' => explode(',', (string)$this->general->interfaces),
                'trusted_networks' => array_filter(explode(',', (string)$this->general->trusted_networks)),
                'max_packet_size' => (int)(string)$this->general->max_packet_size,
                'deep_scan_ports' => (string)$this->general->deep_scan_ports,
                'ssl_inspection' => (string)$this->general->ssl_inspection === "1",
                'archive_extraction' => (string)$this->general->archive_extraction === "1",
                'malware_detection' => (string)$this->general->malware_detection === "1",
                'anomaly_detection' => (string)$this->general->anomaly_detection === "1",
                'performance_profile' => (string)$this->general->performance_profile,
                'low_latency_mode' => (string)$this->general->low_latency_mode === "1",
                'industrial_mode' => (string)$this->general->industrial_mode === "1",
                'log_level' => (string)$this->general->log_level
            ],
            'protocols' => [
                'http_inspection' => (string)$this->protocols->http_inspection === "1",
                'https_inspection' => (string)$this->protocols->https_inspection === "1",
                'ftp_inspection' => (string)$this->protocols->ftp_inspection === "1",
                'smtp_inspection' => (string)$this->protocols->smtp_inspection === "1",
                'dns_inspection' => (string)$this->protocols->dns_inspection === "1",
                'industrial_protocols' => (string)$this->protocols->industrial_protocols === "1",
                'p2p_detection' => (string)$this->protocols->p2p_detection === "1",
                'voip_inspection' => (string)$this->protocols->voip_inspection === "1",
                'custom_protocols' => (string)$this->protocols->custom_protocols
            ],
            'detection' => [
                'virus_signatures' => (string)$this->detection->virus_signatures === "1",
                'trojan_detection' => (string)$this->detection->trojan_detection === "1",
                'crypto_mining' => (string)$this->detection->crypto_mining === "1",
                'data_exfiltration' => (string)$this->detection->data_exfiltration === "1",
                'command_injection' => (string)$this->detection->command_injection === "1",
                'sql_injection' => (string)$this->detection->sql_injection === "1",
                'script_injection' => (string)$this->detection->script_injection === "1",
                'suspicious_downloads' => (string)$this->detection->suspicious_downloads === "1",
                'phishing_detection' => (string)$this->detection->phishing_detection === "1",
                'botnet_detection' => (string)$this->detection->botnet_detection === "1",
                'steganography_detection' => (string)$this->detection->steganography_detection === "1",
                'zero_day_heuristics' => (string)$this->detection->zero_day_heuristics === "1"
            ],
            'advanced' => [
                'signature_updates' => (string)$this->advanced->signature_updates === "1",
                'update_interval' => (int)(string)$this->advanced->update_interval,
                'threat_intelligence_feeds' => (string)$this->advanced->threat_intelligence_feeds,
                'custom_signatures' => (string)$this->advanced->custom_signatures,
                'quarantine_enabled' => (string)$this->advanced->quarantine_enabled === "1",
                'quarantine_path' => (string)$this->advanced->quarantine_path,
                'memory_limit' => (int)(string)$this->advanced->memory_limit,
                'thread_count' => (int)(string)$this->advanced->thread_count,
                'packet_buffer_size' => (int)(string)$this->advanced->packet_buffer_size,
                'analysis_timeout' => (int)(string)$this->advanced->analysis_timeout,
                'bypass_trusted_networks' => (string)$this->advanced->bypass_trusted_networks === "1",
                'industrial_optimization' => (string)$this->advanced->industrial_optimization === "1",
                'scada_protocols' => (string)$this->advanced->scada_protocols === "1",
                'plc_protocols' => (string)$this->advanced->plc_protocols === "1",
                'latency_threshold' => (int)(string)$this->advanced->latency_threshold
            ]
        ];

        return $config;
    }
}