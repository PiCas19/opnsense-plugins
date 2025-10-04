<?php
/*
 * Copyright (C) 2025 Pierpaolo Casati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
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
use OPNsense\Base\Messages\Message;

/**
 * DeepInspector model for Deep Packet Inspection
 *
 * Manages comprehensive validation and configuration for deep packet inspection
 * following Zero Trust security principles with industrial protocol support.
 * Provides advanced threat detection and network analysis capabilities.
 *
 * @package OPNsense\DeepInspector
 */
class DeepInspector extends BaseModel
{
    /**
     * Performs comprehensive validation on the model
     *
     * Validates all aspects of DPI configuration including:
     * - General settings and interface requirements
     * - Performance profile and mode compatibility
     * - Network format validation (CIDR)
     * - SSL inspection dependencies
     * - Detection engine dependencies
     * - Performance vs security trade-offs
     *
     * @param bool $validateFullModel Whether to validate the entire model
     * @return \OPNsense\Base\Messages\Message Collection of validation messages
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        // Validate general settings
        if ($validateFullModel || $this->general->enabled->isFieldChanged()) {
            if ((string)$this->general->enabled === "1") {
                // Check if at least one interface is selected
                if (empty((string)$this->general->interfaces)) {
                    $messages->appendMessage(new Message(
                        gettext('At least one interface must be selected when DPI is enabled.'),
                        'general.' . $this->general->interfaces->getInternalXMLTagName()
                    ));
                }

                // Validate performance profile requirements
                $profile = (string)$this->general->performance_profile;
                $mode = (string)$this->general->mode;
                
                if ($profile === 'high_security' && $mode === 'learning') {
                    $messages->appendMessage(new Message(
                        gettext('High Security profile is not compatible with Learning mode.'),
                        'general.' . $this->general->mode->getInternalXMLTagName()
                    ));
                }
            }
        }

        // Validate trusted networks format
        if ($validateFullModel || $this->general->trusted_networks->isFieldChanged()) {
            $networks = (string)$this->general->trusted_networks;
            if (!empty($networks)) {
                $networkList = explode(',', $networks);
                foreach ($networkList as $network) {
                    $network = trim($network);
                    if (!empty($network) && !preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $network)) {
                        $messages->appendMessage(new Message(
                            sprintf(gettext('Invalid network format: %s. Use CIDR notation (e.g., 192.168.1.0/24)'), $network),
                            'general.' . $this->general->trusted_networks->getInternalXMLTagName()
                        ));
                    }
                }
            }
        }

        // Validate deep scan ports
        if ($validateFullModel || $this->general->deep_scan_ports->isFieldChanged()) {
            $ports = (string)$this->general->deep_scan_ports;
            if (!empty($ports) && !preg_match('/^[0-9,-\s]*$/', $ports)) {
                $messages->appendMessage(new Message(
                    gettext('Deep scan ports must contain only numbers, commas, dashes and spaces.'),
                    'general.' . $this->general->deep_scan_ports->getInternalXMLTagName()
                ));
            }
        }

        // Validate packet size
        if ($validateFullModel || $this->general->max_packet_size->isFieldChanged()) {
            $size = (int)(string)$this->general->max_packet_size;
            if ($size < 64 || $size > 9000) {
                $messages->appendMessage(new Message(
                    gettext('Maximum packet size must be between 64 and 9000 bytes.'),
                    'general.' . $this->general->max_packet_size->getInternalXMLTagName()
                ));
            }
        }

        // Validate SSL inspection requirements
        if ($validateFullModel || $this->general->ssl_inspection->isFieldChanged() || $this->protocols->https_inspection->isFieldChanged()) {
            $sslEnabled = (string)$this->general->ssl_inspection === "1";
            $httpsEnabled = (string)$this->protocols->https_inspection === "1";
            
            if ($httpsEnabled && !$sslEnabled) {
                $messages->appendMessage(new Message(
                    gettext('SSL inspection must be enabled for HTTPS protocol inspection.'),
                    'protocols.' . $this->protocols->https_inspection->getInternalXMLTagName()
                ));
            }
        }

        // Validate detection engine dependencies
        if ($validateFullModel || $this->detection->virus_signatures->isFieldChanged()) {
            $virusEnabled = (string)$this->detection->virus_signatures === "1";
            $malwareEnabled = (string)$this->general->malware_detection === "1";
            
            if ($virusEnabled && !$malwareEnabled) {
                $messages->appendMessage(new Message(
                    gettext('Malware detection must be enabled for virus signature scanning.'),
                    'detection.' . $this->detection->virus_signatures->getInternalXMLTagName()
                ));
            }
        }

        // Validate performance vs security settings
        if ($validateFullModel) {
            $this->validatePerformanceSettings($messages);
        }

        return $messages;
    }

    /**
     * Validates performance settings and warns about potential conflicts
     *
     * Analyzes the relationship between performance profile and enabled
     * detection engines/protocols to ensure optimal configuration.
     *
     * @param \OPNsense\Base\Messages\Message $messages Message collection to append warnings
     * @return void
     */
    private function validatePerformanceSettings($messages)
    {
        $profile = (string)$this->general->performance_profile;
        
        // Count enabled detection engines
        $detectionEngines = [
            'virus_signatures', 'trojan_detection', 'crypto_mining',
            'data_exfiltration', 'command_injection', 'sql_injection', 'script_injection'
        ];
        
        $enabledEngines = 0;
        foreach ($detectionEngines as $engine) {
            if ((string)$this->detection->$engine === "1") {
                $enabledEngines++;
            }
        }

        // Count enabled protocol inspections
        $protocolInspections = [
            'http_inspection', 'https_inspection', 'ftp_inspection',
            'smtp_inspection', 'dns_inspection', 'industrial_protocols'
        ];
        
        $enabledProtocols = 0;
        foreach ($protocolInspections as $protocol) {
            if ((string)$this->protocols->$protocol === "1") {
                $enabledProtocols++;
            }
        }

        // Performance profile validation
        if ($profile === 'high_performance' && ($enabledEngines > 3 || $enabledProtocols > 4)) {
            $messages->appendMessage(new Message(
                gettext('High Performance profile recommends limiting active detection engines and protocol inspections for optimal performance.'),
                'general.' . $this->general->performance_profile->getInternalXMLTagName()
            ));
        }

        if ($profile === 'high_security' && ($enabledEngines < 5 || $enabledProtocols < 4)) {
            $messages->appendMessage(new Message(
                gettext('High Security profile recommends enabling more detection engines and protocol inspections for comprehensive coverage.'),
                'general.' . $this->general->performance_profile->getInternalXMLTagName()
            ));
        }

        // SSL inspection performance warning
        if ((string)$this->general->ssl_inspection === "1" && $profile === 'high_performance') {
            $messages->appendMessage(new Message(
                gettext('SSL inspection may impact performance significantly in High Performance profile.'),
                'general.' . $this->general->ssl_inspection->getInternalXMLTagName()
            ));
        }

        // Archive extraction performance warning
        if ((string)$this->general->archive_extraction === "1" && $profile === 'high_performance') {
            $messages->appendMessage(new Message(
                gettext('Archive extraction may impact performance in High Performance profile.'),
                'general.' . $this->general->archive_extraction->getInternalXMLTagName()
            ));
        }
    }

    /**
     * Serializes configuration to config file and marks as dirty
     *
     * Creates a dirty flag to indicate configuration changes require service reconfiguration.
     *
     * @param bool $validateFullModel Whether to validate the entire model
     * @param bool $disable_validation Whether to disable validation
     * @return mixed Result from parent serialization
     */
    public function serializeToConfig($validateFullModel = false, $disable_validation = false)
    {
        @touch("/tmp/deepinspector.dirty");
        return parent::serializeToConfig($validateFullModel, $disable_validation);
    }

    /**
     * Checks if configuration has changed
     *
     * @return bool True if configuration is dirty (needs reconfiguration)
     */
    public function configChanged()
    {
        return file_exists("/tmp/deepinspector.dirty");
    }

    /**
     * Marks configuration as clean (synchronized with running config)
     *
     * @return bool True on success, false on failure
     */
    public function configClean()
    {
        return @unlink("/tmp/deepinspector.dirty");
    }

    /**
     * Gets summary of current configuration for dashboard
     *
     * Returns a comprehensive summary including enabled state, mode,
     * performance profile, and counts of active protocols and detections.
     *
     * @return array Configuration summary
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

        // Count enabled protocols
        $protocols = ['http_inspection', 'https_inspection', 'ftp_inspection', 'smtp_inspection', 'dns_inspection', 'industrial_protocols'];
        foreach ($protocols as $protocol) {
            if ((string)$this->protocols->$protocol === "1") {
                $summary['enabled_protocols']++;
            }
        }

        // Count enabled detection engines
        $detections = ['virus_signatures', 'trojan_detection', 'crypto_mining', 'data_exfiltration', 'command_injection', 'sql_injection', 'script_injection'];
        foreach ($detections as $detection) {
            if ((string)$this->detection->$detection === "1") {
                $summary['enabled_detections']++;
            }
        }

        return $summary;
    }

    /**
     * Gets industrial optimization recommendations
     *
     * Returns recommended settings for industrial/SCADA environments
     * focusing on low latency and high reliability.
     *
     * @return array Recommended industrial settings
     */
    public function getIndustrialRecommendations()
    {
        return [
            'performance_profile' => 'industrial',
            'low_latency_mode' => '1',
            'industrial_mode' => '1',
            'latency_threshold' => '50',
            'mode' => 'active',
            'ssl_inspection' => '0',  // Disabled for performance
            'archive_extraction' => '0'  // Disabled for performance
        ];
    }

    /**
     * Exports configuration for the DPI engine
     *
     * Converts the model configuration into a format suitable for
     * the deep packet inspection engine with all parameters properly typed.
     *
     * @return array Engine-ready configuration array
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