<?php

/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
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

namespace OPNsense\WebGuard;

use OPNsense\Base\BaseModel;

/**
 * Class WebGuard Settings Model
 * @package OPNsense\WebGuard
 */
class WebGuard extends BaseModel
{
    /**
     * Validate configuration before saving
     * @return array validation errors
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        
        // Custom validation logic
        if ($this->general->enabled->__toString() === '1') {
            // Check if at least one interface is selected
            if (empty($this->general->interfaces->__toString())) {
                $messages[] = "At least one interface must be selected when WebGuard is enabled.";
            }
            
            // Check if protected networks are defined
            if (empty($this->general->protected_networks->__toString())) {
                $messages[] = "Protected networks must be defined when WebGuard is enabled.";
            }
            
            // Validate learning period range
            $learningPeriod = (int)$this->general->learning_period->__toString();
            if ($learningPeriod < 24 || $learningPeriod > 720) {
                $messages[] = "Learning period must be between 24 and 720 hours.";
            }
            
            // Validate auto-block threshold
            $autoBlockThreshold = (int)$this->general->auto_block_threshold->__toString();
            if ($autoBlockThreshold < 1 || $autoBlockThreshold > 100) {
                $messages[] = "Auto-block threshold must be between 1 and 100.";
            }
            
            // Validate block duration
            $blockDuration = (int)$this->general->block_duration->__toString();
            if ($blockDuration < 60 || $blockDuration > 86400) {
                $messages[] = "Block duration must be between 60 and 86400 seconds.";
            }
            
            // Validate webhook URL if provided
            $webhookUrl = $this->response->notification_webhook->__toString();
            if (!empty($webhookUrl) && !filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
                $messages[] = "Notification webhook must be a valid URL.";
            }
        }
        
        return $messages;
    }
    
    /**
     * Get WAF protection status
     * @return bool
     */
    public function isWafEnabled()
    {
        return $this->general->enabled->__toString() === '1' && 
               in_array($this->general->mode->__toString(), ['protection', 'zero_trust']);
    }
    
    /**
     * Get behavioral analysis status
     * @return bool
     */
    public function isBehavioralEnabled()
    {
        return $this->general->enabled->__toString() === '1' && 
               $this->behavioral->anomaly_detection->__toString() === '1';
    }
    
    /**
     * Get covert channels detection status
     * @return bool
     */
    public function isCovertChannelsEnabled()
    {
        return $this->general->enabled->__toString() === '1' && 
               $this->covert_channels->dns_tunneling_detection->__toString() === '1';
    }
    
    /**
     * Get configuration array for engine
     * @return array
     */
    public function getEngineConfig()
    {
        return [
            'general' => [
                'enabled' => $this->general->enabled->__toString() === '1',
                'mode' => $this->general->mode->__toString(),
                'interfaces' => explode(',', $this->general->interfaces->__toString()),
                'protected_networks' => explode(',', $this->general->protected_networks->__toString()),
                'learning_period' => (int)$this->general->learning_period->__toString(),
                'sensitivity_level' => $this->general->sensitivity_level->__toString(),
                'auto_block_threshold' => (int)$this->general->auto_block_threshold->__toString(),
                'block_duration' => (int)$this->general->block_duration->__toString(),
                'ssl_inspection' => $this->general->ssl_inspection->__toString() === '1',
                'geo_blocking' => $this->general->geo_blocking->__toString() === '1',
                'rate_limiting' => $this->general->rate_limiting->__toString() === '1',
                'log_level' => $this->general->log_level->__toString()
            ],
            'waf' => [
                'sql_injection_protection' => $this->waf->sql_injection_protection->__toString() === '1',
                'xss_protection' => $this->waf->xss_protection->__toString() === '1',
                'csrf_protection' => $this->waf->csrf_protection->__toString() === '1',
                'rfi_protection' => $this->waf->rfi_protection->__toString() === '1',
                'lfi_protection' => $this->waf->lfi_protection->__toString() === '1',
                'directory_traversal_protection' => $this->waf->directory_traversal_protection->__toString() === '1',
                'command_injection_protection' => $this->waf->command_injection_protection->__toString() === '1',
                'http_protocol_validation' => $this->waf->http_protocol_validation->__toString() === '1',
                'file_upload_protection' => $this->waf->file_upload_protection->__toString() === '1',
                'session_protection' => $this->waf->session_protection->__toString() === '1',
                'custom_rules' => $this->waf->custom_rules->__toString()
            ],
            'behavioral' => [
                'anomaly_detection' => $this->behavioral->anomaly_detection->__toString() === '1',
                'beaconing_detection' => $this->behavioral->beaconing_detection->__toString() === '1',
                'data_exfiltration_detection' => $this->behavioral->data_exfiltration_detection->__toString() === '1',
                'traffic_pattern_analysis' => $this->behavioral->traffic_pattern_analysis->__toString() === '1',
                'user_behavior_profiling' => $this->behavioral->user_behavior_profiling->__toString() === '1',
                'timing_analysis' => $this->behavioral->timing_analysis->__toString() === '1',
                'entropy_analysis' => $this->behavioral->entropy_analysis->__toString() === '1',
                'baseline_learning' => $this->behavioral->baseline_learning->__toString() === '1'
            ],
            'covert_channels' => [
                'dns_tunneling_detection' => $this->covert_channels->dns_tunneling_detection->__toString() === '1',
                'http_steganography_detection' => $this->covert_channels->http_steganography_detection->__toString() === '1',
                'icmp_tunneling_detection' => $this->covert_channels->icmp_tunneling_detection->__toString() === '1',
                'protocol_anomaly_detection' => $this->covert_channels->protocol_anomaly_detection->__toString() === '1',
                'payload_entropy_analysis' => $this->covert_channels->payload_entropy_analysis->__toString() === '1',
                'timing_channel_detection' => $this->covert_channels->timing_channel_detection->__toString() === '1',
                'size_pattern_analysis' => $this->covert_channels->size_pattern_analysis->__toString() === '1'
            ],
            'response' => [
                'auto_blocking' => $this->response->auto_blocking->__toString() === '1',
                'progressive_blocking' => $this->response->progressive_blocking->__toString() === '1',
                'session_termination' => $this->response->session_termination->__toString() === '1',
                'honeypot_redirect' => $this->response->honeypot_redirect->__toString() === '1',
                'tarpit_mode' => $this->response->tarpit_mode->__toString() === '1',
                'notification_webhook' => $this->response->notification_webhook->__toString(),
                'siem_integration' => $this->response->siem_integration->__toString() === '1'
            ],
            'whitelist' => [
                'trusted_sources' => explode(',', $this->whitelist->trusted_sources->__toString()),
                'trusted_user_agents' => explode("\n", $this->whitelist->trusted_user_agents->__toString()),
                'bypass_urls' => explode("\n", $this->whitelist->bypass_urls->__toString())
            ]
        ];
    }
}