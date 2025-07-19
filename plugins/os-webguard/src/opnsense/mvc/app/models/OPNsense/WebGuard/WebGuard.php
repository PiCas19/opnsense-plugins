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

class WebGuard extends BaseModel
{
    /**
     * Verifica se WebGuard è abilitato
     * @return bool
     */
    public function isEnabled()
    {
        try {
            return (string)$this->general->enabled === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Ottiene la modalità operativa corrente
     * @return string
     */
    public function getOperationMode()
    {
        try {
            return (string)$this->general->mode;
        } catch (\Exception $e) {
            return 'learning';
        }
    }
    
    /**
     * Verifica se l'analisi comportamentale è abilitata
     * @return bool
     */
    public function isBehavioralEnabled()
    {
        try {
            return (string)$this->behavioral->anomaly_detection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il blocco automatico è abilitato
     * @return bool
     */
    public function isAutoBlockingEnabled()
    {
        try {
            return (string)$this->response->auto_blocking === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il blocco progressivo è abilitato
     * @return bool
     */
    public function isProgressiveBlockingEnabled()
    {
        try {
            return (string)$this->response->progressive_blocking === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il blocco geografico è abilitato
     * @return bool
     */
    public function isGeoBlockingEnabled()
    {
        try {
            return (string)$this->general->geo_blocking === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se la protezione WAF è abilitata
     * @return bool
     */
    public function isWafEnabled()
    {
        try {
            return (string)$this->waf->sql_injection_protection === '1' ||
                   (string)$this->waf->xss_protection === '1' ||
                   (string)$this->waf->csrf_protection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se la rilevazione di canali nascosti è abilitata
     * @return bool
     */
    public function isCovertChannelDetectionEnabled()
    {
        try {
            return (string)$this->covert_channels->dns_tunneling_detection === '1' ||
                   (string)$this->covert_channels->http_steganography_detection === '1' ||
                   (string)$this->covert_channels->icmp_tunneling_detection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se l'ispezione SSL è abilitata
     * @return bool
     */
    public function isSslInspectionEnabled()
    {
        try {
            return (string)$this->general->ssl_inspection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il rate limiting è abilitato
     * @return bool
     */
    public function isRateLimitingEnabled()
    {
        try {
            return (string)$this->general->rate_limiting === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Ottiene il livello di sensibilità
     * @return string
     */
    public function getSensitivityLevel()
    {
        try {
            return (string)$this->general->sensitivity_level;
        } catch (\Exception $e) {
            return 'medium';
        }
    }
    
    /**
     * Ottiene la soglia di auto-blocco
     * @return int
     */
    public function getAutoBlockThreshold()
    {
        try {
            return (int)$this->general->auto_block_threshold;
        } catch (\Exception $e) {
            return 5;
        }
    }
    
    /**
     * Ottiene la durata del blocco (in secondi)
     * @return int
     */
    public function getBlockDuration()
    {
        try {
            return (int)$this->general->block_duration;
        } catch (\Exception $e) {
            return 3600;
        }
    }
    
    /**
     * Ottiene il periodo di apprendimento (in ore)
     * @return int
     */
    public function getLearningPeriod()
    {
        try {
            return (int)$this->general->learning_period;
        } catch (\Exception $e) {
            return 168;
        }
    }
    
    /**
     * Ottiene il livello di logging
     * @return string
     */
    public function getLogLevel()
    {
        try {
            return (string)$this->general->log_level;
        } catch (\Exception $e) {
            return 'info';
        }
    }
    
    /**
     * Ottiene le reti protette
     * @return string
     */
    public function getProtectedNetworks()
    {
        try {
            return (string)$this->general->protected_networks;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Ottiene le interfacce protette
     * @return string
     */
    public function getProtectedInterfaces()
    {
        try {
            return (string)$this->general->interfaces;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Verifica se il honeypot redirect è abilitato
     * @return bool
     */
    public function isHoneypotRedirectEnabled()
    {
        try {
            return (string)$this->response->honeypot_redirect === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il tarpit mode è abilitato
     * @return bool
     */
    public function isTarpitModeEnabled()
    {
        try {
            return (string)$this->response->tarpit_mode === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se l'integrazione SIEM è abilitata
     * @return bool
     */
    public function isSiemIntegrationEnabled()
    {
        try {
            return (string)$this->response->siem_integration === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Ottiene l'URL del webhook per le notifiche
     * @return string
     */
    public function getNotificationWebhook()
    {
        try {
            return (string)$this->response->notification_webhook;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Ottiene le sorgenti fidate
     * @return string
     */
    public function getTrustedSources()
    {
        try {
            return (string)$this->whitelist->trusted_sources;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Ottiene gli User-Agent fidati
     * @return string
     */
    public function getTrustedUserAgents()
    {
        try {
            return (string)$this->whitelist->trusted_user_agents;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Ottiene gli URL da bypassare
     * @return string
     */
    public function getBypassUrls()
    {
        try {
            return (string)$this->whitelist->bypass_urls;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Ottiene le regole WAF personalizzate
     * @return string
     */
    public function getCustomWafRules()
    {
        try {
            return (string)$this->waf->custom_rules;
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Verifica se una specifica protezione WAF è abilitata
     * @param string $protectionType
     * @return bool
     */
    public function isWafProtectionEnabled($protectionType)
    {
        try {
            switch ($protectionType) {
                case 'sql_injection':
                    return (string)$this->waf->sql_injection_protection === '1';
                case 'xss':
                    return (string)$this->waf->xss_protection === '1';
                case 'csrf':
                    return (string)$this->waf->csrf_protection === '1';
                case 'rfi':
                    return (string)$this->waf->rfi_protection === '1';
                case 'lfi':
                    return (string)$this->waf->lfi_protection === '1';
                case 'directory_traversal':
                    return (string)$this->waf->directory_traversal_protection === '1';
                case 'command_injection':
                    return (string)$this->waf->command_injection_protection === '1';
                case 'http_protocol':
                    return (string)$this->waf->http_protocol_validation === '1';
                case 'file_upload':
                    return (string)$this->waf->file_upload_protection === '1';
                case 'session':
                    return (string)$this->waf->session_protection === '1';
                default:
                    return false;
            }
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se una specifica rilevazione comportamentale è abilitata
     * @param string $detectionType
     * @return bool
     */
    public function isBehavioralDetectionEnabled($detectionType)
    {
        try {
            switch ($detectionType) {
                case 'anomaly':
                    return (string)$this->behavioral->anomaly_detection === '1';
                case 'beaconing':
                    return (string)$this->behavioral->beaconing_detection === '1';
                case 'data_exfiltration':
                    return (string)$this->behavioral->data_exfiltration_detection === '1';
                case 'traffic_pattern':
                    return (string)$this->behavioral->traffic_pattern_analysis === '1';
                case 'user_behavior':
                    return (string)$this->behavioral->user_behavior_profiling === '1';
                case 'timing':
                    return (string)$this->behavioral->timing_analysis === '1';
                case 'entropy':
                    return (string)$this->behavioral->entropy_analysis === '1';
                case 'baseline_learning':
                    return (string)$this->behavioral->baseline_learning === '1';
                default:
                    return false;
            }
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se una specifica rilevazione di canali nascosti è abilitata
     * @param string $channelType
     * @return bool
     */
    public function isCovertChannelDetectionTypeEnabled($channelType)
    {
        try {
            switch ($channelType) {
                case 'dns_tunneling':
                    return (string)$this->covert_channels->dns_tunneling_detection === '1';
                case 'http_steganography':
                    return (string)$this->covert_channels->http_steganography_detection === '1';
                case 'icmp_tunneling':
                    return (string)$this->covert_channels->icmp_tunneling_detection === '1';
                case 'protocol_anomaly':
                    return (string)$this->covert_channels->protocol_anomaly_detection === '1';
                case 'payload_entropy':
                    return (string)$this->covert_channels->payload_entropy_analysis === '1';
                case 'timing_channel':
                    return (string)$this->covert_channels->timing_channel_detection === '1';
                case 'size_pattern':
                    return (string)$this->covert_channels->size_pattern_analysis === '1';
                default:
                    return false;
            }
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se una specifica risposta automatica è abilitata
     * @param string $responseType
     * @return bool
     */
    public function isResponseTypeEnabled($responseType)
    {
        try {
            switch ($responseType) {
                case 'auto_blocking':
                    return (string)$this->response->auto_blocking === '1';
                case 'progressive_blocking':
                    return (string)$this->response->progressive_blocking === '1';
                case 'session_termination':
                    return (string)$this->response->session_termination === '1';
                case 'honeypot_redirect':
                    return (string)$this->response->honeypot_redirect === '1';
                case 'tarpit_mode':
                    return (string)$this->response->tarpit_mode === '1';
                case 'siem_integration':
                    return (string)$this->response->siem_integration === '1';
                default:
                    return false;
            }
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Ottiene un riepilogo dello stato della configurazione
     * @return array
     */
    public function getConfigurationSummary()
    {
        try {
            return [
                'enabled' => $this->isEnabled(),
                'mode' => $this->getOperationMode(),
                'sensitivity' => $this->getSensitivityLevel(),
                'waf_enabled' => $this->isWafEnabled(),
                'behavioral_enabled' => $this->isBehavioralEnabled(),
                'covert_detection_enabled' => $this->isCovertChannelDetectionEnabled(),
                'auto_blocking_enabled' => $this->isAutoBlockingEnabled(),
                'geo_blocking_enabled' => $this->isGeoBlockingEnabled(),
                'ssl_inspection_enabled' => $this->isSslInspectionEnabled(),
                'rate_limiting_enabled' => $this->isRateLimitingEnabled(),
                'block_threshold' => $this->getAutoBlockThreshold(),
                'block_duration' => $this->getBlockDuration(),
                'learning_period' => $this->getLearningPeriod(),
                'log_level' => $this->getLogLevel()
            ];
        } catch (\Exception $e) {
            return [
                'enabled' => false,
                'mode' => 'learning',
                'sensitivity' => 'medium',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Verifica se il sistema è in modalità di apprendimento
     * @return bool
     */
    public function isInLearningMode()
    {
        try {
            return $this->getOperationMode() === 'learning';
        } catch (\Exception $e) {
            return true;
        }
    }
    
    /**
     * Verifica se il sistema è in modalità di protezione attiva
     * @return bool
     */
    public function isInProtectionMode()
    {
        try {
            return $this->getOperationMode() === 'protection';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il sistema è in modalità zero trust
     * @return bool
     */
    public function isInZeroTrustMode()
    {
        try {
            return $this->getOperationMode() === 'zero_trust';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Ottiene le voci del menu (per compatibilità)
     * @return array
     */
    public function getMenuEntries()
    {
        return array();
    }
    
    /**
     * Valida la configurazione corrente
     * @return array Array con eventuali errori o avvisi di configurazione
     */
    public function validateConfiguration()
    {
        $issues = [];
        
        try {
            // Verifica se ci sono interfacce configurate
            if (empty($this->getProtectedInterfaces())) {
                $issues[] = 'No protected interfaces configured';
            }
            
            // Verifica se ci sono reti protette configurate
            if (empty($this->getProtectedNetworks())) {
                $issues[] = 'No protected networks configured';
            }
            
            // Verifica se almeno una protezione è abilitata
            if (!$this->isWafEnabled() && !$this->isBehavioralEnabled() && !$this->isCovertChannelDetectionEnabled()) {
                $issues[] = 'No protection modules enabled';
            }
            
            // Verifica configurazione del blocco automatico
            if ($this->isAutoBlockingEnabled() && $this->getAutoBlockThreshold() <= 0) {
                $issues[] = 'Auto-blocking enabled but threshold is invalid';
            }
            
            // Verifica durata del blocco
            if ($this->getBlockDuration() <= 0) {
                $issues[] = 'Block duration must be greater than 0';
            }
            
            // Verifica periodo di apprendimento
            if ($this->getLearningPeriod() < 24) {
                $issues[] = 'Learning period should be at least 24 hours';
            }
            
        } catch (\Exception $e) {
            $issues[] = 'Configuration validation error: ' . $e->getMessage();
        }
        
        return $issues;
    }
}