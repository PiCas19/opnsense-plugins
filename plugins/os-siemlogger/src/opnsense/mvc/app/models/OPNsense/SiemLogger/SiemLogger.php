<?php

/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
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

namespace OPNsense\SiemLogger;

use OPNsense\Base\BaseModel;

class SiemLogger extends BaseModel
{
    /**
     * Check if SIEM Logger is enabled
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
     * Get the logging level
     * @return string
     */
    public function getLogLevel()
    {
        try {
            return (string)$this->general->log_level;
        } catch (\Exception $e) {
            return 'INFO';
        }
    }

    /**
     * Get the maximum log file size (in MB)
     * @return int
     */
    public function getMaxLogSize()
    {
        try {
            return (int)$this->general->max_log_size;
        } catch (\Exception $e) {
            return 100;
        }
    }

    /**
     * Get the log retention period (in days)
     * @return int
     */
    public function getRetentionDays()
    {
        try {
            return (int)$this->general->retention_days;
        } catch (\Exception $e) {
            return 30;
        }
    }

    /**
     * Check if SIEM export is enabled
     * @return bool
     */
    public function isExportEnabled()
    {
        try {
            return (string)$this->siem_export->export_enabled === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get the SIEM export format
     * @return string
     */
    public function getExportFormat()
    {
        try {
            return (string)$this->siem_export->export_format;
        } catch (\Exception $e) {
            return 'syslog';
        }
    }

    /**
     * Get the SIEM server hostname or IP
     * @return string
     */
    public function getSiemServer()
    {
        try {
            return (string)$this->siem_export->siem_server;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Get the SIEM server port
     * @return int
     */
    public function getSiemPort()
    {
        try {
            return (int)$this->siem_export->siem_port;
        } catch (\Exception $e) {
            return 514;
        }
    }

    /**
     * Get the SIEM export protocol
     * @return string
     */
    public function getExportProtocol()
    {
        try {
            return (string)$this->siem_export->protocol;
        } catch (\Exception $e) {
            return 'udp';
        }
    }

    /**
     * Get the syslog facility
     * @return string
     */
    public function getFacility()
    {
        try {
            return (string)$this->siem_export->facility;
        } catch (\Exception $e) {
            return 'local0';
        }
    }

    /**
     * Get the TLS certificate path
     * @return string
     */
    public function getTlsCert()
    {
        try {
            return (string)$this->siem_export->tls_cert;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Get the export batch size
     * @return int
     */
    public function getBatchSize()
    {
        try {
            return (int)$this->siem_export->batch_size;
        } catch (\Exception $e) {
            return 100;
        }
    }

    /**
     * Get the export interval (in seconds)
     * @return int
     */
    public function getExportInterval()
    {
        try {
            return (int)$this->siem_export->export_interval;
        } catch (\Exception $e) {
            return 60;
        }
    }

    /**
     * Check if a specific logging rule is enabled
     * @param string $ruleType
     * @return bool
     */
    public function isLoggingRuleEnabled($ruleType)
    {
        try {
            switch ($ruleType) {
                case 'authentication':
                    return (string)$this->logging_rules->log_authentication === '1';
                case 'authorization':
                    return (string)$this->logging_rules->log_authorization === '1';
                case 'configuration_changes':
                    return (string)$this->logging_rules->log_configuration_changes === '1';
                case 'network_events':
                    return (string)$this->logging_rules->log_network_events === '1';
                case 'system_events':
                    return (string)$this->logging_rules->log_system_events === '1';
                case 'firewall_events':
                    return (string)$this->logging_rules->log_firewall_events === '1';
                case 'vpn_events':
                    return (string)$this->logging_rules->log_vpn_events === '1';
                default:
                    return false;
            }
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get custom log file paths
     * @return string
     */
    public function getCustomLogPaths()
    {
        try {
            return (string)$this->logging_rules->custom_log_paths;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Check if auditing is enabled
     * @return bool
     */
    public function isAuditEnabled()
    {
        try {
            return (string)$this->audit_settings->audit_enabled === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if a specific audit rule is enabled
     * @param string $auditType
     * @return bool
     */
    public function isAuditRuleEnabled($auditType)
    {
        try {
            switch ($auditType) {
                case 'failed_logins':
                    return (string)$this->audit_settings->audit_failed_logins === '1';
                case 'admin_actions':
                    return (string)$this->audit_settings->audit_admin_actions === '1';
                case 'privilege_escalation':
                    return (string)$this->audit_settings->audit_privilege_escalation === '1';
                case 'file_access':
                    return (string)$this->audit_settings->audit_file_access === '1';
                default:
                    return false;
            }
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get the suspicious activity threshold
     * @return int
     */
    public function getSuspiciousActivityThreshold()
    {
        try {
            return (int)$this->audit_settings->suspicious_activity_threshold;
        } catch (\Exception $e) {
            return 5;
        }
    }

    /**
     * Check if email alerts are enabled
     * @return bool
     */
    public function isEmailAlertsEnabled()
    {
        try {
            return (string)$this->notifications->email_alerts === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get email recipients
     * @return string
     */
    public function getEmailRecipients()
    {
        try {
            return (string)$this->notifications->email_recipients;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Check if alerts on failed export are enabled
     * @return bool
     */
    public function isAlertOnFailedExportEnabled()
    {
        try {
            return (string)$this->notifications->alert_on_failed_export === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if alerts on suspicious activity are enabled
     * @return bool
     */
    public function isAlertOnSuspiciousActivityEnabled()
    {
        try {
            return (string)$this->notifications->alert_on_suspicious_activity === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get the webhook URL for notifications
     * @return string
     */
    public function getWebhookUrl()
    {
        try {
            return (string)$this->notifications->webhook_url;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Get the health check interval (in seconds)
     * @return int
     */
    public function getHealthCheckInterval()
    {
        try {
            return (int)$this->monitoring->health_check_interval;
        } catch (\Exception $e) {
            return 300;
        }
    }

    /**
     * Check if metrics collection is enabled
     * @return bool
     */
    public function isMetricsCollectionEnabled()
    {
        try {
            return (string)$this->monitoring->metrics_collection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if performance monitoring is enabled
     * @return bool
     */
    public function isPerformanceMonitoringEnabled()
    {
        try {
            return (string)$this->monitoring->performance_monitoring === '1';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get the disk usage threshold (percentage)
     * @return int
     */
    public function getDiskUsageThreshold()
    {
        try {
            return (int)$this->monitoring->disk_usage_threshold;
        } catch (\Exception $e) {
            return 80;
        }
    }

    /**
     * Get a summary of the configuration state
     * @return array
     */
    public function getConfigurationSummary()
    {
        try {
            return [
                'enabled' => $this->isEnabled(),
                'log_level' => $this->getLogLevel(),
                'max_log_size' => $this->getMaxLogSize(),
                'retention_days' => $this->getRetentionDays(),
                'export_enabled' => $this->isExportEnabled(),
                'export_format' => $this->getExportFormat(),
                'siem_server' => $this->getSiemServer(),
                'audit_enabled' => $this->isAuditEnabled(),
                'email_alerts_enabled' => $this->isEmailAlertsEnabled(),
                'metrics_collection_enabled' => $this->isMetricsCollectionEnabled(),
                'disk_usage_threshold' => $this->getDiskUsageThreshold()
            ];
        } catch (\Exception $e) {
            return [
                'enabled' => false,
                'log_level' => 'INFO',
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Validate the current configuration
     * @return array Array of configuration issues or warnings
     */
    public function validateConfiguration()
    {
        $issues = [];

        try {
            // Check if SIEM export is enabled but server is not configured
            if ($this->isExportEnabled() && empty($this->getSiemServer())) {
                $issues[] = 'SIEM export enabled but no server configured';
            }

            // Check if TLS protocol is selected but no certificate is provided
            if ($this->getExportProtocol() === 'tls' && empty($this->getTlsCert())) {
                $issues[] = 'TLS protocol selected but no certificate configured';
            }

            // Check if email alerts are enabled but no recipients are configured
            if ($this->isEmailAlertsEnabled() && empty($this->getEmailRecipients())) {
                $issues[] = 'Email alerts enabled but no recipients configured';
            }

            // Check if any logging rules are enabled
            $logging_enabled = $this->isLoggingRuleEnabled('authentication') ||
                               $this->isLoggingRuleEnabled('authorization') ||
                               $this->isLoggingRuleEnabled('configuration_changes') ||
                               $this->isLoggingRuleEnabled('network_events') ||
                               $this->isLoggingRuleEnabled('system_events') ||
                               $this->isLoggingRuleEnabled('firewall_events') ||
                               $this->isLoggingRuleEnabled('vpn_events');
            if (!$logging_enabled && empty($this->getCustomLogPaths())) {
                $issues[] = 'No logging rules or custom log paths configured';
            }

            // Check if audit is enabled but no audit rules are configured
            if ($this->isAuditEnabled()) {
                $audit_enabled = $this->isAuditRuleEnabled('failed_logins') ||
                                 $this->isAuditRuleEnabled('admin_actions') ||
                                 $this->isAuditRuleEnabled('privilege_escalation') ||
                                 $this->isAuditRuleEnabled('file_access');
                if (!$audit_enabled) {
                    $issues[] = 'Audit enabled but no audit rules configured';
                }
            }

            // Check if max log size is valid
            if ($this->getMaxLogSize() < 10 || $this->getMaxLogSize() > 1000) {
                $issues[] = 'Maximum log size must be between 10 and 1000 MB';
            }

            // Check if retention days is valid
            if ($this->getRetentionDays() < 1 || $this->getRetentionDays() > 365) {
                $issues[] = 'Log retention period must be between 1 and 365 days';
            }

            // Check if suspicious activity threshold is valid
            if ($this->getSuspiciousActivityThreshold() < 1 || $this->getSuspiciousActivityThreshold() > 100) {
                $issues[] = 'Suspicious activity threshold must be between 1 and 100';
            }

            // Check if health check interval is valid
            if ($this->getHealthCheckInterval() < 60 || $this->getHealthCheckInterval() > 3600) {
                $issues[] = 'Health check interval must be between 60 and 3600 seconds';
            }

            // Check if disk usage threshold is valid
            if ($this->getDiskUsageThreshold() < 50 || $this->getDiskUsageThreshold() > 95) {
                $issues[] = 'Disk usage threshold must be between 50 and 95 percent';
            }

        } catch (\Exception $e) {
            $issues[] = 'Configuration validation error: ' . $e->getMessage();
        }

        return $issues;
    }

    /**
     * Mark configuration as changed when data is pushed back to the config
     */
    public function serializeToConfig($validateFullModel = false, $disable_validation = false)
    {
        @touch("/tmp/siemlogger.dirty");
        return parent::serializeToConfig($validateFullModel, $disable_validation);
    }

    /**
     * Get configuration state
     * @return bool
     */
    public function configChanged()
    {
        return file_exists("/tmp/siemlogger.dirty");
    }

    /**
     * Mark configuration as consistent with the running config
     * @return bool
     */
    public function configClean()
    {
        return @unlink("/tmp/siemlogger.dirty");
    }

    /**
     * Export configuration for the SIEM Logger service
     * @return array
     */
    public function exportForEngine()
    {
        $config = [
            'general' => [
                'enabled' => (string)$this->general->enabled === '1',
                'log_level' => (string)$this->general->log_level,
                'max_log_size' => (int)$this->general->max_log_size,
                'retention_days' => (int)$this->general->retention_days
            ],
            'siem_export' => [
                'export_enabled' => (string)$this->siem_export->export_enabled === '1',
                'export_format' => (string)$this->siem_export->export_format,
                'siem_server' => (string)$this->siem_export->siem_server,
                'siem_port' => (int)$this->siem_export->siem_port,
                'protocol' => (string)$this->siem_export->protocol,
                'facility' => (string)$this->siem_export->facility,
                'tls_cert' => (string)$this->siem_export->tls_cert,
                'batch_size' => (int)$this->siem_export->batch_size,
                'export_interval' => (int)$this->siem_export->export_interval
            ],
            'logging_rules' => [
                'log_authentication' => (string)$this->logging_rules->log_authentication === '1',
                'log_authorization' => (string)$this->logging_rules->log_authorization === '1',
                'log_configuration_changes' => (string)$this->logging_rules->log_configuration_changes === '1',
                'log_network_events' => (string)$this->logging_rules->log_network_events === '1',
                'log_system_events' => (string)$this->logging_rules->log_system_events === '1',
                'log_firewall_events' => (string)$this->logging_rules->log_firewall_events === '1',
                'log_vpn_events' => (string)$this->logging_rules->log_vpn_events === '1',
                'custom_log_paths' => array_filter(explode(',', (string)$this->logging_rules->custom_log_paths))
            ],
            'audit_settings' => [
                'audit_enabled' => (string)$this->audit_settings->audit_enabled === '1',
                'audit_failed_logins' => (string)$this->audit_settings->audit_failed_logins === '1',
                'audit_admin_actions' => (string)$this->audit_settings->audit_admin_actions === '1',
                'audit_privilege_escalation' => (string)$this->audit_settings->audit_privilege_escalation === '1',
                'audit_file_access' => (string)$this->audit_settings->audit_file_access === '1',
                'suspicious_activity_threshold' => (int)$this->audit_settings->suspicious_activity_threshold
            ],
            'notifications' => [
                'email_alerts' => (string)$this->notifications->email_alerts === '1',
                'email_recipients' => array_filter(explode(',', (string)$this->notifications->email_recipients)),
                'alert_on_failed_export' => (string)$this->notifications->alert_on_failed_export === '1',
                'alert_on_suspicious_activity' => (string)$this->notifications->alert_on_suspicious_activity === '1',
                'webhook_url' => (string)$this->notifications->webhook_url
            ],
            'monitoring' => [
                'health_check_interval' => (int)$this->monitoring->health_check_interval,
                'metrics_collection' => (string)$this->monitoring->metrics_collection === '1',
                'performance_monitoring' => (string)$this->monitoring->performance_monitoring === '1',
                'disk_usage_threshold' => (int)$this->monitoring->disk_usage_threshold
            ]
        ];

        return $config;
    }

    /**
     * Get menu entries (for compatibility)
     * @return array
     */
    public function getMenuEntries()
    {
        return [];
    }
}