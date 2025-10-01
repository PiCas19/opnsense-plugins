<?php
/*
 * Copyright (C) 2025 OPNsense Validation Core Library
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

namespace OPNsense\ValidationCore\Validators;

use OPNsense\ValidationCore\Utils\NetworkUtils;

/**
 * Alert Filter Validator
 *
 * Specialized validator for alert filter parameters used in DeepInspector.
 * Validates filter parameters such as severity, threat type, time range,
 * source IP, page number, and limit to ensure they are correctly formatted
 * and logically consistent for querying alerts.
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
class AlertFilterValidator extends AbstractValidator
{
    /**
     * Valid severity levels for alerts
     */
    private const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical', 'all'];

    /**
     * Valid threat types for alerts
     */
    private const VALID_THREAT_TYPES = ['malware', 'intrusion', 'ddos', 'phishing', 'botnet', 'all'];

    /**
     * Valid time range filters
     */
    private const VALID_TIME_RANGES = ['1h', '24h', '7d', '30d', 'all'];

    /**
     * Maximum allowed results per page
     */
    private const MAX_PAGE_LIMIT = 500;

    /**
     * Perform alert filter validation
     */
    protected function performValidation(): void
    {
        $filters = $this->getFieldValue('filters', []);

        if (empty($filters)) {
            $this->addWarning(
                'No filter parameters provided. All alerts will be returned',
                'filters'
            );
            return;
        }

        $this->validateSeverity($filters, 'filters.severity');
        $this->validateThreatType($filters, 'filters.type');
        $this->validateTimeRange($filters, 'filters.time');
        $this->validateSourceIp($filters, 'filters.source');
        $this->validatePagination($filters, 'filters.page', 'filters.limit');
    }

    /**
     * Validate severity filter
     *
     * @param array $filters Filter parameters
     * @param string $fieldPath Field path for error reporting
     */
    protected function validateSeverity(array $filters, string $fieldPath): void
    {
        $severity = strtolower($this->getStringValue('filters.severity', 'all'));

        if (!in_array($severity, self::VALID_SEVERITIES)) {
            $this->addError(
                sprintf(
                    'Invalid severity filter: %s. Must be one of: %s',
                    $severity,
                    implode(', ', self::VALID_SEVERITIES)
                ),
                $fieldPath
            );
        }
    }

    /**
     * Validate threat type filter
     *
     * @param array $filters Filter parameters
     * @param string $fieldPath Field path for error reporting
     */
    protected function validateThreatType(array $filters, string $fieldPath): void
    {
        $type = strtolower($this->getStringValue('filters.type', 'all'));

        if (!in_array($type, self::VALID_THREAT_TYPES)) {
            $this->addError(
                sprintf(
                    'Invalid threat type filter: %s. Must be one of: %s',
                    $type,
                    implode(', ', self::VALID_THREAT_TYPES)
                ),
                $fieldPath
            );
        }
    }

    /**
     * Validate time range filter
     *
     * @param array $filters Filter parameters
     * @param string $fieldPath Field path for error reporting
     */
    protected function validateTimeRange(array $filters, string $fieldPath): void
    {
        $time = strtolower($this->getStringValue('filters.time', '24h'));

        if (!in_array($time, self::VALID_TIME_RANGES)) {
            $this->addError(
                sprintf(
                    'Invalid time range filter: %s. Must be one of: %s',
                    $time,
                    implode(', ', self::VALID_TIME_RANGES)
                ),
                $fieldPath
            );
        }
    }

    /**
     * Validate source IP filter
     *
     * @param array $filters Filter parameters
     * @param string $fieldPath Field path for error reporting
     */
    protected function validateSourceIp(array $filters, string $fieldPath): void
    {
        $source = $this->getStringValue('filters.source', '');

        if (!empty($source)) {
            if (!NetworkUtils::isValidIpAddress($source) && !NetworkUtils::isValidPartialIp($source)) {
                $this->addError(
                    'Source IP filter must be a valid IPv4/IPv6 address or partial address',
                    $fieldPath
                );
            }
        }
    }

    /**
     * Validate pagination parameters
     *
     * @param array $filters Filter parameters
     * @param string $pageFieldPath Field path for page parameter
     * @param string $limitFieldPath Field path for limit parameter
     */
    protected function validatePagination(array $filters, string $pageFieldPath, string $limitFieldPath): void
    {
        $page = $this->getIntValue('filters.page', 1);
        $limit = $this->getIntValue('filters.limit', 50);

        if ($page < 1) {
            $this->addError(
                'Page number must be greater than or equal to 1',
                $pageFieldPath
            );
        }

        if ($limit < 1 || $limit > self::MAX_PAGE_LIMIT) {
            $this->addError(
                sprintf('Limit must be between 1 and %d', self::MAX_PAGE_LIMIT),
                $limitFieldPath
            );
        }
    }
}