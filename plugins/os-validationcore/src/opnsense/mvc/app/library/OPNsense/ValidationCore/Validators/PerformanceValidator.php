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

use OPNsense\Base\Messages\MessageCollection;
use OPNsense\Base\Messages\Message;

/**
 * Class PerformanceValidator
 *
 * Validator for DeepInspector performance settings.
 *
 * @package OPNsense\ValidationCore\Validators
 */
class PerformanceValidator extends AbstractValidator
{
    /**
     * Validate performance settings
     *
     * @param array $data Configuration data
     * @param bool $validateFullModel Whether to perform full validation
     * @return MessageCollection Validation messages
     */
    public function validate(array $data, bool $validateFullModel = false): MessageCollection
    {
        $messages = new MessageCollection();
        $general = $data['general'] ?? [];
        $detection = $data['detection'] ?? [];
        $protocols = $data['protocols'] ?? [];

        if ($validateFullModel) {
            $profile = $general['performance_profile'] ?? '';

            // Count enabled detection engines
            $detectionEngines = [
                'virus_signatures', 'trojan_detection', 'crypto_mining',
                'data_exfiltration', 'command_injection', 'sql_injection', 'script_injection'
            ];
            $enabledEngines = 0;
            foreach ($detectionEngines as $engine) {
                if (($detection[$engine] ?? '0') === "1") {
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
                if (($protocols[$protocol] ?? '0') === "1") {
                    $enabledProtocols++;
                }
            }

            // Performance profile validation
            if ($profile === 'high_performance' && ($enabledEngines > 3 || $enabledProtocols > 4)) {
                $messages->appendMessage(new Message(
                    gettext('High Performance profile recommends limiting active detection engines and protocol inspections for optimal performance.'),
                    'general.performance_profile'
                ));
            }

            if ($profile === 'high_security' && ($enabledEngines < 5 || $enabledProtocols < 4)) {
                $messages->appendMessage(new Message(
                    gettext('High Security profile recommends enabling more detection engines and protocol inspections for comprehensive coverage.'),
                    'general.performance_profile'
                ));
            }

            // SSL inspection performance warning
            if (($general['ssl_inspection'] ?? '0') === "1" && $profile === 'high_performance') {
                $messages->appendMessage(new Message(
                    gettext('SSL inspection may impact performance significantly in High Performance profile.'),
                    'general.ssl_inspection'
                ));
            }

            // Archive extraction performance warning
            if (($general['archive_extraction'] ?? '0') === "1" && $profile === 'high_performance') {
                $messages->appendMessage(new Message(
                    gettext('Archive extraction may impact performance in High Performance profile.'),
                    'general.archive_extraction'
                ));
            }
        }

        return $messages;
    }
}