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
 * Class GeneralValidator
 *
 * Validator for DeepInspector general settings.
 *
 * @package OPNsense\ValidationCore\Validators
 */
class GeneralValidator extends AbstractValidator
{
    /**
     * Validate general settings
     *
     * @param array $data Configuration data
     * @param bool $validateFullModel Whether to perform full validation
     * @return MessageCollection Validation messages
     */
    public function validate(array $data, bool $validateFullModel = false): MessageCollection
    {
        $messages = new MessageCollection();
        $general = $data['general'] ?? [];
        $fieldChanges = $general['_field_changes'] ?? [];

        // Validate enabled and interfaces
        if ($validateFullModel || ($fieldChanges['enabled'] ?? false) || ($fieldChanges['interfaces'] ?? false)) {
            if ($general['enabled'] === "1" && empty($general['interfaces'])) {
                $messages->appendMessage(new Message(
                    gettext('At least one interface must be selected when DPI is enabled.'),
                    'general.interfaces'
                ));
            }
        }

        // Validate performance profile and mode
        if ($validateFullModel || ($fieldChanges['performance_profile'] ?? false) || ($fieldChanges['mode'] ?? false)) {
            if ($general['performance_profile'] === 'high_security' && $general['mode'] === 'learning') {
                $messages->appendMessage(new Message(
                    gettext('High Security profile is not compatible with Learning mode.'),
                    'general.mode'
                ));
            }
        }

        // Validate trusted networks format
        if ($validateFullModel || ($fieldChanges['trusted_networks'] ?? false)) {
            $networks = $general['trusted_networks'] ?? '';
            if (!empty($networks)) {
                $networkList = explode(',', $networks);
                foreach ($networkList as $network) {
                    $network = trim($network);
                    if (!empty($network) && !preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $network)) {
                        $messages->appendMessage(new Message(
                            sprintf(gettext('Invalid network format: %s. Use CIDR notation (e.g., 192.168.1.0/24)'), $network),
                            'general.trusted_networks'
                        ));
                    }
                }
            }
        }

        // Validate deep scan ports
        if ($validateFullModel || ($fieldChanges['deep_scan_ports'] ?? false)) {
            $ports = $general['deep_scan_ports'] ?? '';
            if (!empty($ports) && !preg_match('/^[0-9,-\s]*$/', $ports)) {
                $messages->appendMessage(new Message(
                    gettext('Deep scan ports must contain only numbers, commas, dashes and spaces.'),
                    'general.deep_scan_ports'
                ));
            }
        }

        // Validate max packet size
        if ($validateFullModel || ($fieldChanges['max_packet_size'] ?? false)) {
            $size = (int)$general['max_packet_size'];
            if ($size < 64 || $size > 9000) {
                $messages->appendMessage(new Message(
                    gettext('Maximum packet size must be between 64 and 9000 bytes.'),
                    'general.max_packet_size'
                ));
            }
        }

        return $messages;
    }
}