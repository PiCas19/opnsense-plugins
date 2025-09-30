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
 * Class DetectionValidator
 *
 * Validator for DeepInspector detection settings.
 *
 * @package OPNsense\ValidationCore\Validators
 */
class DetectionValidator extends AbstractValidator
{
    /**
     * Validate detection settings
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
        $fieldChanges = $detection['_field_changes'] ?? [];
        $generalFieldChanges = $general['_field_changes'] ?? [];

        // Validate detection engine dependencies
        if ($validateFullModel || ($fieldChanges['virus_signatures'] ?? false) || ($generalFieldChanges['malware_detection'] ?? false)) {
            $virusEnabled = $detection['virus_signatures'] === "1";
            $malwareEnabled = $general['malware_detection'] === "1";

            if ($virusEnabled && !$malwareEnabled) {
                $messages->appendMessage(new Message(
                    gettext('Malware detection must be enabled for virus signature scanning.'),
                    'detection.virus_signatures'
                ));
            }
        }

        return $messages;
    }
}