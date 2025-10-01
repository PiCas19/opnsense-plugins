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

/**
 * Advanced Validator
 *
 * Validator for DeepInspector advanced settings.
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
class AdvancedValidator extends AbstractValidator
{
    /**
     * Perform advanced settings validation
     */
    protected function performValidation(): void
    {
        $advanced = $this->data['advanced'] ?? [];
        $fieldChanges = $advanced['_field_changes'] ?? [];

        // Validate update_interval
        if ($this->validateFullModel || ($fieldChanges['update_interval'] ?? false)) {
            $interval = (int)($advanced['update_interval'] ?? 3600);
            if ($interval < 60 || $interval > 86400) {
                $this->addError(
                    'Update interval must be between 60 and 86400 seconds.',
                    'advanced.update_interval'
                );
            }
        }
    }
}