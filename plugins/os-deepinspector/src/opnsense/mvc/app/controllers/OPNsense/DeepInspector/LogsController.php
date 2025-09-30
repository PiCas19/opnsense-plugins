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

use OPNsense\Base\IndexController;

/**
 * LogsController
 *
 * Manages the Logs page of the DeepInspector plugin, providing access to
 * DPI system logs for monitoring and debugging. This controller renders
 * the logs view, which displays log entries based on the configured log_level
 * from the Settings model.
 *
 * @package OPNsense\DeepInspector
 */
class LogsController extends IndexController
{
    /**
     * Renders the DeepInspector Logs page
     *
     * Sets the page title and selects the logs view template.
     * Log data is expected to be handled by the view or associated JavaScript,
 * potentially pulling data based on Settings::general.log_level.
     *
     * @throws \Exception If the view template cannot be loaded
     */
    public function indexAction()
    {
        $this->view->title = gettext('Deep Packet Inspector - Logs');
        $this->view->pick('OPNsense/DeepInspector/logs');
    }
}