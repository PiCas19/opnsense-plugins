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

/**
 * StatisticsController
 *
 * Provides the entry point for the DeepInspector statistics and reporting UI.
 * This controller is responsible for rendering the statistics view, which
 * includes dashboards, charts, and analytical reports on detected threats,
 * network traffic, and protocol usage.
 *
 * @package OPNsense\DeepInspector
 */
class StatisticsController extends \OPNsense\Base\IndexController
{
    /**
     * Render the Statistics & Reports page
     *
     * Sets the page title and loads the Volt template that provides
     * DeepInspector's statistical dashboards and reporting interface.
     *
     * @throws \Exception If the view cannot be rendered
     */
    public function indexAction()
    {
        $this->view->title = gettext('Deep Packet Inspector - Statistics & Reports');
        $this->view->pick('OPNsense/DeepInspector/statistics');
    }
}
