<?php
/*
 * Copyright (C) 2025 Pierpaolo Casati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
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
 * Dashboard controller for Deep Packet Inspector
 *
 * Provides the main monitoring dashboard with real-time statistics,
 * threat detection overview, and system status information.
 *
 * @package OPNsense\DeepInspector
 */
class DashboardController extends \OPNsense\Base\IndexController
{
    /**
     * Displays the main dashboard page
     *
     * Shows real-time DPI statistics, active threats, and system performance.
     *
     * @return void
     */
    public function indexAction()
    {
        // Allow OpenStreetMap tile servers for the attack map.
        // All other resources remain self-hosted (leaflet.js/css served from /js/ and /css/).
        $this->response->setHeader(
            'Content-Security-Policy',
            "default-src 'self'; " .
            "img-src 'self' data: blob: " .
                "https://a.tile.openstreetmap.org " .
                "https://b.tile.openstreetmap.org " .
                "https://c.tile.openstreetmap.org; " .
            "style-src 'self' 'unsafe-inline'; " .
            "script-src 'self' 'unsafe-inline'; " .
            "connect-src 'self';"
        );

        $this->view->title = gettext('Deep Packet Inspector - Dashboard');
        $this->view->pick('OPNsense/DeepInspector/dashboard');
    }
}
