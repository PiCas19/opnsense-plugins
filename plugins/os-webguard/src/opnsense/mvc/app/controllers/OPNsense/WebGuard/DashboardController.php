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

use OPNsense\Base\IndexController;
use OPNsense\WebGuard\WebGuard;

/**
 * Class DashboardController
 * @package OPNsense\WebGuard
 */
class DashboardController extends IndexController
{
    /**
     * Dashboard index page
     * @return void
     */
    public function indexAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->isEnabled = $mdlWebGuard->general->enabled->__toString() === '1';
        $this->view->currentMode = $mdlWebGuard->general->mode->__toString();
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Dashboard");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/dashboard');
    }
}