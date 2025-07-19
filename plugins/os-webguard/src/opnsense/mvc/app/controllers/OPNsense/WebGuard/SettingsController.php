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
 * Class SettingsController
 * @package OPNsense\WebGuard
 */
class SettingsController extends IndexController
{
    /**
     * Settings index page
     * @return void
     */
    public function indexAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->generalForm = $this->getForm("general");
        $this->view->wafForm = $this->getForm("waf");
        $this->view->behavioralForm = $this->getForm("behavioral");
        $this->view->covertChannelsForm = $this->getForm("covert_channels");
        $this->view->responseForm = $this->getForm("response");
        $this->view->whitelistForm = $this->getForm("whitelist");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Settings");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/settings');
    }

    /**
     * General settings page
     * @return void
     */
    public function generalAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->generalForm = $this->getForm("general");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard General Settings");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/general');
    }

    /**
     * WAF settings page
     * @return void
     */
    public function wafAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->wafForm = $this->getForm("waf");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard WAF Settings");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/waf');
    }

    /**
     * Behavioral analysis settings page
     * @return void
     */
    public function behavioralAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->behavioralForm = $this->getForm("behavioral");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Behavioral Analysis");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/behavioral');
    }

    /**
     * Covert channels detection settings page
     * @return void
     */
    public function covertAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->covertChannelsForm = $this->getForm("covert_channels");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Covert Channels Detection");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/covert');
    }

    /**
     * Response settings page
     * @return void
     */
    public function responseAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->responseForm = $this->getForm("response");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Response Settings");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/response');
    }

    /**
     * Whitelist settings page
     * @return void
     */
    public function whitelistAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->whitelistForm = $this->getForm("whitelist");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Whitelist Settings");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/whitelist');
    }
}