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

class SettingsController extends IndexController
{
    public function indexAction()
    {
        try {
            // Carica il modello WebGuard
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            
            // Carica i form in modo sicuro
            $this->view->generalForm = $this->getFormSafely("general");
            $this->view->wafForm = $this->getFormSafely("waf");
            $this->view->behavioralForm = $this->getFormSafely("behavioral");
            $this->view->covertChannelsForm = $this->getFormSafely("covert_channels");
            $this->view->responseForm = $this->getFormSafely("response");
            $this->view->whitelistForm = $this->getFormSafely("whitelist");
            
            // Imposta il titolo
            $this->view->title = gettext("WebGuard Settings");
            
        } catch (\Exception $e) {
            error_log("WebGuard Settings Error: " . $e->getMessage());
            $this->handleError($e, "WebGuard Settings");
        }
        
        $this->view->pick('OPNsense/WebGuard/settings');
    }
    
    public function generalAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->generalForm = $this->getFormSafely("general");
            $this->view->title = gettext("WebGuard General Settings");
        } catch (\Exception $e) {
            $this->handleError($e, "WebGuard General Settings");
        }
        $this->view->pick('OPNsense/WebGuard/general');
    }
    
    public function wafAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->wafForm = $this->getFormSafely("waf");
            $this->view->title = gettext("WebGuard WAF Settings");
        } catch (\Exception $e) {
            $this->handleError($e, "WebGuard WAF Settings");
        }
        $this->view->pick('OPNsense/WebGuard/waf');
    }
    
    public function behavioralAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->behavioralForm = $this->getFormSafely("behavioral");
            $this->view->title = gettext("WebGuard Behavioral Analysis");
        } catch (\Exception $e) {
            $this->handleError($e, "WebGuard Behavioral Analysis");
        }
        $this->view->pick('OPNsense/WebGuard/behavioral');
    }
    
    public function covertAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->covertChannelsForm = $this->getFormSafely("covert_channels");
            $this->view->title = gettext("WebGuard Covert Channels Detection");
        } catch (\Exception $e) {
            $this->handleError($e, "WebGuard Covert Channels Detection");
        }
        $this->view->pick('OPNsense/WebGuard/covert');
    }
    
    public function responseAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->responseForm = $this->getFormSafely("response");
            $this->view->title = gettext("WebGuard Response Settings");
        } catch (\Exception $e) {
            $this->handleError($e, "WebGuard Response Settings");
        }
        $this->view->pick('OPNsense/WebGuard/response');
    }
    
    public function whitelistAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->whitelistForm = $this->getFormSafely("whitelist");
            $this->view->title = gettext("WebGuard Whitelist Settings");
        } catch (\Exception $e) {
            $this->handleError($e, "WebGuard Whitelist Settings");
        }
        $this->view->pick('OPNsense/WebGuard/whitelist');
    }
    
    /**
     * Carica un form in modo sicuro
     */
    private function getFormSafely($formName)
    {
        try {
            return $this->getForm($formName);
        } catch (\Exception $e) {
            error_log("Form '$formName' not found: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Gestisce gli errori in modo uniforme
     */
    private function handleError($exception, $title)
    {
        error_log("WebGuard Error: " . $exception->getMessage());
        $this->view->webguardModel = null;
        $this->view->error = $exception->getMessage();
        $this->view->title = gettext($title);
    }
}
