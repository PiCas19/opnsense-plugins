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

class ThreatsController extends IndexController
{
    public function indexAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->title = gettext("WebGuard Threats");
            
        } catch (\Exception $e) {
            error_log("WebGuard Threats Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("WebGuard Threats");
        }
        
        $this->view->pick('OPNsense/WebGuard/threats');
    }
    
    public function detailAction($id = null)
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->threatId = $id;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->title = gettext("Threat Details");
            
        } catch (\Exception $e) {
            error_log("WebGuard Threat Detail Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->threatId = $id;
            $this->view->isEnabled = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Threat Details");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_detail');
    }
    
    public function statsAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->title = gettext("Threat Statistics");
            
        } catch (\Exception $e) {
            error_log("WebGuard Threat Stats Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Threat Statistics");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_stats');
    }
    
    public function feedAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->title = gettext("Real-time Threat Feed");
            
        } catch (\Exception $e) {
            error_log("WebGuard Threat Feed Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Real-time Threat Feed");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_feed');
    }
    
    public function geoAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->geoBlocking = (string)$mdlWebGuard->general->geo_blocking === '1';
            $this->view->title = gettext("Geographic Threat Analysis");
            
        } catch (\Exception $e) {
            error_log("WebGuard Geo Analysis Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->geoBlocking = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Geographic Threat Analysis");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_geo');
    }
    
    public function patternsAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            
            // Usa il metodo che creeremo nel modello
            $this->view->behavioralEnabled = $this->isBehavioralEnabled($mdlWebGuard);
            $this->view->title = gettext("Attack Pattern Analysis");
            
        } catch (\Exception $e) {
            error_log("WebGuard Attack Patterns Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->behavioralEnabled = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Attack Pattern Analysis");
        }
        
        $this->view->pick('OPNsense/WebGuard/attack_patterns');
    }
    
    /**
     * Verifica se l'analisi comportamentale è abilitata
     */
    private function isBehavioralEnabled($model)
    {
        try {
            return (string)$model->behavioral->anomaly_detection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
}
