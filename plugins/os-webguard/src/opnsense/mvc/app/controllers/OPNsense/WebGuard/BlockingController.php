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

class BlockingController extends IndexController
{
    public function indexAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->autoBlocking = (string)$mdlWebGuard->response->auto_blocking === '1';
            
            // Carica i form in modo sicuro
            $this->view->blockIpForm = $this->getFormSafely("block_ip");
            $this->view->bulkBlockForm = $this->getFormSafely("bulk_block");
            
            $this->view->title = gettext("WebGuard IP Blocking");
            
        } catch (\Exception $e) {
            error_log("WebGuard Blocking Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->autoBlocking = false;
            $this->view->blockIpForm = null;
            $this->view->bulkBlockForm = null;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("WebGuard IP Blocking");
        }
        
        $this->view->pick('OPNsense/WebGuard/blocking');
    }
    
    public function whitelistAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            
            $this->view->addWhitelistForm = $this->getFormSafely("add_whitelist");
            $this->view->bulkWhitelistForm = $this->getFormSafely("bulk_whitelist");
            
            $this->view->title = gettext("WebGuard Whitelist Management");
            
        } catch (\Exception $e) {
            error_log("WebGuard Whitelist Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->addWhitelistForm = null;
            $this->view->bulkWhitelistForm = null;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("WebGuard Whitelist Management");
        }
        
        $this->view->pick('OPNsense/WebGuard/whitelist');
    }
    
    public function historyAction($ip = null)
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->ipAddress = $ip;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            
            if ($ip) {
                $this->view->title = gettext("IP History: " . $ip);
            } else {
                $this->view->title = gettext("IP History");
            }
            
        } catch (\Exception $e) {
            error_log("WebGuard IP History Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->ipAddress = $ip;
            $this->view->isEnabled = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("IP History");
        }
        
        $this->view->pick('OPNsense/WebGuard/ip_history');
    }
    
    public function statsAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->autoBlocking = (string)$mdlWebGuard->response->auto_blocking === '1';
            $this->view->progressiveBlocking = (string)$mdlWebGuard->response->progressive_blocking === '1';
            
            $this->view->title = gettext("Blocking Statistics");
            
        } catch (\Exception $e) {
            error_log("WebGuard Blocking Stats Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->autoBlocking = false;
            $this->view->progressiveBlocking = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Blocking Statistics");
        }
        
        $this->view->pick('OPNsense/WebGuard/blocking_stats');
    }
    
    public function importexportAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            
            $this->view->importForm = $this->getFormSafely("import_blocked");
            $this->view->exportForm = $this->getFormSafely("export_blocked");
            
            $this->view->title = gettext("Import/Export Blocked IPs");
            
        } catch (\Exception $e) {
            error_log("WebGuard Import/Export Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->importForm = null;
            $this->view->exportForm = null;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Import/Export Blocked IPs");
        }
        
        $this->view->pick('OPNsense/WebGuard/import_export');
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
}