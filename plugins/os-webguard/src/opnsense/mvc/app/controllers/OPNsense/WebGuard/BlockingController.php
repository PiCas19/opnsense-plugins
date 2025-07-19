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
 * Class BlockingController
 * @package OPNsense\WebGuard
 */
class BlockingController extends IndexController
{
    /**
     * Blocking index page - shows blocked IPs
     * @return void
     */
    public function indexAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->isEnabled = $mdlWebGuard->general->enabled->__toString() === '1';
        $this->view->autoBlocking = $mdlWebGuard->response->auto_blocking->__toString() === '1';
        
        // Get forms for dialogs
        $this->view->blockIpForm = $this->getForm("block_ip");
        $this->view->bulkBlockForm = $this->getForm("bulk_block");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard IP Blocking");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/blocking');
    }

    /**
     * Whitelist management page
     * @return void
     */
    public function whitelistAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->isEnabled = $mdlWebGuard->general->enabled->__toString() === '1';
        
        // Get forms for dialogs
        $this->view->addWhitelistForm = $this->getForm("add_whitelist");
        $this->view->bulkWhitelistForm = $this->getForm("bulk_whitelist");
        
        // Set page title
        $this->view->title = $this->gettext("WebGuard Whitelist Management");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/whitelist');
    }

    /**
     * IP history page
     * @param string $ip
     * @return void
     */
    public function historyAction($ip = null)
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model and IP to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->ipAddress = $ip;
        $this->view->isEnabled = $mdlWebGuard->general->enabled->__toString() === '1';
        
        // Set page title
        if ($ip) {
            $this->view->title = $this->gettext("IP History: " . $ip);
        } else {
            $this->view->title = $this->gettext("IP History");
        }
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/ip_history');
    }

    /**
     * Blocking statistics page
     * @return void
     */
    public function statsAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->isEnabled = $mdlWebGuard->general->enabled->__toString() === '1';
        $this->view->autoBlocking = $mdlWebGuard->response->auto_blocking->__toString() === '1';
        $this->view->progressiveBlocking = $mdlWebGuard->response->progressive_blocking->__toString() === '1';
        
        // Set page title
        $this->view->title = $this->gettext("Blocking Statistics");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/blocking_stats');
    }

    /**
     * Import/Export page for blocked IPs
     * @return void
     */
    public function importexportAction()
    {
        // Get WebGuard model instance
        $mdlWebGuard = new WebGuard();
        
        // Pass model to view
        $this->view->webguardModel = $mdlWebGuard;
        $this->view->isEnabled = $mdlWebGuard->general->enabled->__toString() === '1';
        
        // Get forms for import/export
        $this->view->importForm = $this->getForm("import_blocked");
        $this->view->exportForm = $this->getForm("export_blocked");
        
        // Set page title
        $this->view->title = $this->gettext("Import/Export Blocked IPs");
        
        // Pick the template
        $this->view->pick('OPNsense/WebGuard/import_export');
    }
}