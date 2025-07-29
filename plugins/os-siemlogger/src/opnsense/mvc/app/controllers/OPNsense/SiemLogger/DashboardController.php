<?php

/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
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

namespace OPNsense\SiemLogger;

/**
 * Class DashboardController
 * @package OPNsense\SiemLogger
 */
class DashboardController extends \OPNsense\Base\IndexController
{
    /**
     * SIEM Logger dashboard page
     * @throws \Exception
     */
    public function indexAction()
    {
        try {
            // Load the SiemLogger model
            $mdlSiemLogger = new SiemLogger();

            // Set view variables safely
            $this->view->siemLoggerModel = $mdlSiemLogger;
            $this->view->isEnabled = $mdlSiemLogger->isEnabled();
            $this->view->logLevel = $mdlSiemLogger->getLogLevel();
            $this->view->exportEnabled = $mdlSiemLogger->isExportEnabled();
            $this->view->auditEnabled = $mdlSiemLogger->isAuditEnabled();
            $this->view->maxLogSize = $mdlSiemLogger->getMaxLogSize();
            $this->view->retentionDays = $mdlSiemLogger->getRetentionDays();
            $this->view->title = gettext("SIEM Logger Dashboard");

        } catch (\Exception $e) {
            // Log the error
            error_log("SIEM Logger Dashboard Error: " . $e->getMessage());
            
            // Safe fallback values
            $this->view->siemLoggerModel = null;
            $this->view->isEnabled = false;
            $this->view->logLevel = 'INFO';
            $this->view->exportEnabled = false;
            $this->view->auditEnabled = false;
            $this->view->maxLogSize = 100;
            $this->view->retentionDays = 30;
            $this->view->title = gettext("SIEM Logger Dashboard");
            $this->view->error = $e->getMessage();
        }

        // Explicitly set template
        $this->view->pick('OPNsense/SiemLogger/dashboard');
    }
}