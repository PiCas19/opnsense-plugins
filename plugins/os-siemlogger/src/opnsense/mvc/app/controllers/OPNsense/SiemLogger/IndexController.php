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

use OPNsense\Base\IndexController as BaseController;

class IndexController extends BaseController
{
    /**
     * SIEM Logger settings page with all tabs
     * @throws \Exception
     */
    public function indexAction()
    {
        $this->view->formGeneralSettings = $this->getForm("general");
        $this->view->formSiemExportSettings = $this->getForm("siem_export");
        $this->view->formLoggingRulesSettings = $this->getForm("logging_rules");
        $this->view->formAuditSettings = $this->getForm("audit_settings");
        $this->view->formNotificationsSettings = $this->getForm("notifications");
        $this->view->formMonitoringSettings = $this->getForm("monitoring");
        $this->view->pick('OPNsense/SiemLogger/index');
    }
}