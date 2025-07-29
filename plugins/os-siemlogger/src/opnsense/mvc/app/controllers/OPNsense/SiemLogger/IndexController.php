<?php
/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
 * All rights reserved.
 */

namespace OPNsense\SiemLogger;

use OPNsense\Base\IndexController as BaseController;
use OPNsense\Core\Config;
use OPNsense\SiemLogger\SiemLogger;

/**
 * Class IndexController - Settings Page
 * @package OPNsense\SiemLogger
 */
class IndexController extends BaseController
{
    /**
     * SIEM Logger settings page with all configuration tabs
     */
    public function indexAction()
    {
        try {
            // Create model instance
            $mdlSiemLogger = new SiemLogger();

            // Get forms for all tabs
            $this->view->formGeneralSettings = $this->getForm("general");
            $this->view->formSiemExportSettings = $this->getForm("siem_export");  
            $this->view->formLoggingRulesSettings = $this->getForm("logging_rules");
            $this->view->formAuditSettings = $this->getForm("audit_settings");
            $this->view->formNotificationsSettings = $this->getForm("notifications");
            $this->view->formMonitoringSettings = $this->getForm("monitoring");

            // Set page title
            $this->view->title = gettext("SIEM Logger Settings");

        } catch (\Exception $e) {
            // Log error and provide fallback
            error_log("SIEM Logger Settings Error: " . $e->getMessage());
            $this->view->error = $e->getMessage();
        }

        // Explicitly set template
        $this->view->pick('OPNsense/SiemLogger/index');
    }
}