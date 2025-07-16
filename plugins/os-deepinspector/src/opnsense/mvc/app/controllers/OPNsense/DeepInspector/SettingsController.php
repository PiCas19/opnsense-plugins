<?php

namespace OPNsense\DeepInspector;

/**
 * Settings Controller - DPI configuration interface
 */
class SettingsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->protocolsForm = $this->getForm('protocols');
        $this->view->detectionForm = $this->getForm('detection');
        $this->view->advancedForm = $this->getForm('advanced');
        $this->view->pick('OPNsense/DeepInspector/settings');
    }
}