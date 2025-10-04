<?php

/*
 * Copyright (C) 2025 OPNsense Project
 * All rights reserved.
 */

namespace OPNsense\DeepInspector;

/**
 * Class IndexController
 * @package OPNsense\DeepInspector
 */
class IndexController extends \OPNsense\Base\IndexController
{
    /**
     * deep inspector index page con tutti i tabs
     * @throws \Exception
     */
    public function indexAction()
    {
        $this->view->formGeneralSettings = $this->getForm("general");
        $this->view->formProtocolsSettings = $this->getForm("protocols");
        $this->view->formDetectionSettings = $this->getForm("detection");
        $this->view->formAdvancedSettings = $this->getForm("advanced");
        $this->view->pick('OPNsense/DeepInspector/index');
    }
}