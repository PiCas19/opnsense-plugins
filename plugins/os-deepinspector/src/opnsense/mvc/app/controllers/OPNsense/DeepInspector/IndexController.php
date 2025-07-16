<?php
/*
 * Copyright (C) 2025 OPNsense Project
 * All rights reserved.
 */
namespace OPNsense\DeepInspector;
use OPNsense\Base\IndexController as BaseIndexController;

/**
 * Class IndexController
 * @package OPNsense\DeepInspector
 */
class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        $this->view->formGeneral  = $this->getForm("general");
        $this->view->formProtocols= $this->getForm("protocols");
        $this->view->formDetection= $this->getForm("detection");
        $this->view->formAdvanced = $this->getForm("advanced");
        $this->view->pick('OPNsense/DeepInspector/index');
    }

}