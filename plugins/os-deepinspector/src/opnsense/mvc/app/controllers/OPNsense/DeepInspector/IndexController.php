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
     * deep inspector index page - COPIA ESATTA DI MONIT
     * @throws \Exception
     */
    public function indexAction()
    {
        $this->view->formGeneralSettings = $this->getForm("general");
        $this->view->pick('OPNsense/DeepInspector/index');
    }
}