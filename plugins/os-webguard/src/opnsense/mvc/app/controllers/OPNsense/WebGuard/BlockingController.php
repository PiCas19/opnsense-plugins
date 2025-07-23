<?php

/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
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
            
        } catch (\Exception $e) {
            error_log("WebGuard Blocking Error: " . $e->getMessage());
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->error = $e->getMessage();
        }
        
        $this->view->pick('OPNsense/WebGuard/blocking');
    }
}