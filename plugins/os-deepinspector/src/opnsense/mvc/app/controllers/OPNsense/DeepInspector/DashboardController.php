<?php

namespace OPNsense\DeepInspector;

/**
 * Dashboard Controller - Main DPI interface
 */
class DashboardController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/DeepInspector/dashboard');
    }
}
