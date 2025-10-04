<?php

namespace OPNsense\DeepInspector;

/**
 * Dashboard Controller - Main DPI interface
 */
class DashboardController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Deep Packet Inspector - Dashboard');
        $this->view->pick('OPNsense/DeepInspector/dashboard');
    }
}
