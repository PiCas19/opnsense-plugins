<?php

namespace OPNsense\DeepInspector;

/**
 * Logs Controller - Log viewing and management
 */
class LogsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Deep Packet Inspector - Logs');
        $this->view->pick('OPNsense/DeepInspector/logs');
    }
}