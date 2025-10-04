<?php

namespace OPNsense\DeepInspector;

/**
 * Threats Controller - Threat analysis and alerts
 */
class ThreatsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Deep Packet Inspector - Threats');
        $this->view->pick('OPNsense/DeepInspector/threats');
    }
}