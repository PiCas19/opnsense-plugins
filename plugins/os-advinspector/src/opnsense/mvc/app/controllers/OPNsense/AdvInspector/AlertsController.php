<?php

namespace OPNsense\AdvInspector;

/**
 * Alerts controller for Advanced Packet Inspector
 *
 * Manages the alerts view displaying security events detected by the packet inspector.
 *
 * @package OPNsense\AdvInspector
 */
class AlertsController extends \OPNsense\Base\IndexController
{
    /**
     * Display the alerts page
     *
     * @return void
     */
    public function indexAction()
    {
        $this->view->pick('OPNsense/AdvInspector/alerts');
    }
}