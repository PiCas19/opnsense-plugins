<?php

namespace OPNsense\AdvInspector;

/**
 * Logs controller for Advanced Packet Inspector
 *
 * Manages the logs view for packet inspection events and alerts.
 *
 * @package OPNsense\AdvInspector
 */
class LogsController extends \OPNsense\Base\IndexController
{
    /**
     * Display the logs page
     *
     * @return void
     */
    public function indexAction()
    {
        $this->view->pick('OPNsense/AdvInspector/logs');
    }
}