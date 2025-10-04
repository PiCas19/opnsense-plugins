<?php

namespace OPNsense\AdvInspector;

/**
 * Main index controller for Advanced Packet Inspector
 *
 * Handles the main dashboard view for the Zero Trust packet inspection interface.
 *
 * @package OPNsense\AdvInspector
 */
class IndexController extends \OPNsense\Base\IndexController
{
    /**
     * Display the main dashboard page
     *
     * @return void
     */
    public function indexAction()
    {
        $this->view->pick('OPNsense/AdvInspector/index');
    }
}
