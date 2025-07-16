<?php
namespace OPNsense\AdvInspector;

class AlertsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/AdvInspector/alerts');
    }
}