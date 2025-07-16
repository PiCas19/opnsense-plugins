<?php
namespace OPNsense\AdvInspector;

class LogsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/AdvInspector/logs');
    }
}