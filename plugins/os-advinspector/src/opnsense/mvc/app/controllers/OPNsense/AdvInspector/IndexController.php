<?php

namespace OPNsense\AdvInspector;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/AdvInspector/index');
    }
}
