<?php

namespace OPNsense\DeepInspector;


/**
 * Analysis Controller - Deep analysis and reporting
 */
class AnalysisController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/DeepInspector/analysis');
    }
}