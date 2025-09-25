<?php
namespace OPNsense\DeepInspector;

/**
 * Statistics Controller - DPI Statistics and Reports
 */
class StatisticsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Deep Packet Inspector - Statistics & Reports');
        $this->view->pick('OPNsense/DeepInspector/statistics');
    }
}