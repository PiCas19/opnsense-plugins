<?php

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * Class SettingsController
 * @package OPNsense\DeepInspector
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'deepinspector';
    protected static $internalModelClass = 'OPNsense\DeepInspector\DeepInspector';

    /**
     * check if changes to the deepinspector settings were made
     * @return array result
     */
    public function dirtyAction()
    {
        $result = array('status' => 'ok');
        $result['deepinspector']['dirty'] = $this->getModel()->configChanged();
        return $result;
    }

    /**
     * Retrieve general settings
     * @return array deepinspector general settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getGeneralAction()
    {
         return ['deepinspector' => $this->getModel()->general->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set general settings (COPIA ESATTA DI MONIT)
     * @return array save result + validation output
     */
    public function setAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
            
            // COPIA ESATTA DI MONIT - USA TUTTO IL POST DATA
            $mdl->setNodes($this->request->getPost("deepinspector"));
            $valMsgs = $mdl->performValidation();
            
            if ($valMsgs->count() > 0) {
                $result["validations"] = [];
                foreach ($valMsgs as $msg) {
                    $field = $msg->getField();
                    $result["validations"]["deepinspector." . $field] = $msg->getMessage();
                }
            } else {
                $mdl->serializeToConfig();
                Config::getInstance()->save();
                $result["result"] = "saved";
            }
        }
        return $result;
    }
}