<?php

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'deepinspector';
    protected static $internalModelClass = '\OPNsense\DeepInspector\DeepInspector';

    /**
     * Check if changes to the DeepInspector settings were made
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
     * Set general settings
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function setGeneralAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
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

    /**
     * Retrieve protocols settings
     * @return array deepinspector protocols settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getProtocolsAction()
    {
        return ['deepinspector' => $this->getModel()->protocols->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set protocols settings
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function setProtocolsAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
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

    /**
     * Retrieve detection settings
     * @return array deepinspector detection settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getDetectionAction()
    {
        return ['deepinspector' => $this->getModel()->detection->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set detection settings
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function setDetectionAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
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

    /**
     * Retrieve advanced settings
     * @return array deepinspector advanced settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getAdvancedAction()
    {
        return ['deepinspector' => $this->getModel()->advanced->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set advanced settings
     * @return array save result + validation output
     * @throws \OPNsense\Base\ValidationException when field validations fail
     * @throws \ReflectionException when not bound to model
     */
    public function setAdvancedAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
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

    /**
     * Get DPI statistics and performance metrics
     * @return array
     */
    public function statsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector get_stats");
            $stats = json_decode($response, true);
            if (!$stats) {
                $stats = [
                    'packets_analyzed' => 0,
                    'threats_detected' => 0,
                    'false_positives' => 0,
                    'performance' => ['cpu_usage' => 0, 'memory_usage' => 0],
                    'protocols' => [],
                    'top_threats' => [],
                    'recent_threats' => [],
                    'critical_alerts' => 0,
                    'detection_rate' => 0.0,
                    'latency_avg' => 0,
                    'throughput' => 0,
                    'industrial_protocols' => [],
                    'scada_alerts' => 0
                ];
            }
            return ['status' => 'ok', 'data' => $stats];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
}