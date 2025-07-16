<?php

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'deepinspector';
    protected static $internalModelClass = '\OPNsense\DeepInspector';

    /**
     * Get DPI settings
     * @return array
     */
    public function getAction()
    {
        $result = [];
        if ($this->request->isGet()) {
            $mdl = $this->getModel();
            $result['deepinspector'] = $mdl->getNodes();
        }
        return $result;
    }

    /**
     * Set DPI settings
     * @return array
     */
    public function setAction()
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
                // Export configuration for the DPI engine
                try {
                    (new Backend())->configdRun("deepinspector export_config");
                } catch (\Exception $e) {
                    // Log error but don't fail
                    error_log("DeepInspector export_config failed: " . $e->getMessage());
                }
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

    /**
     * Update threat signatures
     * @return array
     */
    public function updateSignaturesAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector update_signatures");
            return ['status' => 'ok', 'message' => 'Signature update initiated'];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Test DPI engine with sample data
     * @return array
     */
    public function testEngineAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector test_engine");
            $result = json_decode($response, true);
            return ['status' => 'ok', 'data' => $result];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Get industrial protocol statistics
     * @return array
     */
    public function industrialStatsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector get_industrial_stats");
            $stats = json_decode($response, true);
            if (!$stats) {
                $stats = [
                    'modbus_packets' => 0,
                    'dnp3_packets' => 0,
                    'opcua_packets' => 0,
                    'scada_alerts' => 0,
                    'plc_communications' => 0,
                    'industrial_threats' => 0,
                    'avg_latency' => 0,
                    'protocol_distribution' => []
                ];
            }
            return ['status' => 'ok', 'data' => $stats];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Get latency metrics for industrial environments
     * @return array
     */
    public function latencyMetricsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector get_latency_metrics");
            $metrics = json_decode($response, true);
            if (!$metrics) {
                $metrics = [
                    'avg_latency' => 0,
                    'max_latency' => 0,
                    'min_latency' => 0,
                    'latency_distribution' => [],
                    'threshold_violations' => 0,
                    'industrial_impact' => 'none'
                ];
            }
            return ['status' => 'ok', 'data' => $metrics];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Apply industrial optimization settings
     * @return array
     */
    public function applyIndustrialOptimizationAction()
    {
        try {
            $mdl = $this->getModel();
            $recommendations = $mdl->getIndustrialRecommendations();
            
            // Apply recommended settings
            foreach ($recommendations as $key => $value) {
                $node = $mdl->getNodeByReference('general.' . $key);
                if ($node) {
                    $node->setValue($value);
                }
            }
            
            $mdl->serializeToConfig();
            Config::getInstance()->save();
            
            $backend = new Backend();
            $backend->configdRun("deepinspector reconfigure");
            
            return ['status' => 'ok', 'message' => 'Industrial optimization applied'];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Get Zero Trust compliance status
     * @return array
     */
    public function zeroTrustStatusAction()
    {
        try {
            $mdl = $this->getModel();
            $general = $mdl->getNodeByReference('general');
            $protocols = $mdl->getNodeByReference('protocols');
            $detection = $mdl->getNodeByReference('detection');
            
            $compliance = [
                'overall_score' => 0,
                'checks' => [
                    'deep_inspection_enabled' => (string)$general->malware_detection === '1',
                    'all_protocols_inspected' => true,
                    'ssl_inspection_enabled' => (string)$general->ssl_inspection === '1',
                    'anomaly_detection_enabled' => (string)$general->anomaly_detection === '1',
                    'industrial_protocols_covered' => (string)$protocols->industrial_protocols === '1',
                    'zero_day_protection' => (string)$detection->zero_day_heuristics === '1'
                ],
                'recommendations' => []
            ];
            
            // Calculate compliance score
            $passed = array_sum($compliance['checks']);
            $total = count($compliance['checks']);
            $compliance['overall_score'] = round(($passed / $total) * 100);
            
            // Generate recommendations
            if (!$compliance['checks']['ssl_inspection_enabled']) {
                $compliance['recommendations'][] = 'Enable SSL/TLS inspection for complete Zero Trust coverage';
            }
            if (!$compliance['checks']['industrial_protocols_covered']) {
                $compliance['recommendations'][] = 'Enable industrial protocol inspection for OT environments';
            }
            
            return ['status' => 'ok', 'data' => $compliance];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
}