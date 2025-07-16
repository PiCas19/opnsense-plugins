<?php

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\DeepInspector\Settings';
    protected static $internalServiceTemplate = 'OPNsense/DeepInspector';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'deepinspector';

    /**
     * Start DPI service
     * @return array
     */
    public function startAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector start");
        return ["response" => $response, "status" => "started"];
    }

    /**
     * Stop DPI service
     * @return array
     */
    public function stopAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector stop");
        return ["response" => $response, "status" => "stopped"];
    }

    /**
     * Restart DPI service
     * @return array
     */
    public function restartAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector restart");
        return ["response" => $response, "status" => "restarted"];
    }

    /**
     * Reconfigure DPI service
     * @return array
     */
    public function reconfigureAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector reconfigure");
        return ["response" => $response, "status" => "reconfigured"];
    }

    /**
     * Get detailed service status
     * @return array
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector status");
        
        // Parse the response to provide detailed status
        $lines = explode("\n", trim($response));
        $status = [
            'running' => false,
            'pid' => null,
            'uptime' => null,
            'memory_usage' => null,
            'cpu_usage' => null,
            'threads' => [],
            'last_error' => null
        ];

        foreach ($lines as $line) {
            if (strpos($line, 'PID:') !== false) {
                $status['pid'] = trim(str_replace('PID:', '', $line));
                $status['running'] = !empty($status['pid']);
            } elseif (strpos($line, 'Uptime:') !== false) {
                $status['uptime'] = trim(str_replace('Uptime:', '', $line));
            } elseif (strpos($line, 'Memory:') !== false) {
                $status['memory_usage'] = trim(str_replace('Memory:', '', $line));
            } elseif (strpos($line, 'CPU:') !== false) {
                $status['cpu_usage'] = trim(str_replace('CPU:', '', $line));
            }
        }

        return ["status" => $status];
    }

    /**
     * Get engine performance metrics
     * @return array
     */
    public function metricsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector get_metrics");
            
            $metrics = json_decode($response, true) ?: [];
            
            return [
                "status" => "ok",
                "metrics" => $metrics,
                "timestamp" => date('c')
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * Flush analysis caches and temporary data
     * @return array
     */
    public function flushCacheAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector flush_cache");
            
            return [
                "status" => "ok",
                "message" => "Cache flushed successfully",
                "response" => $response
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * Update threat intelligence feeds
     * @return array
     */
    public function updateThreatIntelAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector update_threat_intel");
            
            return [
                "status" => "ok",
                "message" => "Threat intelligence update initiated",
                "response" => $response
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * Generate and download diagnostic report
     * @return array
     */
    public function diagnosticsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector generate_diagnostics");
            
            return [
                "status" => "ok",
                "report_path" => "/tmp/deepinspector_diagnostics.tar.gz",
                "message" => "Diagnostic report generated"
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * Test engine with sample malware patterns
     * @return array
     */
    public function runTestsAction()
    {
        try {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector run_tests");
            
            $results = json_decode($response, true) ?: ['status' => 'unknown'];
            
            return [
                "status" => "ok",
                "test_results" => $results,
                "timestamp" => date('c')
            ];
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }
}