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
     * Retrieve protocol settings
     * @return array deepinspector protocol settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getProtocolsAction()
    {
        return ['deepinspector' => $this->getModel()->protocols->getNodes(), 'result' => 'ok'];
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
     * Retrieve advanced settings
     * @return array deepinspector advanced settings content
     * @throws \ReflectionException when not bound to model
     */
    public function getAdvancedAction()
    {
        return ['deepinspector' => $this->getModel()->advanced->getNodes(), 'result' => 'ok'];
    }

    /**
     * Set settings and automatically apply changes
     * @return array save result + validation output
     */
    public function setAction()
    {
        $result = ["result" => "failed"];
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
            // Set all posted data
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
                
                // Automatically reconfigure after save
                $backend = new Backend();
                $backend->configdRun('deepinspector reconfigure');
                
                // Clear the dirty flag
                $mdl->configClean();
                
                $result["result"] = "saved";
            }
        }
        return $result;
    }

    /**
     * Get DPI engine statistics for dashboard
     * @return array statistics data
     */
    public function statsAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $statsFile = '/var/log/deepinspector/stats.json';
            $alertsFile = '/var/log/deepinspector/alerts.log';
            
            // Load statistics from file
            if (file_exists($statsFile)) {
                $statsData = json_decode(file_get_contents($statsFile), true);
                if ($statsData) {
                    $result['data'] = $statsData;
                } else {
                    $result['data'] = $this->getDefaultStats();
                }
            } else {
                $result['data'] = $this->getDefaultStats();
            }
            
            // Load recent threats from alerts log
            $result['data']['recent_threats'] = $this->getRecentThreats($alertsFile);
            
            // Add system information
            $result['data']['system_info'] = $this->getSystemInfo();
            
        } catch (Exception $e) {
            $result['status'] = 'error';
            $result['message'] = 'Failed to load statistics: ' . $e->getMessage();
            $result['data'] = $this->getDefaultStats();
        }
        
        return $result;
    }
    
    /**
     * Get default statistics structure
     * @return array default stats
     */
    private function getDefaultStats()
    {
        return [
            'packets_analyzed' => 0,
            'threats_detected' => 0,
            'false_positives' => 0,
            'critical_alerts' => 0,
            'protocols_analyzed' => [
                'TCP' => 0,
                'UDP' => 0,
                'ICMP' => 0
            ],
            'threat_types' => [
                'malware' => 0,
                'command_injection' => 0,
                'sql_injection' => 0,
                'script_injection' => 0,
                'crypto_mining' => 0,
                'industrial_threat' => 0
            ],
            'performance' => [
                'cpu_usage' => 0,
                'memory_usage' => 0,
                'throughput_mbps' => 0,
                'latency_avg' => 0
            ],
            'industrial_stats' => [
                'modbus_packets' => 0,
                'dnp3_packets' => 0,
                'opcua_packets' => 0,
                'scada_alerts' => 0
            ],
            'timestamp' => date('c')
        ];
    }
    
    /**
     * Get recent threats from alerts log
     * @param string $alertsFile path to alerts log file
     * @return array recent threats
     */
    private function getRecentThreats($alertsFile)
    {
        $recentThreats = [];
        
        if (file_exists($alertsFile)) {
            try {
                $lines = file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                $lines = array_slice($lines, -50); // Get last 50 lines
                
                foreach (array_reverse($lines) as $line) {
                    $threat = json_decode($line, true);
                    if ($threat && isset($threat['threat_type'])) {
                        $recentThreats[] = [
                            'id' => $threat['id'] ?? uniqid(),
                            'timestamp' => $threat['timestamp'] ?? date('c'),
                            'source_ip' => $threat['source_ip'] ?? 'Unknown',
                            'destination_ip' => $threat['destination_ip'] ?? 'Unknown',
                            'threat_type' => $threat['threat_type'],
                            'severity' => $threat['severity'] ?? 'medium',
                            'protocol' => $threat['protocol'] ?? 'Unknown',
                            'description' => $threat['description'] ?? 'No description',
                            'industrial_context' => $threat['industrial_context'] ?? false
                        ];
                        
                        // Limit to 20 most recent threats
                        if (count($recentThreats) >= 20) {
                            break;
                        }
                    }
                }
            } catch (Exception $e) {
                // Log error but continue with empty array
                error_log("Error reading alerts file: " . $e->getMessage());
            }
        }
        
        return $recentThreats;
    }
    
    /**
     * Get system information
     * @return array system info
     */
    private function getSystemInfo()
    {
        $info = [
            'engine_version' => '1.0.0',
            'signatures_version' => 'Unknown',
            'uptime' => 'Unknown',
            'engine_status' => 'Unknown'
        ];
        
        try {
            // Check if engine is running
            $pidFile = '/var/run/deepinspector.pid';
            if (file_exists($pidFile)) {
                $pid = trim(file_get_contents($pidFile));
                if ($pid && posix_kill($pid, 0)) {
                    $info['engine_status'] = 'Running';
                    
                    // Get uptime from process
                    $cmd = "ps -o etime= -p $pid 2>/dev/null";
                    $uptime = trim(shell_exec($cmd));
                    if ($uptime) {
                        $info['uptime'] = $uptime;
                    }
                } else {
                    $info['engine_status'] = 'Stopped';
                }
            } else {
                $info['engine_status'] = 'Stopped';
            }
            
            // Get signatures version
            $sigFile = '/usr/local/etc/deepinspector/signatures.json';
            if (file_exists($sigFile)) {
                $sigData = json_decode(file_get_contents($sigFile), true);
                if ($sigData && isset($sigData['version'])) {
                    $info['signatures_version'] = $sigData['version'];
                } else {
                    $info['signatures_version'] = 'Default';
                }
            }
            
        } catch (Exception $e) {
            error_log("Error getting system info: " . $e->getMessage());
        }
        
        return $info;
    }
}