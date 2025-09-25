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
    {nano co
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
        
        $statsFile = '/var/log/deepinspector/stats.json';
        $alertsFile = '/var/log/deepinspector/alerts.log';
        
        // Load statistics from file
        if (file_exists($statsFile)) {
            $statsData = @file_get_contents($statsFile);
            if ($statsData !== false) {
                $decodedStats = @json_decode($statsData, true);
                if ($decodedStats !== null) {
                    $result['data'] = $decodedStats;
                } else {
                    $result['data'] = $this->getDefaultStats();
                }
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
            $lines = @file($alertsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                $lines = array_slice($lines, -50); // Get last 50 lines
                
                foreach (array_reverse($lines) as $line) {
                    $threat = @json_decode($line, true);
                    if ($threat !== null && isset($threat['threat_type'])) {
                        $recentThreats[] = [
                            'id' => isset($threat['id']) ? $threat['id'] : uniqid(),
                            'timestamp' => isset($threat['timestamp']) ? $threat['timestamp'] : date('c'),
                            'source_ip' => isset($threat['source_ip']) ? $threat['source_ip'] : 'Unknown',
                            'destination_ip' => isset($threat['destination_ip']) ? $threat['destination_ip'] : 'Unknown',
                            'threat_type' => $threat['threat_type'],
                            'severity' => isset($threat['severity']) ? $threat['severity'] : 'medium',
                            'protocol' => isset($threat['protocol']) ? $threat['protocol'] : 'Unknown',
                            'description' => isset($threat['description']) ? $threat['description'] : 'No description',
                            'industrial_context' => isset($threat['industrial_context']) ? $threat['industrial_context'] : false
                        ];
                        
                        // Limit to 20 most recent threats
                        if (count($recentThreats) >= 20) {
                            break;
                        }
                    }
                }
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
            'engine_status' => 'Unknown',
            'pid' => 'Unknown',
            'memory_usage' => 'Unknown',
            'cpu_usage' => 'Unknown'
        ];
        
        // Get status from backend (correct approach)
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector status");
        
        $lines = explode("\n", trim($response));
        $running = false;
        $pid = null;
        $memory_usage = null;
        
        foreach ($lines as $line) {
            if (strpos($line, "is running as PID") !== false) {
                $running = true;
                if (preg_match('/PID (\d+)/', $line, $matches)) {
                    $pid = $matches[1];
                }
            } elseif (strpos($line, "is not running") !== false) {
                $running = false;
            } elseif (strpos($line, "Memory usage:") !== false) {
                if (preg_match('/Memory usage:\s*(\d+(?:\.\d+)?)\s*MB/', $line, $matches)) {
                    $memory_usage = $matches[1] . "MB";
                }
            }
        }
        
        if ($running && $pid) {
            $info['engine_status'] = 'Active';
            $info['pid'] = $pid;
            $info['memory_usage'] = $memory_usage ?: 'Unknown';
            
            // Get additional process info
            $processInfo = $this->getProcessInfo($pid);
            $info['cpu_usage'] = $processInfo['cpu_usage'];
            $info['uptime'] = $processInfo['uptime'];
        } else {
            $info['engine_status'] = 'Inactive';
            $info['pid'] = 'N/A';
            $info['memory_usage'] = 'N/A';
            $info['cpu_usage'] = 'N/A';
            $info['uptime'] = 'N/A';
        }
        
        // Get signatures version
        $sigFile = '/usr/local/etc/deepinspector/signatures.json';
        if (file_exists($sigFile)) {
            $sigData = @file_get_contents($sigFile);
            if ($sigData !== false) {
                $sigJson = @json_decode($sigData, true);
                if ($sigJson !== null && isset($sigJson['version'])) {
                    $sigVersion = $sigJson['version'];
                    // If it's a date, format it as yyyy-mm-dd
                    if (strtotime($sigVersion) !== false) {
                        $info['signatures_version'] = date('Y-m-d', strtotime($sigVersion));
                    } else {
                        $info['signatures_version'] = $sigVersion;
                    }
                } else {
                    $info['signatures_version'] = date('Y-m-d'); // Current date as default
                }
            }
        }
        
        return $info;
    }
    
    /**
     * Get process information
     * @param string $pid
     * @return array
     */
    private function getProcessInfo($pid)
    {
        $cpu_usage = "Unknown";
        $uptime = "Unknown";
        
        try {
            // Get CPU usage
            $cpuCmd = "ps -o pcpu= -p " . escapeshellarg($pid);
            $cpuResult = @shell_exec($cpuCmd);
            if ($cpuResult !== null && $cpuResult !== false) {
                $cpuResult = trim($cpuResult);
                if ($cpuResult !== '' && is_numeric($cpuResult)) {
                    $cpu_usage = $cpuResult . "%";
                }
            }
            
            // Get uptime
            $uptimeCmd = "ps -o etime= -p " . escapeshellarg($pid);
            $uptimeResult = @shell_exec($uptimeCmd);
            if ($uptimeResult !== null && $uptimeResult !== false) {
                $uptimeResult = trim($uptimeResult);
                if ($uptimeResult !== '') {
                    $uptime = $uptimeResult;
                }
            }
        } catch (Exception $e) {
            // Ignore errors, keep default values
        }
        
        return [
            'cpu_usage' => $cpu_usage,
            'uptime' => $uptime
        ];
    }
}