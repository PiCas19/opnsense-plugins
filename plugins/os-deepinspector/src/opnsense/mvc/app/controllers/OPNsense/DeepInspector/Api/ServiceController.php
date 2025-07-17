<?php
namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\DeepInspector\DeepInspector;

/**
 * Class ServiceController
 * @package OPNsense\DeepInspector
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\DeepInspector\DeepInspector';
    protected static $internalServiceName = 'deepinspector';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceTemplate = 'OPNsense/DeepInspector';

    /**
     * Start the Deep Packet Inspector service
     * @return array service start result
     */
    public function startAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $backend = new Backend();
            $response = $backend->configdRun('deepinspector start');
            
            if (trim($response) === 'OK') {
                $result["status"] = "ok";
                $result["message"] = "Deep Packet Inspector service started successfully";
            } else {
                $result["message"] = "Failed to start service: " . $response;
            }
        } catch (Exception $e) {
            $result["message"] = "Error starting service: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Stop the Deep Packet Inspector service
     * @return array service stop result
     */
    public function stopAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $backend = new Backend();
            $response = $backend->configdRun('deepinspector stop');
            
            if (trim($response) === 'OK') {
                $result["status"] = "ok";
                $result["message"] = "Deep Packet Inspector service stopped successfully";
            } else {
                $result["message"] = "Failed to stop service: " . $response;
            }
        } catch (Exception $e) {
            $result["message"] = "Error stopping service: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Restart the Deep Packet Inspector service
     * @return array service restart result
     */
    public function restartAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $backend = new Backend();
            $response = $backend->configdRun('deepinspector restart');
            
            if (trim($response) === 'OK') {
                $result["status"] = "ok";
                $result["message"] = "Deep Packet Inspector service restarted successfully";
            } else {
                $result["message"] = "Failed to restart service: " . $response;
            }
        } catch (Exception $e) {
            $result["message"] = "Error restarting service: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Reconfigure the Deep Packet Inspector service
     * @return array service reconfigure result
     */
    public function reconfigureAction()
    {
        $result = ["status" => "failed"];
        
        try {
            $backend = new Backend();
            $response = $backend->configdRun('deepinspector reconfigure');
            
            if (trim($response) === 'OK') {
                $result["status"] = "ok";
                $result["message"] = "Deep Packet Inspector service reconfigured successfully";
            } else {
                $result["message"] = "Failed to reconfigure service: " . $response;
            }
        } catch (Exception $e) {
            $result["message"] = "Error reconfiguring service: " . $e->getMessage();
        }
        
        return $result;
    }
    
    /**
     * Get the Deep Packet Inspector service status
     * @return array service status information
     */
    public function statusAction()
    {
        $result = ["status" => "ok"];
        
        try {
            $pidFile = '/var/run/deepinspector.pid';
            $isRunning = false;
            $pid = null;
            
            if (file_exists($pidFile)) {
                $pid = trim(file_get_contents($pidFile));
                if ($pid && posix_kill($pid, 0)) {
                    $isRunning = true;
                }
            }
            
            $result["data"] = [
                "running" => $isRunning,
                "pid" => $pid
            ];
            
            if ($isRunning) {
                // Get additional process information
                $result["data"]["uptime"] = $this->getProcessUptime($pid);
                $result["data"]["memory_usage"] = $this->getProcessMemoryUsage($pid);
                $result["data"]["cpu_usage"] = $this->getProcessCpuUsage($pid);
            }
            
        } catch (Exception $e) {
            $result["status"] = "error";
            $result["message"] = "Error checking service status: " . $e->getMessage();
            $result["data"] = [
                "running" => false,
                "pid" => null
            ];
        }
        
        return $result;
    }
    
    /**
     * Block an IP address
     * @return array block result
     */
    public function blockIPAction()
    {
        $result = ["status" => "failed"];
        
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                try {
                    $backend = new Backend();
                    $response = $backend->configdRun('deepinspector block_ip', $ip);
                    
                    if (trim($response) === 'OK') {
                        $result["status"] = "ok";
                        $result["message"] = "IP address $ip blocked successfully";
                    } else {
                        $result["message"] = "Failed to block IP: " . $response;
                    }
                } catch (Exception $e) {
                    $result["message"] = "Error blocking IP: " . $e->getMessage();
                }
            } else {
                $result["message"] = "Invalid IP address format";
            }
        }
        
        return $result;
    }
    
    /**
     * Unblock an IP address
     * @return array unblock result
     */
    public function unblockIPAction()
    {
        $result = ["status" => "failed"];
        
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                try {
                    $backend = new Backend();
                    $response = $backend->configdRun('deepinspector unblock_ip', $ip);
                    
                    if (trim($response) === 'OK') {
                        $result["status"] = "ok";
                        $result["message"] = "IP address $ip unblocked successfully";
                    } else {
                        $result["message"] = "Failed to unblock IP: " . $response;
                    }
                } catch (Exception $e) {
                    $result["message"] = "Error unblocking IP: " . $e->getMessage();
                }
            } else {
                $result["message"] = "Invalid IP address format";
            }
        }
        
        return $result;
    }
    
    /**
     * Whitelist an IP address
     * @return array whitelist result
     */
    public function whitelistIPAction()
    {
        $result = ["status" => "failed"];
        
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                try {
                    $backend = new Backend();
                    $response = $backend->configdRun('deepinspector whitelist_ip', $ip);
                    
                    if (trim($response) === 'OK') {
                        $result["status"] = "ok";
                        $result["message"] = "IP address $ip whitelisted successfully";
                    } else {
                        $result["message"] = "Failed to whitelist IP: " . $response;
                    }
                } catch (Exception $e) {
                    $result["message"] = "Error whitelisting IP: " . $e->getMessage();
                }
            } else {
                $result["message"] = "Invalid IP address format";
            }
        }
        
        return $result;
    }
    
    /**
     * Get process uptime
     * @param string $pid process ID
     * @return string uptime string
     */
    private function getProcessUptime($pid)
    {
        try {
            $cmd = "ps -o etime= -p $pid 2>/dev/null";
            $uptime = trim(shell_exec($cmd));
            return $uptime ?: 'Unknown';
        } catch (Exception $e) {
            return 'Unknown';
        }
    }
    
    /**
     * Get process memory usage
     * @param string $pid process ID
     * @return string memory usage string
     */
    private function getProcessMemoryUsage($pid)
    {
        try {
            $cmd = "ps -o rss= -p $pid 2>/dev/null";
            $rss = trim(shell_exec($cmd));
            if ($rss) {
                $mb = round($rss / 1024, 2);
                return $mb . ' MB';
            }
            return 'Unknown';
        } catch (Exception $e) {
            return 'Unknown';
        }
    }
    
    /**
     * Get process CPU usage
     * @param string $pid process ID
     * @return string CPU usage string
     */
    private function getProcessCpuUsage($pid)
    {
        try {
            $cmd = "ps -o pcpu= -p $pid 2>/dev/null";
            $cpu = trim(shell_exec($cmd));
            if ($cpu) {
                return $cpu . '%';
            }
            return 'Unknown';
        } catch (Exception $e) {
            return 'Unknown';
        }
    }
}