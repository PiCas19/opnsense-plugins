<?php

/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\WebGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class BlockingController
 * @package OPNsense\WebGuard\Api
 */
class BlockingController extends ApiControllerBase
{
    /**
     * Get blocked IPs list with pagination and filtering
     * @return array
     */
    public function getBlockedIpsAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $page = $this->request->getQuery('page', 'int', 1);
            $limit = $this->request->getQuery('limit', 'int', 100);
            $blockType = $this->request->getQuery('block_type', 'string', '');
            $startDate = $this->request->getQuery('start_date', 'string', '');
            $endDate = $this->request->getQuery('end_date', 'string', '');
            $sourceIp = $this->request->getQuery('source_ip', 'string', '');

            $filters = array(
                'page' => $page,
                'limit' => $limit,
                'block_type' => $blockType,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'source_ip' => $sourceIp
            );

            $backend = new Backend();
            $response = $backend->configdRun("webguard get_blocked_ips", array(json_encode($filters)));
            
            if (!empty($response)) {
                $blockedIps = json_decode($response, true);
                if ($blockedIps !== null) {
                    $result = $blockedIps;
                } else {
                    $result = array(
                        'blocked_ips' => array(),
                        'total' => 0,
                        'page' => $page,
                        'limit' => $limit
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Get whitelist entries
     * @return array
     */
    public function getWhitelistAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $page = $this->request->getQuery('page', 'int', 1);
            $limit = $this->request->getQuery('limit', 'int', 100);
            
            $filters = array(
                'page' => $page,
                'limit' => $limit
            );

            $backend = new Backend();
            $response = $backend->configdRun("webguard get_whitelist", array(json_encode($filters)));
            
            if (!empty($response)) {
                $whitelist = json_decode($response, true);
                if ($whitelist !== null) {
                    $result = $whitelist;
                } else {
                    $result = array(
                        'whitelist' => array(),
                        'total' => 0,
                        'page' => $page,
                        'limit' => $limit
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Block IP address manually
     * @return array
     */
    public function blockIpAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $ipAddress = $this->request->getPost('ip_address', 'string', '');
            $duration = $this->request->getPost('duration', 'int', 3600);
            $reason = $this->request->getPost('reason', 'string', 'Manual block');
            $blockType = $this->request->getPost('block_type', 'string', 'temporary');
            
            if (!empty($ipAddress) && filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard block_ip", 
                    array($ipAddress, $duration, $reason, $blockType));
                
                if (strpos($response, "OK") !== false) {
                    $result = array(
                        "result" => "ok",
                        "message" => "IP address blocked successfully"
                    );
                } else {
                    $result["message"] = "Failed to block IP address: " . trim($response);
                }
            } else {
                $result["message"] = "Invalid IP address";
            }
        }
        return $result;
    }

    /**
     * Unblock IP address
     * @return array
     */
    public function unblockIpAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $ipAddress = $this->request->getPost('ip_address', 'string', '');
            $reason = $this->request->getPost('reason', 'string', 'Manual unblock');
            
            if (!empty($ipAddress) && filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard unblock_ip", array($ipAddress, $reason));
                
                if (strpos($response, "OK") !== false) {
                    $result = array(
                        "result" => "ok",
                        "message" => "IP address unblocked successfully"
                    );
                } else {
                    $result["message"] = "Failed to unblock IP address: " . trim($response);
                }
            } else {
                $result["message"] = "Invalid IP address";
            }
        }
        return $result;
    }

    /**
     * Add IP to whitelist
     * @return array
     */
    public function addToWhitelistAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $ipAddress = $this->request->getPost('ip_address', 'string', '');
            $description = $this->request->getPost('description', 'string', '');
            $permanent = $this->request->getPost('permanent', 'boolean', true);
            $expiry = $this->request->getPost('expiry', 'string', '');
            
            if (!empty($ipAddress) && filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard add_to_whitelist", 
                    array($ipAddress, $description, $permanent, $expiry));
                
                if (strpos($response, "OK") !== false) {
                    $result = array(
                        "result" => "ok",
                        "message" => "IP address added to whitelist successfully"
                    );
                } else {
                    $result["message"] = "Failed to add IP to whitelist: " . trim($response);
                }
            } else {
                $result["message"] = "Invalid IP address";
            }
        }
        return $result;
    }

    /**
     * Remove IP from whitelist
     * @return array
     */
    public function removeFromWhitelistAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $ipAddress = $this->request->getPost('ip_address', 'string', '');
            $reason = $this->request->getPost('reason', 'string', 'Manual removal');
            
            if (!empty($ipAddress) && filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard remove_from_whitelist", 
                    array($ipAddress, $reason));
                
                if (strpos($response, "OK") !== false) {
                    $result = array(
                        "result" => "ok",
                        "message" => "IP address removed from whitelist successfully"
                    );
                } else {
                    $result["message"] = "Failed to remove IP from whitelist: " . trim($response);
                }
            } else {
                $result["message"] = "Invalid IP address";
            }
        }
        return $result;
    }

    /**
     * Bulk block multiple IPs
     * @return array
     */
    public function bulkBlockAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $ipList = $this->request->getPost('ip_list', 'string', '');
            $duration = $this->request->getPost('duration', 'int', 3600);
            $reason = $this->request->getPost('reason', 'string', 'Bulk block');
            $blockType = $this->request->getPost('block_type', 'string', 'temporary');
            
            if (!empty($ipList)) {
                $ips = array_filter(array_map('trim', explode("\n", $ipList)));
                $validIps = array();
                $invalidIps = array();
                
                foreach ($ips as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $validIps[] = $ip;
                    } else {
                        $invalidIps[] = $ip;
                    }
                }
                
                if (!empty($validIps)) {
                    $backend = new Backend();
                    $response = $backend->configdRun("webguard bulk_block_ips", 
                        array(json_encode($validIps), $duration, $reason, $blockType));
                    
                    if (strpos($response, "OK") !== false) {
                        $result = array(
                            "result" => "ok",
                            "message" => count($validIps) . " IP addresses blocked successfully",
                            "blocked_count" => count($validIps),
                            "invalid_ips" => $invalidIps
                        );
                    } else {
                        $result["message"] = "Failed to block IP addresses: " . trim($response);
                    }
                } else {
                    $result["message"] = "No valid IP addresses provided";
                }
            } else {
                $result["message"] = "IP list is required";
            }
        }
        return $result;
    }

    /**
     * Bulk unblock multiple IPs
     * @return array
     */
    public function bulkUnblockAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $ipList = $this->request->getPost('ip_list', 'string', '');
            $reason = $this->request->getPost('reason', 'string', 'Bulk unblock');
            
            if (!empty($ipList)) {
                $ips = array_filter(array_map('trim', explode("\n", $ipList)));
                $validIps = array();
                $invalidIps = array();
                
                foreach ($ips as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $validIps[] = $ip;
                    } else {
                        $invalidIps[] = $ip;
                    }
                }
                
                if (!empty($validIps)) {
                    $backend = new Backend();
                    $response = $backend->configdRun("webguard bulk_unblock_ips", 
                        array(json_encode($validIps), $reason));
                    
                    if (strpos($response, "OK") !== false) {
                        $result = array(
                            "result" => "ok",
                            "message" => count($validIps) . " IP addresses unblocked successfully",
                            "unblocked_count" => count($validIps),
                            "invalid_ips" => $invalidIps
                        );
                    } else {
                        $result["message"] = "Failed to unblock IP addresses: " . trim($response);
                    }
                } else {
                    $result["message"] = "No valid IP addresses provided";
                }
            } else {
                $result["message"] = "IP list is required";
            }
        }
        return $result;
    }

    /**
     * Clear expired blocks
     * @return array
     */
    public function clearExpiredAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard clear_expired_blocks");
            
            if (strpos($response, "OK") !== false) {
                $clearedCount = trim(str_replace("OK:", "", $response));
                $result = array(
                    "result" => "ok",
                    "message" => "Expired blocks cleared successfully",
                    "cleared_count" => (int)$clearedCount
                );
            } else {
                $result["message"] = "Failed to clear expired blocks: " . trim($response);
            }
        }
        return $result;
    }

    /**
     * Get blocking statistics
     * @return array
     */
    public function getStatsAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '24h');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_blocking_stats", array($period));
            
            if (!empty($response)) {
                $stats = json_decode($response, true);
                if ($stats !== null) {
                    $result = $stats;
                } else {
                    $result = array(
                        'total_blocked' => 0,
                        'active_blocks' => 0,
                        'whitelist_entries' => 0,
                        'auto_blocks' => 0,
                        'manual_blocks' => 0,
                        'block_timeline' => array()
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Export blocked IPs list
     * @return array
     */
    public function exportBlockedAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isGet()) {
            $format = $this->request->getQuery('format', 'string', 'csv');
            $includeExpired = $this->request->getQuery('include_expired', 'boolean', false);
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard export_blocked_ips", 
                array($format, $includeExpired));
            
            if (!empty($response)) {
                $export = json_decode($response, true);
                if ($export !== null && isset($export['data'])) {
                    $result = array(
                        "result" => "ok",
                        "data" => $export['data'],
                        "filename" => $export['filename'],
                        "format" => $format
                    );
                } else {
                    $result["message"] = "Failed to export blocked IPs";
                }
            } else {
                $result["message"] = "No data to export";
            }
        }
        return $result;
    }

    /**
     * Import blocked IPs list
     * @return array
     */
    public function importBlockedAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $importData = $this->request->getPost('import_data', 'string', '');
            $format = $this->request->getPost('format', 'string', 'csv');
            $defaultDuration = $this->request->getPost('default_duration', 'int', 3600);
            $reason = $this->request->getPost('reason', 'string', 'Imported block');
            
            if (!empty($importData)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard import_blocked_ips", 
                    array($importData, $format, $defaultDuration, $reason));
                
                if (strpos($response, "OK") !== false) {
                    $importedCount = trim(str_replace("OK:", "", $response));
                    $result = array(
                        "result" => "ok",
                        "message" => "Blocked IPs imported successfully",
                        "imported_count" => (int)$importedCount
                    );
                } else {
                    $result["message"] = "Failed to import blocked IPs: " . trim($response);
                }
            } else {
                $result["message"] = "Import data is required";
            }
        }
        return $result;
    }

    /**
     * Get block history for specific IP
     * @param string $ip
     * @return array
     */
    public function getIpHistoryAction($ip = null)
    {
        $result = array("result" => "failed");
        if ($this->request->isGet() && !empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_ip_history", array($ip));
            
            if (!empty($response)) {
                $history = json_decode($response, true);
                if ($history !== null) {
                    $result = array(
                        "result" => "ok",
                        "ip_address" => $ip,
                        "history" => $history
                    );
                } else {
                    $result["message"] = "No history found for this IP";
                }
            } else {
                $result["message"] = "No history found for this IP";
            }
        } else {
            $result["message"] = "Invalid IP address";
        }
        return $result;
    }
}