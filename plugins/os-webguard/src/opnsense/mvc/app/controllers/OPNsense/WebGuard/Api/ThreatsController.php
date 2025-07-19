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
 * Class ThreatsController
 * @package OPNsense\WebGuard\Api
 */
class ThreatsController extends ApiControllerBase
{
    /**
     * Get threats list with pagination and filtering
     * @return array
     */
    public function getAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $page = $this->request->getQuery('page', 'int', 1);
            $limit = $this->request->getQuery('limit', 'int', 100);
            $severity = $this->request->getQuery('severity', 'string', '');
            $type = $this->request->getQuery('type', 'string', '');
            $startDate = $this->request->getQuery('start_date', 'string', '');
            $endDate = $this->request->getQuery('end_date', 'string', '');
            $sourceIp = $this->request->getQuery('source_ip', 'string', '');

            $filters = array(
                'page' => $page,
                'limit' => $limit,
                'severity' => $severity,
                'type' => $type,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'source_ip' => $sourceIp
            );

            $backend = new Backend();
            $response = $backend->configdRun("webguard get_threats", array(json_encode($filters)));
            
            if (!empty($response)) {
                $threats = json_decode($response, true);
                if ($threats !== null) {
                    $result = $threats;
                } else {
                    $result = array(
                        'threats' => array(),
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
     * Get threat details by ID
     * @param string $id
     * @return array
     */
    public function getDetailAction($id = null)
    {
        $result = array("result" => "failed");
        if ($this->request->isGet() && !empty($id)) {
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_threat_detail", array($id));
            
            if (!empty($response)) {
                $threat = json_decode($response, true);
                if ($threat !== null) {
                    $result = array(
                        "result" => "ok",
                        "threat" => $threat
                    );
                } else {
                    $result["message"] = "Threat not found";
                }
            } else {
                $result["message"] = "Threat not found";
            }
        } else {
            $result["message"] = "Invalid threat ID";
        }
        return $result;
    }

    /**
     * Get threat statistics
     * @return array
     */
    public function getStatsAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '24h');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_threat_stats", array($period));
            
            if (!empty($response)) {
                $stats = json_decode($response, true);
                if ($stats !== null) {
                    $result = $stats;
                } else {
                    $result = array(
                        'total_threats' => 0,
                        'threats_by_type' => array(),
                        'threats_by_severity' => array(),
                        'top_source_ips' => array(),
                        'threat_timeline' => array()
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Get real-time threat feed
     * @return array
     */
    public function getFeedAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $lastId = $this->request->getQuery('last_id', 'int', 0);
            $limit = $this->request->getQuery('limit', 'int', 50);
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_threat_feed", array($lastId, $limit));
            
            if (!empty($response)) {
                $feed = json_decode($response, true);
                if ($feed !== null) {
                    $result = $feed;
                } else {
                    $result = array(
                        'threats' => array(),
                        'last_id' => $lastId
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Mark threat as false positive
     * @param string $id
     * @return array
     */
    public function markFalsePositiveAction($id = null)
    {
        $result = array("result" => "failed");
        if ($this->request->isPost() && !empty($id)) {
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard mark_false_positive", array($id, $comment));
            
            if (strpos($response, "OK") !== false) {
                $result = array(
                    "result" => "ok",
                    "message" => "Threat marked as false positive"
                );
            } else {
                $result["message"] = "Failed to mark threat as false positive";
            }
        } else {
            $result["message"] = "Invalid threat ID";
        }
        return $result;
    }

    /**
     * Add IP to whitelist from threat
     * @param string $id
     * @return array
     */
    public function whitelistIpAction($id = null)
    {
        $result = array("result" => "failed");
        if ($this->request->isPost() && !empty($id)) {
            $permanent = $this->request->getPost('permanent', 'boolean', false);
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard whitelist_ip_from_threat", array($id, $permanent, $comment));
            
            if (strpos($response, "OK") !== false) {
                $result = array(
                    "result" => "ok",
                    "message" => "IP added to whitelist"
                );
            } else {
                $result["message"] = "Failed to add IP to whitelist";
            }
        } else {
            $result["message"] = "Invalid threat ID";
        }
        return $result;
    }

    /**
     * Block IP from threat
     * @param string $id
     * @return array
     */
    public function blockIpAction($id = null)
    {
        $result = array("result" => "failed");
        if ($this->request->isPost() && !empty($id)) {
            $duration = $this->request->getPost('duration', 'int', 3600);
            $comment = $this->request->getPost('comment', 'string', '');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard block_ip_from_threat", array($id, $duration, $comment));
            
            if (strpos($response, "OK") !== false) {
                $result = array(
                    "result" => "ok",
                    "message" => "IP blocked successfully"
                );
            } else {
                $result["message"] = "Failed to block IP";
            }
        } else {
            $result["message"] = "Invalid threat ID";
        }
        return $result;
    }

    /**
     * Create custom WAF rule from threat
     * @param string $id
     * @return array
     */
    public function createRuleAction($id = null)
    {
        $result = array("result" => "failed");
        if ($this->request->isPost() && !empty($id)) {
            $ruleName = $this->request->getPost('rule_name', 'string', '');
            $ruleDescription = $this->request->getPost('rule_description', 'string', '');
            $action = $this->request->getPost('action', 'string', 'block');
            
            if (!empty($ruleName)) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard create_rule_from_threat", 
                    array($id, $ruleName, $ruleDescription, $action));
                
                if (strpos($response, "OK") !== false) {
                    $result = array(
                        "result" => "ok",
                        "message" => "Custom rule created successfully"
                    );
                } else {
                    $result["message"] = "Failed to create custom rule";
                }
            } else {
                $result["message"] = "Rule name is required";
            }
        } else {
            $result["message"] = "Invalid threat ID";
        }
        return $result;
    }

    /**
     * Export threats data
     * @return array
     */
    public function exportAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isGet()) {
            $format = $this->request->getQuery('format', 'string', 'json');
            $startDate = $this->request->getQuery('start_date', 'string', '');
            $endDate = $this->request->getQuery('end_date', 'string', '');
            $severity = $this->request->getQuery('severity', 'string', '');
            $type = $this->request->getQuery('type', 'string', '');

            $filters = array(
                'format' => $format,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'severity' => $severity,
                'type' => $type
            );

            $backend = new Backend();
            $response = $backend->configdRun("webguard export_threats", array(json_encode($filters)));
            
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
                    $result["message"] = "Failed to export threats data";
                }
            } else {
                $result["message"] = "No data to export";
            }
        }
        return $result;
    }

    /**
     * Get geographic distribution of threats
     * @return array
     */
    public function getGeoStatsAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '24h');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_geo_stats", array($period));
            
            if (!empty($response)) {
                $geoStats = json_decode($response, true);
                if ($geoStats !== null) {
                    $result = $geoStats;
                } else {
                    $result = array(
                        'countries' => array(),
                        'total_countries' => 0,
                        'top_countries' => array()
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Get attack patterns analysis
     * @return array
     */
    public function getPatternsAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $period = $this->request->getQuery('period', 'string', '7d');
            $patternType = $this->request->getQuery('pattern_type', 'string', 'all');
            
            $backend = new Backend();
            $response = $backend->configdRun("webguard get_attack_patterns", array($period, $patternType));
            
            if (!empty($response)) {
                $patterns = json_decode($response, true);
                if ($patterns !== null) {
                    $result = $patterns;
                } else {
                    $result = array(
                        'patterns' => array(),
                        'trending_attacks' => array(),
                        'attack_sequences' => array()
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Clear old threats from database
     * @return array
     */
    public function clearOldAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $daysOld = $this->request->getPost('days_old', 'int', 30);
            $keepCritical = $this->request->getPost('keep_critical', 'boolean', true);
            
            if ($daysOld > 0) {
                $backend = new Backend();
                $response = $backend->configdRun("webguard clear_old_threats", array($daysOld, $keepCritical));
                
                if (strpos($response, "OK") !== false) {
                    $result = array(
                        "result" => "ok",
                        "message" => "Old threats cleared successfully"
                    );
                } else {
                    $result["message"] = "Failed to clear old threats";
                }
            } else {
                $result["message"] = "Invalid days_old parameter";
            }
        }
        return $result;
    }
}