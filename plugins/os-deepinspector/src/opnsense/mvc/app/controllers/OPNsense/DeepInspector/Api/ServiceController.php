<?php

/*
 * Copyright (C) 2025 OPNsense Project
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

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Class ServiceController
 *
 * Manages the DeepInspector service operations within the OPNsense framework.
 * Provides API endpoints for starting, stopping, restarting, reconfiguring the service,
 * and managing IP addresses (blocking, unblocking, whitelisting). Ensures that all
 * operations are performed using real system data, avoiding any fallback or default data.
 *
 * Key Features:
 * - Service control (start, stop, restart, reconfigure)
 * - IP address management (block, unblock, whitelist, status check)
 * - Real-time service status retrieval
 * - Integration with OPNsense backend for command execution
 * - Robust error handling without fallback data
 *
 * @package OPNsense\DeepInspector\Api
 * @author Pierpaolo Casati
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    /**
     * Internal service class for OPNsense framework integration
     *
     * Defines the service class used by the parent class to manage the DeepInspector service.
     *
     * @var string Service class path
     */
    protected static $internalServiceClass = '\\OPNsense\\DeepInspector\\DeepInspector';

    /**
     * Service template for configuration generation
     *
     * Specifies the template used for generating service configuration files.
     *
     * @var string Service template identifier
     */
    protected static $internalServiceTemplate = 'OPNsense/DeepInspector';

    /**
     * Configuration key for service enablement
     *
     * Defines the configuration key used to check if the service is enabled.
     *
     * @var string Configuration key for enabled state
     */
    protected static $internalServiceEnabled = 'enabled';

    /**
     * Internal service name for OPNsense framework
     *
     * Specifies the service name used by the OPNsense backend for command execution.
     *
     * @var string Service name
     */
    protected static $internalServiceName = 'deepinspector';

    /**
     * Start the DeepInspector service
     *
     * Initiates the DeepInspector service using the OPNsense backend. Requires a POST request
     * for security and returns the status of the operation.
     *
     * @api POST /api/deepinspector/service/start
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" if the service started successfully, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/start
     * Response: {
     *   "status": "ok",
     *   "response": "DeepInspector started with PID 12345",
     *   "message": "Starting Deep Packet Inspector Engine"
     * }
     *
     * @example
     * POST /api/deepinspector/service/start
     * Response: {
     *   "status": "failed",
     *   "response": "Failed to start service",
     *   "message": "Starting Deep Packet Inspector Engine"
     * }
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector start");
            $status = strpos($response, "started") !== false ? "ok" : "failed";
            return [
                "status" => $status,
                "response" => $response,
                "message" => "Starting Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Stop the DeepInspector service
     *
     * Terminates the DeepInspector service using the OPNsense backend. Requires a POST request
     * for security and returns the status of the operation.
     *
     * @api POST /api/deepinspector/service/stop
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" if the service stopped successfully, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/stop
     * Response: {
     *   "status": "ok",
     *   "response": "DeepInspector stopped",
     *   "message": "Stopping Deep Packet Inspector Engine"
     * }
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector stop");
            $status = strpos($response, "stopped") !== false ? "ok" : "failed";
            return [
                "status" => $status,
                "response" => $response,
                "message" => "Stopping Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Restart the DeepInspector service
     *
     * Restarts the DeepInspector service using the OPNsense backend. Requires a POST request
     * for security and returns the status of the operation.
     *
     * @api POST /api/deepinspector/service/restart
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/restart
     * Response: {
     *   "status": "ok",
     *   "response": "DeepInspector restarted with PID 12345",
     *   "message": "Restarting Deep Packet Inspector Engine"
     * }
     */
    public function restartAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("deepinspector restart");
            return [
                "status" => "ok",
                "response" => $response,
                "message" => "Restarting Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Get the status of the DeepInspector service
     *
     * Retrieves the current status of the DeepInspector service, including whether it is running,
     * the process ID (PID), and the socket status. Returns an error if the backend response is invalid.
     *
     * @api GET /api/deepinspector/service/status
     *
     * @return array{status: string, running: bool, pid: ?string, socket_status: string, response: string, message: string, error?: string} Service status
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" if the response is invalid
     * - running: Boolean indicating if the service is running
     * - pid: Process ID if running, null otherwise
     * - socket_status: Socket status ("active", "inactive", or "unknown")
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     * - error: Error message if the backend response is invalid
     *
     * @example
     * GET /api/deepinspector/service/status
     * Response: {
     *   "status": "ok",
     *   "running": true,
     *   "pid": "12345",
     *   "socket_status": "active",
     *   "response": "DeepInspector is running as PID 12345\nSocket: (active)",
     *   "message": "Getting DPI engine status"
     * }
     *
     * @example
     * GET /api/deepinspector/service/status
     * Response: {
     *   "status": "failed",
     *   "error": "Invalid backend response",
     *   "message": "Getting DPI engine status"
     * }
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("deepinspector status");

        if (empty(trim($response))) {
            return [
                "status" => "failed",
                "error" => "Invalid backend response",
                "message" => "Getting DPI engine status"
            ];
        }

        $lines = explode("\n", trim($response));
        $running = false;
        $pid = null;
        $socket_status = "unknown";

        foreach ($lines as $line) {
            if (strpos($line, "is running") !== false || strpos($line, "started") !== false) {
                $running = true;
                if (preg_match('/PID (\d+)/', $line, $matches)) {
                    $pid = $matches[1];
                }
            } elseif (strpos($line, "Socket:") !== false) {
                $socket_status = strpos($line, "(active)") !== false ? "active" : "inactive";
            } elseif (strpos($line, "is not running") !== false || strpos($line, "stopped") !== false) {
                $running = false;
            }
        }

        return [
            "status" => "ok",
            "running" => $running,
            "pid" => $pid,
            "socket_status" => $socket_status,
            "response" => $response,
            "message" => "Getting DPI engine status"
        ];
    }

    /**
     * Reconfigure and restart the DeepInspector service
     *
     * Regenerates the service configuration and restarts the DeepInspector service.
     * Requires a POST request for security and marks the configuration as clean upon success.
     *
     * @api POST /api/deepinspector/service/reconfigure
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/reconfigure
     * Response: {
     *   "status": "ok",
     *   "response": "DeepInspector restarted with PID 12345",
     *   "message": "Reconfiguring Deep Packet Inspector Engine"
     * }
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun("template reload OPNsense/DeepInspector");
            $response = $backend->configdRun("deepinspector restart");
            $mdl = new \OPNsense\DeepInspector\DeepInspector();
            $mdl->configClean();
            return [
                "status" => "ok",
                "response" => $response,
                "message" => "Reconfiguring Deep Packet Inspector Engine"
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Block an IP address using the DeepInspector daemon
     *
     * Adds the specified IP address to the block list using the OPNsense backend.
     * Validates the IP address format and requires a POST request for security.
     *
     * @api POST /api/deepinspector/service/blockIP
     *
     * Request Body Format:
     * {
     *   "ip": "192.168.1.100"
     * }
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" if the IP was blocked successfully, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/blockIP
     * Content-Type: application/json
     * Body: {"ip": "192.168.1.100"}
     * Response: {
     *   "status": "ok",
     *   "response": "OK",
     *   "message": "IP address 192.168.1.100 blocked successfully"
     * }
     */
    public function blockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdpRun("deepinspector", ["block_ip", $ip]);
                $status = trim($response) === "OK" ? "ok" : "failed";
                $message = $status === "ok" ? "IP address $ip blocked successfully" : "Failed to block IP: $response";
                return [
                    "status" => $status,
                    "response" => $response,
                    "message" => $message
                ];
            }
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Unblock an IP address using the DeepInspector daemon
     *
     * Removes the specified IP address from the block list using the OPNsense backend.
     * Validates the IP address format and requires a POST request for security.
     *
     * @api POST /api/deepinspector/service/unblockIP
     *
     * Request Body Format:
     * {
     *   "ip": "192.168.1.100"
     * }
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" if the IP was unblocked successfully, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/unblockIP
     * Content-Type: application/json
     * Body: {"ip": "192.168.1.100"}
     * Response: {
     *   "status": "ok",
     *   "response": "OK",
     *   "message": "IP address 192.168.1.100 unblocked successfully"
     * }
     */
    public function unblockIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdpRun("deepinspector", ["unblock_ip", $ip]);
                $status = trim($response) === "OK" ? "ok" : "failed";
                $message = $status === "ok" ? "IP address $ip unblocked successfully" : "Failed to unblock IP: $response";
                return [
                    "status" => $status,
                    "response" => $response,
                    "message" => $message
                ];
            }
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Whitelist an IP address using the DeepInspector daemon
     *
     * Adds the specified IP address to the whitelist using the OPNsense backend.
     * Validates the IP address format and requires a POST request for security.
     *
     * @api POST /api/deepinspector/service/whitelistIP
     *
     * Request Body Format:
     * {
     *   "ip": "192.168.1.100"
     * }
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" if the IP was whitelisted successfully, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/whitelistIP
     * Content-Type: application/json
     * Body: {"ip": "192.168.1.100"}
     * Response: {
     *   "status": "ok",
     *   "response": "OK",
     *   "message": "IP address 192.168.1.100 whitelisted successfully"
     * }
     */
    public function whitelistIPAction()
    {
        if ($this->request->isPost()) {
            $ip = $this->request->getPost('ip');
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $backend = new Backend();
                $response = $backend->configdpRun("deepinspector", ["whitelist_ip", $ip]);
                $status = trim($response) === "OK" ? "ok" : "failed";
                $message = $status === "ok" ? "IP address $ip whitelisted successfully" : "Failed to whitelist IP: $response";
                return [
                    "status" => $status,
                    "response" => $response,
                    "message" => $message
                ];
            }
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * Clear DeepInspector logs using the daemon
     *
     * Clears all DeepInspector log files using the OPNsense backend.
     * Requires a POST request for security.
     *
     * @api POST /api/deepinspector/service/clearLogs
     *
     * @return array{status: string, response: string, message: string} Operation result
     *
     * Response Format:
     * - status: "ok" if logs were cleared successfully, "failed" otherwise
     * - response: Raw response from the backend command
     * - message: Descriptive message of the operation
     *
     * @example
     * POST /api/deepinspector/service/clearLogs
     * Response: {
     *   "status": "ok",
     *   "response": "OK",
     *   "message": "Logs cleared successfully"
     * }
     */
    public function clearLogsAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdpRun("deepinspector", ["clear_logs"]);
            $status = trim($response) === "OK" ? "ok" : "failed";
            $message = $status === "ok" ? "Logs cleared successfully" : "Failed to clear logs: $response";
            return [
                "status" => $status,
                "response" => $response,
                "message" => $message
            ];
        }
        return ["status" => "failed", "message" => "POST method required"];
    }

    /**
     * List blocked IP addresses
     *
     * Retrieves the list of blocked IP addresses using the OPNsense backend.
     *
     * @api GET /api/deepinspector/service/listBlocked
     *
     * @return array{status: string, data: array, count: int, message: string, error?: string} List of blocked IPs
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" if the response is invalid
     * - data: Array of blocked IP addresses
     * - count: Number of blocked IPs
     * - message: Descriptive message of the operation
     * - error: Error message if the backend response is invalid
     *
     * @example
     * GET /api/deepinspector/service/listBlocked
     * Response: {
     *   "status": "ok",
     *   "data": ["192.168.1.100", "10.0.0.5"],
     *   "count": 2,
     *   "message": "Getting blocked IP list"
     * }
     */
    public function listBlockedAction()
    {
        $backend = new Backend();
        $response = $backend->configdpRun("deepinspector", ["list_blocked"]);
        if (empty(trim($response))) {
            return [
                "status" => "failed",
                "error" => "Invalid backend response",
                "message" => "Getting blocked IP list"
            ];
        }
        $ips = array_filter(explode("\n", trim($response)));
        return [
            "status" => "ok",
            "data" => $ips,
            "count" => count($ips),
            "message" => "Getting blocked IP list"
        ];
    }

    /**
     * List whitelisted IP addresses
     *
     * Retrieves the list of whitelisted IP addresses using the OPNsense backend.
     *
     * @api GET /api/deepinspector/service/listWhitelist
     *
     * @return array{status: string, data: array, count: int, message: string, error?: string} List of whitelisted IPs
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" if the response is invalid
     * - data: Array of whitelisted IP addresses
     * - count: Number of whitelisted IPs
     * - message: Descriptive message of the operation
     * - error: Error message if the backend response is invalid
     *
     * @example
     * GET /api/deepinspector/service/listWhitelist
     * Response: {
     *   "status": "ok",
     *   "data": ["192.168.1.10"],
     *   "count": 1,
     *   "message": "Getting whitelist IP list"
     * }
     */
    public function listWhitelistAction()
    {
        $backend = new Backend();
        $response = $backend->configdpRun("deepinspector", ["list_whitelist"]);
        if (empty(trim($response))) {
            return [
                "status" => "failed",
                "error" => "Invalid backend response",
                "message" => "Getting whitelist IP list"
            ];
        }
        $ips = array_filter(explode("\n", trim($response)));
        return [
            "status" => "ok",
            "data" => $ips,
            "count" => count($ips),
            "message" => "Getting whitelist IP list"
        ];
    }

    /**
     * Retrieve JSON data for blocked or whitelisted IPs
     *
     * Fetches JSON-formatted data for blocked or whitelisted IPs using the OPNsense backend.
     * Validates the type parameter and requires a valid JSON response.
     *
     * @api POST /api/deepinspector/service/showJson
     *
     * Request Body Format:
     * {
     *   "type": "blocked" | "whitelist"
     * }
     *
     * @return array{status: string, data?: array, response?: string, message: string, error?: string} JSON data or error
     *
     * Response Format:
     * - status: "ok" if JSON data is retrieved successfully, "failed" otherwise
     * - data: JSON-decoded data if valid
     * - response: Raw response if JSON is invalid
     * - message: Descriptive message of the operation
     * - error: Error message if the response is invalid or JSON decoding fails
     *
     * @example
     * POST /api/deepinspector/service/showJson
     * Content-Type: application/json
     * Body: {"type": "blocked"}
     * Response: {
     *   "status": "ok",
     *   "data": {"ips": ["192.168.1.100"]},
     *   "message": "Getting blocked IPs JSON data"
     * }
     *
     * @example
     * POST /api/deepinspector/service/showJson
     * Body: {"type": "invalid"}
     * Response: {
     *   "status": "failed",
     *   "message": "Type must be 'blocked' or 'whitelist'"
     * }
     */
    public function showJsonAction()
    {
        $type = $this->request->getPost('type') ?: $this->request->getParam('type');
        if (!in_array($type, ['blocked', 'whitelist'])) {
            return ["status" => "failed", "message" => "Type must be 'blocked' or 'whitelist'"];
        }

        $backend = new Backend();
        $response = $backend->configdpRun("deepinspector", ["show_json", $type]);
        if (empty(trim($response))) {
            return [
                "status" => "failed",
                "error" => "Invalid backend response",
                "message" => "Getting $type IPs JSON data"
            ];
        }

        $data = json_decode($response, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return [
                "status" => "ok",
                "data" => $data,
                "message" => "Getting $type IPs JSON data"
            ];
        }

        return [
            "status" => "failed",
            "error" => "Invalid JSON response from backend",
            "response" => $response,
            "message" => "Getting $type IPs JSON data"
        ];
    }

    /**
     * Check the status of an IP address (blocked, whitelisted, or unknown)
     *
     * Verifies whether the specified IP address is in the blocked or whitelisted list
     * using the OPNsense backend. Validates the IP address format and requires an IP parameter.
     *
     * @api POST /api/deepinspector/service/checkIPStatus
     *
     * Request Body Format:
     * {
     *   "ip": "192.168.1.100"
     * }
     *
     * @return array{status: string, ip_status: string, message: string, error?: string} IP status
     *
     * Response Format:
     * - status: "ok" for successful execution, "failed" if validation fails
     * - ip_status: "blocked", "whitelisted", or "unknown"
     * - message: Descriptive message of the operation
     * - error: Error message if the IP is invalid or backend response is invalid
     *
     * @example
     * POST /api/deepinspector/service/checkIPStatus
     * Content-Type: application/json
     * Body: {"ip": "192.168.1.100"}
     * Response: {
     *   "status": "ok",
     *   "ip_status": "blocked",
     *   "message": "IP is in blocked list"
     * }
     */
    public function checkIPStatusAction()
    {
        $ip = $this->request->getPost('ip') ?: $this->request->getParam('ip');
        if (empty($ip)) {
            return ["status" => "failed", "message" => "IP address is required"];
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }

        $backend = new Backend();
        $blockedResponse = $backend->configdpRun("deepinspector", ["list_blocked"]);
        if (empty(trim($blockedResponse))) {
            return [
                "status" => "failed",
                "error" => "Invalid backend response for blocked IPs",
                "message" => "Checking IP status"
            ];
        }
        $blockedIPs = array_filter(explode("\n", trim($blockedResponse)));
        if (in_array($ip, $blockedIPs)) {
            return [
                "status" => "ok",
                "ip_status" => "blocked",
                "message" => "IP is in blocked list"
            ];
        }

        $whitelistResponse = $backend->configdpRun("deepinspector", ["list_whitelist"]);
        if (empty(trim($whitelistResponse))) {
            return [
                "status" => "failed",
                "error" => "Invalid backend response for whitelisted IPs",
                "message" => "Checking IP status"
            ];
        }
        $whitelistIPs = array_filter(explode("\n", trim($whitelistResponse)));
        if (in_array($ip, $whitelistIPs)) {
            return [
                "status" => "ok",
                "ip_status" => "whitelisted",
                "message" => "IP is in whitelist"
            ];
        }

        return [
            "status" => "ok",
            "ip_status" => "unknown",
            "message" => "IP is not in any list"
        ];
    }
}