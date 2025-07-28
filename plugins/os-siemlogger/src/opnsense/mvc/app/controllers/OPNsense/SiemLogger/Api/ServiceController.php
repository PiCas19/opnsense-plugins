<?php

/*
 * Copyright (C) 2025 OPNsense SIEM Logger Plugin
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

namespace OPNsense\SiemLogger\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * /api/siemlogger/service/<action>
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass    = '\\OPNsense\\SiemLogger\\SiemLogger';
    protected static $internalServiceTemplate = 'OPNsense/SiemLogger';
    protected static $internalServiceEnabled  = 'general.enabled';
    protected static $internalServiceName     = 'siemlogger';

    /* ===== SERVICE MANAGEMENT ===== */

    public function startAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        return $this->svcCmd('start');
    }

    public function stopAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        return $this->svcCmd('stop');
    }

    public function restartAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        return $this->svcCmd('restart');
    }

    public function statusAction()
    {
        $backend = new Backend();
        $out = trim($backend->configdRun('siemlogger status'));

        $isRunning = (strpos($out, 'is running') !== false) ||
                     (strpos($out, 'siemlogger is running') !== false) ||
                     (strpos($out, 'active') !== false);

        return [
            'status'   => 'ok',
            'running'  => $isRunning,
            'response' => $out
        ];
    }

    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $result = $backend->configdpRun('siemlogger', ['reconfigure']);

        return [
            'status' => 'ok',
            'message' => 'Configuration reloaded',
            'response' => $result
        ];
    }

    /* ===== SIEM OPERATIONS ===== */

    public function exportEventsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $format = $this->request->getPost('format', 'string', 'json');
        if (!in_array($format, ['json', 'syslog', 'cef', 'leef'])) {
            return ['status' => 'error', 'message' => 'Invalid format'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('siemlogger', ['export_events', $format]));

        if ($out && $out !== '') {
            $data = json_decode($out, true);
            if (is_array($data)) {
                $filename = 'siemlogger_events_' . date('Y-m-d_H-i-s') . '.' . $format;
                $contentTypes = [
                    'json' => 'application/json',
                    'syslog' => 'text/plain',
                    'cef' => 'text/plain',
                    'leef' => 'text/plain'
                ];

                return [
                    'status' => 'ok',
                    'filename' => $filename,
                    'content_type' => $contentTypes[$format] ?? 'application/octet-stream',
                    'data' => $out
                ];
            }
        }

        return ['status' => 'error', 'message' => 'Failed to export events', 'data' => []];
    }

    public function getStatsAction()
    {
        $backend = new Backend();
        $out = trim($backend->configdpRun('siemlogger', ['get_stats']));

        if ($out && $out !== '') {
            $stats = json_decode($out, true);
            if (is_array($stats)) {
                return ['status' => 'ok', 'data' => $stats];
            }
        }

        return ['status' => 'error', 'message' => 'Failed to retrieve statistics', 'data' => []];
    }

    public function getLogsAction()
    {
        $page = max(1, (int)$this->request->getQuery('page', 'int', 1));
        $limit = max(1, min(1000, (int)$this->request->getQuery('limit', 'int', 100)));

        $backend = new Backend();
        $out = trim($backend->configdpRun('siemlogger', ['get_logs', (string)$page, (string)$limit]));

        if ($out && $out !== '') {
            $logs = json_decode($out, true);
            if (is_array($logs)) {
                if (!empty($logs['logs'])) {
                    foreach ($logs['logs'] as &$row) {
                        $row['message'] = $this->viewSafe($row['message'] ?? 'Unknown');
                        if (isset($row['timestamp']) && !isset($row['timestamp_iso'])) {
                            $row['timestamp_iso'] = date('c', $row['timestamp']);
                        }
                    }
                }
                return ['status' => 'ok', 'data' => $logs];
            }
        }

        return ['status' => 'error', 'message' => 'Failed to retrieve logs', 'data' => []];
    }

    public function clearLogsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('siemlogger', ['clear_logs']));

        if (strpos($out, 'OK:') === 0 || strpos($out, 'Success') !== false) {
            return ['status' => 'ok', 'message' => 'Logs cleared successfully'];
        }

        return ['status' => 'error', 'message' => $this->cleanErrorMessage($out)];
    }

    public function testExportAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $format = $this->request->getPost('format', 'string', 'json');
        if (!in_array($format, ['json', 'syslog', 'cef', 'leef'])) {
            return ['status' => 'error', 'message' => 'Invalid format'];
        }

        $backend = new Backend();
        $out = trim($backend->configdpRun('siemlogger', ['test_export', $format]));

        if ($out && $out !== '') {
            $result = json_decode($out, true);
            if (is_array($result)) {
                return ['status' => 'ok', 'data' => $result];
            }
        }

        return ['status' => 'error', 'message' => 'Failed to test export', 'data' => []];
    }

    /* ===== HELPER METHODS ===== */

    private function svcCmd(string $cmd): array
    {
        $backend = new Backend();

        if (in_array($cmd, ['start', 'stop', 'restart', 'status'])) {
            $response = $backend->configdRun("siemlogger {$cmd}");
        } else {
            $response = $backend->configdpRun('siemlogger', [$cmd]);
        }

        $success = (strpos($response, 'OK:') === 0) ||
                   (strpos($response, 'Success') !== false) ||
                   (strpos($response, 'started') !== false) ||
                   (strpos($response, 'stopped') !== false) ||
                   (strpos($response, 'restarted') !== false);

        return [
            'status' => $success ? 'ok' : 'error',
            'response' => $response,
            'message' => $success ? ucfirst($cmd) . ' completed' : $this->cleanErrorMessage($response)
        ];
    }

    private function viewSafe(string $value): string
    {
        return htmlspecialchars(str_replace('_', ' ', $value), ENT_QUOTES, 'UTF-8');
    }

    private function cleanErrorMessage(string $message): string
    {
        $message = trim($message);
        if (strpos($message, 'ERROR:') === 0) {
            $message = substr($message, 6);
        }
        return empty($message) ? 'Operation failed' : $message;
    }
}