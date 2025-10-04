<?php

/*
 * Copyright (C) 2024 Your Name
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

namespace OPNsense\AdvInspector\Api;

use OPNsense\Base\ApiControllerBase;

/**
 * API controller for managing alerts
 *
 * Provides REST API endpoints for retrieving security alerts detected by
 * the Advanced Packet Inspector. Returns real data only - no fallback values.
 *
 * @package OPNsense\AdvInspector\Api
 */
class AlertsController extends ApiControllerBase
{
    /** @var string Path to the alerts log file */
    private const LOG_FILE = '/var/log/advinspector_alerts.log';

    /**
     * List security alerts
     *
     * Returns up to 100 most recent alerts from the inspection log.
     * If no alerts exist or the file cannot be read, returns an empty array
     * (no fallback data).
     *
     * @return array Response array with status and data
     *               - status: 'ok' or 'error'
     *               - data: Array of alert entries (empty if none)
     *               - message: Error description (only on error)
     */
    public function listAction()
    {
        $logFile = self::LOG_FILE;

        // Return empty array if file doesn't exist (no fallback data)
        if (!file_exists($logFile)) {
            return ['status' => 'ok', 'data' => []];
        }

        if (!is_readable($logFile)) {
            return ['status' => 'error', 'message' => 'Log file is not readable', 'data' => []];
        }

        try {
            $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines === false) {
                throw new \RuntimeException("Unable to read log file");
            }

            $alerts = [];
            foreach ($lines as $line) {
                $entry = json_decode($line, true);
                if (is_array($entry)) {
                    $alerts[] = $entry;
                }
            }

            // Sort by timestamp descending (newest first)
            usort($alerts, function ($a, $b) {
                return strcmp($b['timestamp'] ?? '', $a['timestamp'] ?? '');
            });

            return ['status' => 'ok', 'data' => array_slice($alerts, 0, 100)];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => 'Failed to read alerts: ' . $e->getMessage(), 'data' => []];
        }
    }
}