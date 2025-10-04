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
 * API controller for managing logs
 *
 * Provides endpoints for reading packet inspection logs including alerts
 * and raw packet data. Returns only real data from the inspector.
 *
 * @package OPNsense\AdvInspector\Api
 */
class LogsController extends ApiControllerBase
{
    /** @var array Mapping of log types to file paths */
    private const LOG_FILES = [
        'alerts'  => '/var/log/advinspector_alerts.log',
        'packets' => '/var/log/advinspector_packets.log',
    ];

    /**
     * Read logs from the inspection system
     *
     * Retrieves log entries based on type (alerts/packets) and optional timestamp.
     * Returns real data only - empty array if no logs exist.
     *
     * @return array Response with status, logs array, and type
     */
    public function readAction()
    {
        $type = $this->request->get('type') ?: 'alerts';
        $since = $this->request->get('since') ?: null;
        $logFile = self::LOG_FILES[$type] ?? null;

        // Return empty logs array if file doesn't exist or is not readable
        if (!$logFile || !file_exists($logFile) || !is_readable($logFile)) {
            return ['status' => 'ok', 'logs' => [], 'type' => $type];
        }

        try {
            $fp = fopen($logFile, 'r');
            if (!$fp) {
                throw new \RuntimeException("Unable to open log file");
            }

            $logs = [];
            $bufferSize = 8192;
            $lines = [];
            $maxEntries = 200;
            $pos = -1;
            $chunk = '';
            $lineCount = 0;

            fseek($fp, 0, SEEK_END);
            $filesize = ftell($fp);

            while (abs($pos) < $filesize) {
                fseek($fp, $pos--, SEEK_END);
                $char = fgetc($fp);
                $chunk = $char . $chunk;

                if ($char === "\n") {
                    $line = trim($chunk);
                    $chunk = '';
                    if (!empty($line)) {
                        $entry = json_decode($line, true);
                        if (is_array($entry)) {
                            if ($since) {
                                if (!isset($entry['timestamp']) || strcmp($entry['timestamp'], $since) <= 0) {
                                    // Raggiunto il timestamp, fermati
                                    break;
                                }
                            }

                            $logs[] = $entry;
                            $lineCount++;

                            if (!$since && $lineCount >= $maxEntries) {
                                break;
                            }
                        }
                    }
                }
            }

            fclose($fp);

            // Sort ascending by timestamp for console append
            usort($logs, function ($a, $b) {
                return strcmp($a['timestamp'] ?? '', $b['timestamp'] ?? '');
            });

            return [
                'status' => 'ok',
                'logs'   => $logs,
                'type'   => $type
            ];
        } catch (\Throwable $e) {
            // Return empty logs array on error (no fallback data)
            return [
                'status'  => 'ok',
                'logs'    => [],
                'type'    => $type
            ];
        }
    }



    /**
     * Download raw packet data
     *
     * Provides binary download of a specific packet identified by timestamp.
     * Returns 404 if no matching entry is found (no fallback data).
     *
     * @param string|null $timestamp The packet timestamp to download
     * @return void Outputs binary data directly
     */
    public function downloadAction($timestamp = null)
    {
        $type = $this->request->get('type') ?: 'packets';
        $logFile = self::LOG_FILES[$type] ?? null;

        if (!$logFile || !file_exists($logFile) || !is_readable($logFile)) {
            header("HTTP/1.1 404 Not Found");
            exit("Log file not accessible.");
        }

        if (empty($timestamp)) {
            header("HTTP/1.1 400 Bad Request");
            exit("Missing timestamp.");
        }

        $timestamp = urldecode($timestamp);

        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                continue;
            }

            if (
                isset($entry['timestamp'], $entry['raw']) &&
                trim($entry['timestamp']) === trim($timestamp)
            ) {
                $binary = hex2bin($entry['raw']);
                if ($binary === false) {
                    header("HTTP/1.1 500 Internal Server Error");
                    exit("Invalid hex format.");
                }

                $safeTimestamp = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $timestamp);
                $filename = "{$type}_{$safeTimestamp}.bin";

                header("Content-Type: application/octet-stream");
                header("Content-Disposition: attachment; filename=\"$filename\"");
                header("Content-Length: " . strlen($binary));
                echo $binary;
                exit;
            }
        }

        header("HTTP/1.1 404 Not Found");
        exit("Matching entry not found.");
    }
}
