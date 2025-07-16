<?php

namespace OPNsense\AdvInspector\Api;

use OPNsense\Base\ApiControllerBase;

class LogsController extends ApiControllerBase
{
    private const LOG_FILES = [
        'alerts'  => '/var/log/advinspector_alerts.log',
        'packets' => '/var/log/advinspector_packets.log',
    ];

    public function readAction()
    {
        $type = $this->request->get('type') ?: 'alerts';
        $since = $this->request->get('since') ?: null;
        $logFile = self::LOG_FILES[$type] ?? null;

        if (!$logFile || !file_exists($logFile) || !is_readable($logFile)) {
            return ['status' => 'error', 'logs' => [], 'message' => 'Invalid or unreadable log file'];
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

            // Ordina crescente per timestamp per append in console
            usort($logs, function ($a, $b) {
                return strcmp($a['timestamp'] ?? '', $b['timestamp'] ?? '');
            });

            return [
                'status' => 'ok',
                'logs'   => $logs,
                'type'   => $type
            ];
        } catch (\Throwable $e) {
            return [
                'status'  => 'error',
                'logs'    => [],
                'message' => $e->getMessage()
            ];
        }
    }



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
