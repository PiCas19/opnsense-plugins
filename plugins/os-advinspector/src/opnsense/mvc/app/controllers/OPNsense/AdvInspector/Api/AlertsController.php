<?php

namespace OPNsense\AdvInspector\Api;

use OPNsense\Base\ApiControllerBase;

class AlertsController extends ApiControllerBase
{
    private const LOG_FILE = '/var/log/advinspector_alerts.log';

    public function listAction()
    {
        $logFile = self::LOG_FILE;

        if (!file_exists($logFile)) {
            return ['status' => 'ok', 'data' => []];
        }

        if (!is_readable($logFile)) {
            return ['status' => 'error', 'message' => 'Log file is not readable'];
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

            // Ordina per timestamp decrescente
            usort($alerts, function ($a, $b) {
                return strcmp($b['timestamp'] ?? '', $a['timestamp'] ?? '');
            });

            return ['status' => 'ok', 'data' => array_slice($alerts, 0, 100)];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => 'Failed to read alerts: ' . $e->getMessage()];
        }
    }
}