<?php

namespace OPNsense\DeepInspector\Api;

use OPNsense\Base\ApiControllerBase;

class AlertsController extends ApiControllerBase
{
    private const ALERT_LOG = '/var/log/deepinspector/alerts.log';
    private const THREAT_LOG = '/var/log/deepinspector/threats.log';
    private const DETECTION_LOG = '/var/log/deepinspector/detections.log';

    /**
     * Get recent alerts with filtering and pagination
     * @return array
     */
    public function listAction()
    {
        $severity = $this->request->get('severity') ?: 'all';
        $type = $this->request->get('type') ?: 'all';
        $since = $this->request->get('since') ?: null;
        $limit = min((int)($this->request->get('limit') ?: 100), 500);

        try {
            $alerts = $this->readAlertLog(self::ALERT_LOG, $since, $limit);
            
            // Filter by severity and type
            if ($severity !== 'all') {
                $alerts = array_filter($alerts, function($alert) use ($severity) {
                    return ($alert['severity'] ?? 'medium') === $severity;
                });
            }

            if ($type !== 'all') {
                $alerts = array_filter($alerts, function($alert) use ($type) {
                    return ($alert['threat_type'] ?? 'unknown') === $type;
                });
            }

            return [
                'status' => 'ok',
                'data' => array_values($alerts),
                'count' => count($alerts),
                'filters' => [
                    'severity' => $severity,
                    'type' => $type,
                    'since' => $since
                ]
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to read alerts: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Get threat statistics and trends
     * @return array
     */
    public function threatStatsAction()
    {
        try {
            $stats = $this->calculateThreatStats();
            return ['status' => 'ok', 'data' => $stats];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Get detailed information about a specific threat
     * @param string $threatId
     * @return array
     */
    public function threatDetailsAction($threatId = null)
    {
        if (!$threatId) {
            return ['status' => 'error', 'message' => 'Threat ID required'];
        }

        try {
            $details = $this->getThreatDetails($threatId);
            return ['status' => 'ok', 'data' => $details];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Export alerts for external analysis
     * @return array
     */
    public function exportAction()
    {
        $format = $this->request->get('format') ?: 'json';
        $hours = min((int)($this->request->get('hours') ?: 24), 168); // Max 1 week

        try {
            $since = date('c', time() - ($hours * 3600));
            $alerts = $this->readAlertLog(self::ALERT_LOG, $since, 10000);

            if ($format === 'csv') {
                return $this->exportToCsv($alerts);
            } else {
                return [
                    'status' => 'ok',
                    'data' => $alerts,
                    'export_time' => date('c'),
                    'timeframe_hours' => $hours
                ];
            }
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Mark alert as resolved or add notes
     * @param string $alertId
     * @return array
     */
    public function updateAlertAction($alertId = null)
    {
        if (!$alertId || !$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'Invalid request'];
        }

        $status = $this->request->getPost('status');
        $notes = $this->request->getPost('notes');

        try {
            $result = $this->updateAlertStatus($alertId, $status, $notes);
            return ['status' => 'ok', 'data' => $result];
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    private function readAlertLog($logFile, $since = null, $limit = 100)
    {
        if (!file_exists($logFile) || !is_readable($logFile)) {
            return [];
        }

        $alerts = [];
        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        // Read from end for recent alerts
        $lines = array_reverse($lines);
        $count = 0;

        foreach ($lines as $line) {
            if ($count >= $limit) break;

            $alert = json_decode($line, true);
            if (!is_array($alert)) continue;

            if ($since && isset($alert['timestamp'])) {
                if (strtotime($alert['timestamp']) < strtotime($since)) {
                    break;
                }
            }

            $alerts[] = $alert;
            $count++;
        }

        return array_reverse($alerts); // Restore chronological order
    }

    private function calculateThreatStats()
    {
        $stats = [
            'last_24h' => ['total' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
            'last_7d' => ['total' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
            'threat_types' => [],
            'top_sources' => [],
            'detection_rate_trend' => []
        ];

        $alerts = $this->readAlertLog(self::ALERT_LOG, date('c', time() - (7*24*3600)), 10000);

        $day_ago = time() - (24*3600);
        
        foreach ($alerts as $alert) {
            $timestamp = strtotime($alert['timestamp'] ?? '');
            $severity = $alert['severity'] ?? 'medium';
            $threat_type = $alert['threat_type'] ?? 'unknown';
            $source_ip = $alert['source_ip'] ?? 'unknown';

            // Last 7 days stats
            $stats['last_7d']['total']++;
            $stats['last_7d'][$severity] = ($stats['last_7d'][$severity] ?? 0) + 1;

            // Last 24 hours stats
            if ($timestamp >= $day_ago) {
                $stats['last_24h']['total']++;
                $stats['last_24h'][$severity] = ($stats['last_24h'][$severity] ?? 0) + 1;
            }

            // Threat types
            $stats['threat_types'][$threat_type] = ($stats['threat_types'][$threat_type] ?? 0) + 1;

            // Top sources
            $stats['top_sources'][$source_ip] = ($stats['top_sources'][$source_ip] ?? 0) + 1;
        }

        // Sort top sources
        arsort($stats['top_sources']);
        $stats['top_sources'] = array_slice($stats['top_sources'], 0, 10, true);

        return $stats;
    }

    private function getThreatDetails($threatId)
    {
        // Implementation would search through logs for specific threat ID
        // and compile detailed information including packet captures,
        // analysis results, related alerts, etc.
        
        return [
            'threat_id' => $threatId,
            'status' => 'active',
            'first_seen' => date('c'),
            'last_seen' => date('c'),
            'packet_samples' => [],
            'analysis_results' => [],
            'related_alerts' => []
        ];
    }

    private function exportToCsv($alerts)
    {
        $csv = "timestamp,severity,threat_type,source_ip,destination_ip,protocol,description\n";
        
        foreach ($alerts as $alert) {
            $csv .= sprintf("%s,%s,%s,%s,%s,%s,\"%s\"\n",
                $alert['timestamp'] ?? '',
                $alert['severity'] ?? '',
                $alert['threat_type'] ?? '',
                $alert['source_ip'] ?? '',
                $alert['destination_ip'] ?? '',
                $alert['protocol'] ?? '',
                str_replace('"', '""', $alert['description'] ?? '')
            );
        }

        return [
            'status' => 'ok',
            'data' => $csv,
            'content_type' => 'text/csv',
            'filename' => 'dpi_alerts_' . date('Y-m-d_H-i-s') . '.csv'
        ];
    }

    private function updateAlertStatus($alertId, $status, $notes)
    {
        // Implementation would update alert status in database or log file
        return [
            'alert_id' => $alertId,
            'old_status' => 'active',
            'new_status' => $status,
            'updated_at' => date('c'),
            'notes' => $notes
        ];
    }
}