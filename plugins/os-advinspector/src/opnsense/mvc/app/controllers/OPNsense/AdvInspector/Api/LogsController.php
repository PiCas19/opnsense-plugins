<?php

/*
 * Copyright (C) 2024 Advanced Network Inspector
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
 * Class LogsController
 *
 * Provides API endpoints for accessing and managing Advanced Network Inspector log files.
 * Supports efficient reading of large log files with filtering capabilities and raw packet
 * data download functionality for forensic analysis.
 *
 * Features:
 * - Efficient reverse file reading for recent entries
 * - Timestamp-based filtering for incremental updates
 * - Raw packet data download in binary format
 * - Memory-efficient processing of large log files
 * - JSON structured log entry parsing
 *
 * @package OPNsense\AdvInspector\Api
 * @author Pierpaolo Casati
 */
class LogsController extends ApiControllerBase
{
    /**
     * Mapping of log types to their corresponding file paths
     * 
     * @var array<string, string> Log type to file path mapping
     */
    private const LOG_FILES = [
        'alerts'  => '/var/log/advinspector_alerts.log',
        'packets' => '/var/log/advinspector_packets.log',
    ];

    /**
     * Read and retrieve log entries from specified log file
     *
     * Efficiently reads log entries from the end of the file backwards to get
     * the most recent entries first. Supports incremental reading using the
     * 'since' parameter to only retrieve entries newer than a specified timestamp.
     *
     * This method uses a character-by-character reverse reading approach to handle
     * very large log files without loading the entire file into memory.
     *
     * @api GET /api/advinspector/logs/read
     * 
     * Query Parameters:
     * @param string $type Log type to read ('alerts' or 'packets', default: 'alerts')
     * @param string $since Optional ISO timestamp to filter entries newer than this time
     * 
     * Response Format:
     * @return array{
     *   status: string,
     *   logs: array<array<string, mixed>>,
     *   type: string,
     *   message?: string
     * } JSON response containing log entries or error information
     * 
     * Success Response:
     * - status: 'ok'
     * - logs: Array of parsed JSON log entries, sorted chronologically
     * - type: The log type that was requested
     * 
     * Error Response:
     * - status: 'error'
     * - logs: Empty array
     * - message: Error description
     * 
     * @throws \RuntimeException When unable to open or read log file
     * @throws \Throwable On any other processing error
     * 
     * @example
     * // Get latest 200 alert entries
     * GET /api/advinspector/logs/read?type=alerts
     * 
     * // Get packet entries newer than specific timestamp
     * GET /api/advinspector/logs/read?type=packets&since=2024-01-20T10:30:00Z
     */
    public function readAction()
    {
        // Extract and validate request parameters
        $type = $this->request->get('type') ?: 'alerts';
        $since = $this->request->get('since') ?: null;
        $logFile = self::LOG_FILES[$type] ?? null;

        // Validate log file accessibility
        if (!$logFile || !file_exists($logFile) || !is_readable($logFile)) {
            return [
                'status' => 'error', 
                'logs' => [], 
                'message' => 'Invalid or unreadable log file'
            ];
        }

        try {
            // Open file handle for reading
            $fp = fopen($logFile, 'r');
            if (!$fp) {
                throw new \RuntimeException("Unable to open log file");
            }

            // Initialize reading variables
            $logs = [];
            $maxEntries = 200; // Maximum entries to return in one request
            $pos = -1; // Current position from end of file
            $chunk = ''; // Character accumulator for current line
            $lineCount = 0;

            // Get file size for boundary checking
            fseek($fp, 0, SEEK_END);
            $filesize = ftell($fp);

            // Read file backwards character by character
            while (abs($pos) < $filesize) {
                // Move to next character from end
                fseek($fp, $pos--, SEEK_END);
                $char = fgetc($fp);
                $chunk = $char . $chunk;

                // Process complete line when newline is found
                if ($char === "\n") {
                    $line = trim($chunk);
                    $chunk = ''; // Reset chunk for next line
                    
                    if (!empty($line)) {
                        // Parse JSON log entry
                        $entry = json_decode($line, true);
                        if (is_array($entry)) {
                            // Apply timestamp filter if specified
                            if ($since) {
                                if (!isset($entry['timestamp']) || strcmp($entry['timestamp'], $since) <= 0) {
                                    // Reached the cutoff timestamp, stop reading
                                    break;
                                }
                            }

                            $logs[] = $entry;
                            $lineCount++;

                            // Stop if maximum entries reached (unless filtering by timestamp)
                            if (!$since && $lineCount >= $maxEntries) {
                                break;
                            }
                        }
                    }
                }
            }

            fclose($fp);

            // Sort entries chronologically (oldest first) for proper display order
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

    /**
     * Download raw packet data in binary format for forensic analysis
     *
     * Searches through log entries to find a packet with the specified timestamp
     * and provides the raw packet data as a binary download. The raw data is
     * stored as hexadecimal strings in the log files and is converted back to
     * binary format for download.
     *
     * This functionality is essential for network forensics, allowing security
     * analysts to examine the actual packet contents with external tools like
     * Wireshark or tcpdump.
     *
     * @api GET /api/advinspector/logs/download/{timestamp}
     * 
     * URL Parameters:
     * @param string $timestamp URL-encoded ISO timestamp of the packet to download
     * 
     * Query Parameters:
     * @param string $type Log type to search ('alerts' or 'packets', default: 'packets')
     * 
     * @return void This method directly outputs binary data and exits
     * 
     * Success Response:
     * - HTTP 200 with binary packet data
     * - Content-Type: application/octet-stream
     * - Content-Disposition: attachment with safe filename
     * - Content-Length: Size of binary data
     * 
     * Error Responses:
     * - HTTP 400: Missing or invalid timestamp parameter
     * - HTTP 404: Log file not accessible or matching entry not found
     * - HTTP 500: Invalid hexadecimal data format
     * 
     * Security Considerations:
     * - Timestamp parameter is sanitized for safe filename generation
     * - File path validation prevents directory traversal attacks
     * - Binary data validation ensures hex format integrity
     * 
     * @throws \RuntimeException When file operations fail
     * 
     * @example
     * // Download packet data for specific timestamp
     * GET /api/advinspector/logs/download/2024-01-20T10:30:45.123Z?type=packets
     * 
     * // This will download a file named: packets_2024-01-20T10_30_45_123Z.bin
     */
    public function downloadAction($timestamp = null)
    {
        // Extract and validate request parameters
        $type = $this->request->get('type') ?: 'packets';
        $logFile = self::LOG_FILES[$type] ?? null;

        // Validate log file accessibility
        if (!$logFile || !file_exists($logFile) || !is_readable($logFile)) {
            header("HTTP/1.1 404 Not Found");
            exit("Log file not accessible.");
        }

        // Validate timestamp parameter
        if (empty($timestamp)) {
            header("HTTP/1.1 400 Bad Request");
            exit("Missing timestamp parameter.");
        }

        // Decode URL-encoded timestamp
        $timestamp = urldecode($timestamp);

        try {
            // Read all log file lines into memory
            // Note: For very large files, this could be optimized with streaming
            $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            // Search for matching timestamp entry
            foreach ($lines as $line) {
                $entry = json_decode($line, true);
                if (!is_array($entry)) {
                    continue; // Skip malformed entries
                }

                // Check if this entry matches the requested timestamp and contains raw data
                if (
                    isset($entry['timestamp'], $entry['raw']) &&
                    trim($entry['timestamp']) === trim($timestamp)
                ) {
                    // Convert hexadecimal string back to binary data
                    $binary = hex2bin($entry['raw']);
                    if ($binary === false) {
                        header("HTTP/1.1 500 Internal Server Error");
                        exit("Invalid hexadecimal format in log entry.");
                    }

                    // Generate safe filename by replacing special characters
                    $safeTimestamp = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $timestamp);
                    $filename = "{$type}_{$safeTimestamp}.bin";

                    // Set HTTP headers for binary download
                    header("Content-Type: application/octet-stream");
                    header("Content-Disposition: attachment; filename=\"$filename\"");
                    header("Content-Length: " . strlen($binary));
                    header("Cache-Control: no-cache, must-revalidate");
                    header("Pragma: no-cache");
                    
                    // Output binary data and terminate
                    echo $binary;
                    exit;
                }
            }

            // No matching entry found
            header("HTTP/1.1 404 Not Found");
            exit("No packet found with the specified timestamp.");
            
        } catch (\Throwable $e) {
            header("HTTP/1.1 500 Internal Server Error");
            exit("Error processing download request: " . $e->getMessage());
        }
    }
}