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

namespace OPNsense\AdvInspector;

/**
 * Class IndexController
 *
 * Main dashboard controller for the Advanced Network Inspector web interface.
 * This controller serves as the primary entry point and central hub for the
 * entire Advanced Network Inspector management system, providing users with
 * an overview of system status, key metrics, and navigation to detailed
 * management interfaces.
 *
 * The IndexController renders the main dashboard page which typically serves
 * as the landing page for the Advanced Network Inspector plugin. This page
 * provides administrators with a comprehensive overview of the system's
 * operational status and key performance indicators.
 *
 * Dashboard Functionality:
 * - System status overview and health indicators
 * - Real-time service status monitoring
 * - Key performance metrics and statistics
 * - Recent alerts and security events summary
 * - Quick access navigation to detailed management pages
 * - Configuration status and validation indicators
 *
 * Navigation Hub:
 * The dashboard serves as a central navigation point providing access to:
 * - Settings and configuration management
 * - Security rules management
 * - Alerts and monitoring interfaces
 * - Logs and forensic analysis tools
 * - Service control and maintenance functions
 *
 * @package OPNsense\AdvInspector
 * @author Pierpaolo Casati
 */
class IndexController extends \OPNsense\Base\IndexController
{
    /**
     * Render the main Advanced Network Inspector dashboard
     *
     * This action serves as the primary entry point for the Advanced Network Inspector
     * web interface, rendering the main dashboard page that provides administrators
     * with a comprehensive overview of the system's status and performance.
     *
     * The dashboard is designed to give users immediate visibility into:
     * - Current service operational status (running, stopped, error states)
     * - System health indicators and resource utilization
     * - Recent security events and alert summaries
     * - Key performance metrics (packets processed, rules matched, etc.)
     * - Configuration validation status and any issues requiring attention
     * - Quick access controls for common administrative tasks
     *
     * Template Components:
     * The rendered dashboard template typically includes:
     * - Service status widget with start/stop/restart controls
     * - Real-time metrics dashboard with charts and graphs
     * - Recent alerts summary table with severity indicators
     * - System configuration overview with validation status
     * - Performance statistics and trend visualizations
     * - Navigation cards for accessing detailed management interfaces
     *
     * Client-Side Data Loading:
     * The dashboard page loads data dynamically through AJAX calls to various API endpoints:
     * - /api/advinspector/service/status - Service operational status
     * - /api/advinspector/alerts/stats - Alert statistics and summaries
     * - /api/advinspector/settings/get - Configuration status information
     * - Custom endpoints for performance metrics and system health
     *
     * @route GET /ui/advinspector
     * @route GET /ui/advinspector/index
     *
     * @return void This method renders a view template and does not return data
     *
     * View Template: 'OPNsense/AdvInspector/index'
     * - Template Location: /usr/local/opnsense/mvc/app/views/OPNsense/AdvInspector/index.volt
     * - Contains: Main dashboard HTML structure and layout
     * - Includes: JavaScript for dynamic content loading and real-time updates
     * - Utilizes: OPNsense UI framework components and widgets
     * - Integrates: Bootstrap-based responsive design components
     *
     * User Experience Features:
     * - Responsive design that works on desktop and mobile devices
     * - Real-time data updates without requiring page refresh
     * - Intuitive navigation with clear visual hierarchy
     * - Status indicators using color coding and icons
     * - Interactive elements for quick access to common tasks
     * - Contextual help and tooltips for complex information
     *
     * Security and Access Control:
     * - Authentication enforced by OPNsense framework
     * - Role-based access control for administrative functions
     * - Audit logging of dashboard access and administrative actions
     * - CSRF protection for all interactive elements
     * - Secure API communication for data loading
     *
     * Performance Optimizations:
     * - Lightweight initial page load with template-only rendering
     * - Asynchronous data loading to improve perceived performance
     * - Client-side caching to reduce unnecessary API requests
     * - Progressive enhancement for optional JavaScript features
     * - Optimized API endpoints with appropriate caching headers
     *
     * @throws \Exception When view template cannot be found or rendered
     * @throws \RuntimeException When required system components are unavailable
     *
     * @example
     * // User accesses main dashboard
     * GET /ui/advinspector/
     * 
     * // Controller renders dashboard template
     * Template: OPNsense/AdvInspector/index.volt
     * 
     * // Page JavaScript loads dashboard data
     * AJAX: GET /api/advinspector/service/status
     * AJAX: GET /api/advinspector/alerts/stats
     * AJAX: GET /api/advinspector/settings/get
     * 
     * // User sees live dashboard with:
     * // - Service status: "Running (PID: 12345)"
     * // - Recent alerts: "3 high severity in last hour"
     * // - Performance: "1.2M packets processed today"
     * // - Quick actions: Start/Stop/Restart buttons
     */
    public function indexAction()
    {
        // Select the main dashboard view template for rendering
        // This template contains the complete dashboard interface including
        // service status widgets, performance charts, alert summaries,
        // and navigation elements for the Advanced Network Inspector
        $this->view->pick('OPNsense/AdvInspector/index');
    }
}
