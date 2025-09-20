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

use OPNsense\Base\IndexController;

/**
 * Class AlertsController
 *
 * Web interface controller for the Advanced Network Inspector alerts management page.
 * This controller serves as the main entry point for the web-based alerts monitoring
 * interface, providing users with access to security alert visualization, filtering,
 * and analysis capabilities.
 *
 * This controller is part of the presentation layer and handles the rendering of
 * the main alerts dashboard. The actual data processing and API functionality
 * is handled by the corresponding API controller (Api\AlertsController).
 *
 * Key Responsibilities:
 * - Render the main alerts monitoring interface
 * - Serve the base template for the alerts dashboard
 * - Provide entry point for client-side JavaScript applications
 * - Handle initial page load and view selection
 *
 * The alerts interface typically includes:
 * - Real-time alert monitoring dashboard
 * - Alert filtering and search capabilities
 * - Alert severity visualization and categorization
 * - Historical alert analysis tools
 * - Export and reporting functionality
 *
 * @package OPNsense\AdvInspector
 * @author Pierpaolo Casati
 */
class AlertsController extends \OPNsense\Base\IndexController
{
    /**
     * Render the main alerts monitoring interface
     *
     * This action serves as the primary entry point for the alerts management
     * web interface. It renders the base template that contains the alerts
     * dashboard, which typically includes JavaScript applications for real-time
     * monitoring, filtering controls, and interactive alert management tools.
     *
     * The method follows the standard OPNsense MVC pattern by selecting the
     * appropriate view template for rendering. The actual alert data is loaded
     * dynamically through AJAX calls to the corresponding API endpoints.
     *
     * Page Components Rendered:
     * - Alert dashboard with real-time updates
     * - Filtering and search interface
     * - Alert severity indicators and statistics
     * - Interactive alert list with pagination
     * - Export and download controls
     * - Alert detail modal dialogs
     *
     * Client-Side Integration:
     * The rendered page includes JavaScript that communicates with:
     * - /api/advinspector/alerts/list - For alert data retrieval
     * - /api/advinspector/alerts/stats - For dashboard statistics  
     * - /api/advinspector/logs/read - For detailed log access
     * - /api/advinspector/logs/download - For packet data downloads
     *
     * @route GET /ui/advinspector/alerts
     *
     * @return void This method renders a view template and does not return data
     *
     * View Template: 'OPNsense/AdvInspector/alerts'
     * - Located at: /usr/local/opnsense/mvc/app/views/OPNsense/AdvInspector/alerts.volt
     * - Contains: HTML structure for alerts dashboard
     * - Includes: JavaScript for dynamic content loading
     * - Uses: OPNsense UI framework components
     *
     * Security Considerations:
     * - Authentication handled by OPNsense framework
     * - Authorization based on user privileges
     * - No direct data exposure (data loaded via authenticated API calls)
     * - CSRF protection provided by framework
     *
     * Performance Considerations:
     * - Initial page load is lightweight (template only)
     * - Heavy data processing handled by API endpoints
     * - Client-side caching reduces server requests
     * - Pagination prevents large data transfer
     *
     * @throws \Exception When view template cannot be found or rendered
     *
     * @example
     * // User navigates to alerts page
     * GET /ui/advinspector/alerts
     * 
     * // Controller renders template
     * Template: OPNsense/AdvInspector/alerts.volt
     * 
     * // JavaScript on page makes API calls for data
     * AJAX: GET /api/advinspector/alerts/list
     * AJAX: GET /api/advinspector/alerts/stats
     */
    public function indexAction()
    {
        // Select the appropriate view template for the alerts interface
        // This renders the main alerts dashboard page with all necessary
        // HTML structure, CSS includes, and JavaScript initialization
        $this->view->pick('OPNsense/AdvInspector/alerts');
    }
}