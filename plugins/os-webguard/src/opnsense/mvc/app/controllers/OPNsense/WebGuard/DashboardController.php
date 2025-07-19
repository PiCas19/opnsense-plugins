<?php

/*
 * DashboardController.php - CORRETTO
 * Posizione: /usr/local/opnsense/mvc/app/controllers/OPNsense/WebGuard/DashboardController.php
 */

namespace OPNsense\WebGuard;

use OPNsense\Base\IndexController;
use OPNsense\WebGuard\WebGuard;

class DashboardController extends IndexController
{
    public function indexAction()
    {
        try {
            // Prova a caricare il modello WebGuard
            $mdlWebGuard = new WebGuard();
            
            // Imposta le variabili della vista in modo sicuro
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            
            // Imposta il titolo (gettext è ora disponibile)
            $this->view->title = gettext("WebGuard Dashboard");
            
        } catch (\Exception $e) {
            // Log dell'errore
            error_log("WebGuard Dashboard Error: " . $e->getMessage());
            
            // Valori di fallback sicuri
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->title = gettext("WebGuard Dashboard");
            $this->view->error = $e->getMessage();
        }
        
        // Seleziona il template
        $this->view->pick('OPNsense/WebGuard/dashboard');
    }
}
