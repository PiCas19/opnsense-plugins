<?php
/*
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * All rights reserved.
 */

namespace OPNsense\WebGuard;

use OPNsense\Base\IndexController;
use OPNsense\WebGuard\WebGuard;

/**
 * ThreatsController MVC - Serve le pagine HTML per le minacce
 * Posizione: /usr/local/opnsense/mvc/app/controllers/OPNsense/WebGuard/ThreatsController.php
 */
class ThreatsController extends IndexController
{
    /**
     * Pagina principale delle minacce
     */
    public function indexAction()
    {
        try {
            // Carica il modello WebGuard
            $mdlWebGuard = new WebGuard();
            
            // Imposta le variabili della vista in modo sicuro
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            $this->view->title = gettext("");
            
            // Aggiungi informazioni aggiuntive per la pagina
            $this->view->threatDetection = $this->isThreatDetectionEnabled($mdlWebGuard);
            $this->view->logLevel = (string)$mdlWebGuard->general->log_level;
            
        } catch (\Exception $e) {
            // Log dell'errore per debugging
            error_log("WebGuard Threats MVC Error: " . $e->getMessage());
            
            // Valori di fallback sicuri
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->threatDetection = false;
            $this->view->logLevel = 'info';
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("WebGuard Threats");
        }
        
        // Seleziona il template della pagina threats
        $this->view->pick('OPNsense/WebGuard/threats');
    }
    
    /**
     * Dettagli di una minaccia specifica
     */
    public function detailAction($id = null)
    {
        try {
            $mdlWebGuard = new WebGuard();
            
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->threatId = $id;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            $this->view->title = gettext("Threat Details");
            
            // Valida l'ID della minaccia
            if (empty($id) || !is_numeric($id)) {
                $this->view->error = gettext("Invalid threat ID");
            }
            
        } catch (\Exception $e) {
            error_log("WebGuard Threat Detail MVC Error: " . $e->getMessage());
            
            $this->view->webguardModel = null;
            $this->view->threatId = $id;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Threat Details");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_details');
    }
    
    /**
     * Statistiche delle minacce
     */
    public function statsAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            $this->view->title = gettext("Threat Statistics");
            
            // Aggiungi configurazioni specifiche per le statistiche
            $this->view->statisticsEnabled = $this->isStatisticsEnabled($mdlWebGuard);
            $this->view->retentionDays = 30; // Valore fisso dato che non è nel modello
            
        } catch (\Exception $e) {
            error_log("WebGuard Threat Stats MVC Error: " . $e->getMessage());
            
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->statisticsEnabled = false;
            $this->view->retentionDays = 30;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Threat Statistics");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_stats');
    }
    
    /**
     * Analisi geografica delle minacce
     */
    public function geoAction()
    {
        try {
            $mdlWebGuard = new WebGuard();

            // Imposta i parametri della vista
            $this->view->webguardModel    = $mdlWebGuard;
            $this->view->isEnabled        = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode      = (string)$mdlWebGuard->general->mode;
            $this->view->geoBlocking      = $this->isGeoBlockingEnabled($mdlWebGuard);
            $this->view->geoDatabase      = $this->isGeoDatabaseAvailable();
            $this->view->blockedCountries = [];  // Da aggiornare se vuoi integrarli dal backend
            $this->response->setHeader(
                'Content-Security-Policy',
                "default-src 'self'; img-src 'self' data: blob: https://a.tile.openstreetmap.org https://b.tile.openstreetmap.org https://c.tile.openstreetmap.org;"
            );
            $this->view->title            = gettext("Geographic Threat Analysis");

        } catch (\Exception $e) {
            error_log("WebGuard Geo Analysis MVC Error: " . $e->getMessage());

            // In caso di errore, imposta fallback sicuri
            $this->view->webguardModel    = null;
            $this->view->isEnabled        = false;
            $this->view->currentMode      = 'learning';
            $this->view->geoBlocking      = false;
            $this->view->geoDatabase      = false;
            $this->view->blockedCountries = [];
            $this->view->error            = $e->getMessage();
            $this->view->title            = gettext("Geographic Threat Analysis");
        }

        // Seleziona la vista associata
        $this->view->pick('OPNsense/WebGuard/threat_geo');
    }


    
    /**
     * Analisi dei pattern di attacco
     */
    public function patternsAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            $this->view->title = gettext("Attack Pattern Analysis");
            
            // Configurazioni per l'analisi dei pattern (usando le proprietà reali del modello)
            $this->view->behavioralEnabled = $this->isBehavioralEnabled($mdlWebGuard);
            $this->view->patternAnalysis = $this->isPatternAnalysisEnabled($mdlWebGuard);
            $this->view->machineLearning = false; // Non presente nel modello
            
        } catch (\Exception $e) {
            error_log("WebGuard Attack Patterns MVC Error: " . $e->getMessage());
            
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->behavioralEnabled = false;
            $this->view->patternAnalysis = false;
            $this->view->machineLearning = false;
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Attack Pattern Analysis");
        }
        
        $this->view->pick('OPNsense/WebGuard/attack_patterns');
    }
    
    /* ===== METODI HELPER PRIVATI CORRETTI ===== */
    
    /**
     * Verifica se il rilevamento delle minacce è abilitato
     */
    private function isThreatDetectionEnabled($model)
    {
        try {
            return (string)$model->general->enabled === '1' && 
                   (string)$model->general->mode !== 'disabled';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se l'analisi comportamentale è abilitata
     */
    private function isBehavioralEnabled($model)
    {
        try {
            // Usa la proprietà reale del modello
            return (string)$model->behavioral->anomaly_detection === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se le statistiche sono abilitate
     */
    private function isStatisticsEnabled($model)
    {
        try {
            // Semplificato: se WebGuard è abilitato, le statistiche sono disponibili
            return (string)$model->general->enabled === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    
    /**
     * Verifica se il geo-blocking è abilitato
     */
    private function isGeoBlockingEnabled($model)
    {
        try {
            // Usa la proprietà reale del modello
            return (string)$model->general->geo_blocking === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se l'analisi dei pattern è abilitata
     */
    private function isPatternAnalysisEnabled($model)
    {
        try {
            // Usa la proprietà reale del modello
            return (string)$model->behavioral->traffic_pattern_analysis === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il database geografico è disponibile
     */
    private function isGeoDatabaseAvailable()
    {
        try {
            // Controlla se il file del database GeoIP esiste
            $geoDbPath = '/usr/local/share/GeoIP/GeoLite2-Country.mmdb';
            return file_exists($geoDbPath);
        } catch (\Exception $e) {
            return false;
        }
    }
}