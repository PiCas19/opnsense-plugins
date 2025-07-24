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
            $this->view->title = gettext("WebGuard Threat Analysis");
            
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
        
        $this->view->pick('OPNsense/WebGuard/threat_detail');
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
            $this->view->retentionDays = $this->getLogRetentionDays($mdlWebGuard);
            
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
     * Feed in tempo reale delle minacce
     */
    public function feedAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            $this->view->title = gettext("Real-time Threat Feed");
            
            // Configurazioni per il feed in tempo reale
            $this->view->realTimeFeed = $this->isRealTimeFeedEnabled($mdlWebGuard);
            $this->view->updateInterval = $this->getFeedUpdateInterval($mdlWebGuard);
            
        } catch (\Exception $e) {
            error_log("WebGuard Threat Feed MVC Error: " . $e->getMessage());
            
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->realTimeFeed = false;
            $this->view->updateInterval = 5000; // 5 secondi di default
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Real-time Threat Feed");
        }
        
        $this->view->pick('OPNsense/WebGuard/threat_feed');
    }
    
    /**
     * Analisi geografica delle minacce
     */
    public function geoAction()
    {
        try {
            $mdlWebGuard = new WebGuard();
            
            $this->view->webguardModel = $mdlWebGuard;
            $this->view->isEnabled = (string)$mdlWebGuard->general->enabled === '1';
            $this->view->currentMode = (string)$mdlWebGuard->general->mode;
            $this->view->geoBlocking = $this->isGeoBlockingEnabled($mdlWebGuard);
            $this->view->title = gettext("Geographic Threat Analysis");
            
            // Configurazioni geografiche
            $this->view->geoDatabase = $this->isGeoDatabaseAvailable($mdlWebGuard);
            $this->view->blockedCountries = $this->getBlockedCountries($mdlWebGuard);
            
        } catch (\Exception $e) {
            error_log("WebGuard Geo Analysis MVC Error: " . $e->getMessage());
            
            $this->view->webguardModel = null;
            $this->view->isEnabled = false;
            $this->view->currentMode = 'learning';
            $this->view->geoBlocking = false;
            $this->view->geoDatabase = false;
            $this->view->blockedCountries = [];
            $this->view->error = $e->getMessage();
            $this->view->title = gettext("Geographic Threat Analysis");
        }
        
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
            
            // Configurazioni per l'analisi dei pattern
            $this->view->behavioralEnabled = $this->isBehavioralEnabled($mdlWebGuard);
            $this->view->patternAnalysis = $this->isPatternAnalysisEnabled($mdlWebGuard);
            $this->view->machineLearning = $this->isMachineLearningEnabled($mdlWebGuard);
            
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
    
    /* ===== METODI HELPER PRIVATI ===== */
    
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
            // Adatta questo al tuo modello WebGuard
            return isset($model->behavioral) && 
                   (string)$model->behavioral->anomaly_detection === '1';
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
            return (string)$model->general->enabled === '1' && 
                   (string)$model->general->logging === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il feed in tempo reale è abilitato
     */
    private function isRealTimeFeedEnabled($model)
    {
        try {
            return (string)$model->general->enabled === '1' && 
                   (string)$model->general->real_time_monitoring === '1';
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
            return isset($model->general->geo_blocking) && 
                   (string)$model->general->geo_blocking === '1';
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
            return isset($model->behavioral->pattern_analysis) && 
                   (string)$model->behavioral->pattern_analysis === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il machine learning è abilitato
     */
    private function isMachineLearningEnabled($model)
    {
        try {
            return isset($model->behavioral->machine_learning) && 
                   (string)$model->behavioral->machine_learning === '1';
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verifica se il database geografico è disponibile
     */
    private function isGeoDatabaseAvailable($model)
    {
        try {
            // Controlla se il file del database GeoIP esiste
            $geoDbPath = '/usr/local/share/GeoIP/GeoLite2-Country.mmdb';
            return file_exists($geoDbPath);
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Ottiene i giorni di retention dei log
     */
    private function getLogRetentionDays($model)
    {
        try {
            if (isset($model->general->log_retention_days)) {
                return (int)(string)$model->general->log_retention_days;
            }
            return 30; // Default
        } catch (\Exception $e) {
            return 30;
        }
    }
    
    /**
     * Ottiene l'intervallo di aggiornamento del feed
     */
    private function getFeedUpdateInterval($model)
    {
        try {
            if (isset($model->general->feed_update_interval)) {
                return (int)(string)$model->general->feed_update_interval * 1000; // Converti in ms
            }
            return 5000; // 5 secondi di default
        } catch (\Exception $e) {
            return 5000;
        }
    }
    
    /**
     * Ottiene la lista dei paesi bloccati
     */
    private function getBlockedCountries($model)
    {
        try {
            if (isset($model->geo_blocking->blocked_countries)) {
                $countries = (string)$model->geo_blocking->blocked_countries;
                return !empty($countries) ? explode(',', $countries) : [];
            }
            return [];
        } catch (\Exception $e) {
            return [];
        }
    }
}