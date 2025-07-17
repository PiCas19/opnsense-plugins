<?php
/*
 * Copyright (C) 2025 OPNsense Project
 * All rights reserved.
 */
namespace OPNsense\DeepInspector;
use OPNsense\Base\IndexController as BaseIndexController;

/**
 * Class IndexController
 * @package OPNsense\DeepInspector
 */
class IndexController extends BaseIndexController
{
    /**
     * Deep Packet Inspector index page
     * @throws \Exception
     */
    public function indexAction()
    {
        try {
            $this->view->title = gettext('Deep Packet Inspector');
            
            // Carica i form con i nomi corretti che si aspetta il template
            $this->view->formGeneral = $this->getForm("general");
            $this->view->formProtocols = $this->getForm("protocols");
            $this->view->formDetection = $this->getForm("detection");
            $this->view->formAdvanced = $this->getForm("advanced");
            
            // Debug per verificare il caricamento
            error_log("=== DEEPINSPECTOR FORM LOADING ===");
            error_log("formGeneral loaded: " . (empty($this->view->formGeneral) ? 'NO' : 'YES (' . count($this->view->formGeneral) . ' fields)'));
            error_log("formProtocols loaded: " . (empty($this->view->formProtocols) ? 'NO' : 'YES (' . count($this->view->formProtocols) . ' fields)'));
            error_log("formDetection loaded: " . (empty($this->view->formDetection) ? 'NO' : 'YES (' . count($this->view->formDetection) . ' fields)'));
            error_log("formAdvanced loaded: " . (empty($this->view->formAdvanced) ? 'NO' : 'YES (' . count($this->view->formAdvanced) . ' fields)'));
            
            // Se qualche form è vuoto, prova a ricaricare
            if (empty($this->view->formGeneral) || empty($this->view->formProtocols) || 
                empty($this->view->formDetection) || empty($this->view->formAdvanced)) {
                
                error_log("Some forms are empty, trying to reload...");
                
                // Verifica se il modello esiste e può essere caricato
                try {
                    $model = $this->getModel();
                    if ($model) {
                        error_log("Model loaded successfully");
                        
                        // Riprova a caricare i form
                        $this->view->formGeneral = $this->getForm("general");
                        $this->view->formProtocols = $this->getForm("protocols");
                        $this->view->formDetection = $this->getForm("detection");
                        $this->view->formAdvanced = $this->getForm("advanced");
                        
                        error_log("After reload:");
                        error_log("- formGeneral: " . count($this->view->formGeneral) . " fields");
                        error_log("- formProtocols: " . count($this->view->formProtocols) . " fields");
                        error_log("- formDetection: " . count($this->view->formDetection) . " fields");
                        error_log("- formAdvanced: " . count($this->view->formAdvanced) . " fields");
                    } else {
                        error_log("Model could not be loaded");
                    }
                } catch (\Exception $e) {
                    error_log("Error loading model: " . $e->getMessage());
                }
            }
            
            $this->view->pick('OPNsense/DeepInspector/index');
            
        } catch (\Exception $e) {
            error_log("IndexController error: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            throw $e;
        }
    }
}