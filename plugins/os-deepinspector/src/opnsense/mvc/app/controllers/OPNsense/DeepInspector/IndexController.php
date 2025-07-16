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
            
            // Debug completo: verifica file form
            $basePath = '/usr/local/opnsense/mvc/app/models/OPNsense/DeepInspector/';
            $formsPath = '/usr/local/opnsense/mvc/app/forms/OPNsense/DeepInspector/';
            
            error_log("=== DEBUG DEEPINSPECTOR ===");
            error_log("Base path: " . $basePath);
            error_log("Forms path: " . $formsPath);
            
            // Verifica se la directory dei form esiste
            if (!is_dir($formsPath)) {
                error_log("ERRORE: Directory dei form non esiste: " . $formsPath);
                mkdir($formsPath, 0755, true);
                error_log("Directory creata: " . $formsPath);
            }
            
            // Verifica file modello
            $modelFile = $basePath . 'DeepInspector.xml';
            error_log("Verificando modello: " . $modelFile);
            if (file_exists($modelFile)) {
                error_log("✓ File modello trovato");
            } else {
                error_log("✗ File modello NON trovato: " . $modelFile);
            }
            
            // Lista tutti i file nella directory forms
            if (is_dir($formsPath)) {
                $files = scandir($formsPath);
                error_log("File nella directory forms: " . implode(', ', $files));
            }
            
            // Prova a caricare ogni form singolarmente
            $forms = ['general', 'protocols', 'detection', 'advanced'];
            $loadedForms = [];
            
            foreach ($forms as $formName) {
                try {
                    error_log("Tentando di caricare form: " . $formName);
                    $form = $this->getForm($formName);
                    if ($form) {
                        $loadedForms[$formName] = $form;
                        error_log("✓ Form caricato con successo: " . $formName);
                        error_log("Campi nel form: " . count($form));
                    } else {
                        error_log("✗ Form vuoto o nullo: " . $formName);
                        // Crea un form vuoto per evitare errori
                        $loadedForms[$formName] = [];
                    }
                } catch (\Exception $e) {
                    error_log("✗ Errore caricamento form " . $formName . ": " . $e->getMessage());
                    $loadedForms[$formName] = [];
                }
            }
            
            // Assegna i form alle view
            $this->view->generalForm = $loadedForms['general'];
            $this->view->protocolsForm = $loadedForms['protocols'];
            $this->view->detectionForm = $loadedForms['detection'];
            $this->view->advancedForm = $loadedForms['advanced'];
            
            // Debug finale
            error_log("Form assegnati alla view:");
            error_log("- generalForm: " . (empty($this->view->generalForm) ? 'VUOTO' : 'OK (' . count($this->view->generalForm) . ' campi)'));
            error_log("- protocolsForm: " . (empty($this->view->protocolsForm) ? 'VUOTO' : 'OK (' . count($this->view->protocolsForm) . ' campi)'));
            error_log("- detectionForm: " . (empty($this->view->detectionForm) ? 'VUOTO' : 'OK (' . count($this->view->detectionForm) . ' campi)'));
            error_log("- advancedForm: " . (empty($this->view->advancedForm) ? 'VUOTO' : 'OK (' . count($this->view->advancedForm) . ' campi)'));
            
            $this->view->pick('OPNsense/DeepInspector/index');
            
        } catch (\Exception $e) {
            error_log("✗ ERRORE GRAVE IndexController: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            throw $e;
        }
    }
}