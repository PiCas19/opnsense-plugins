<?php

namespace OPNsense\MfaCustom;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        // Se l'autenticazione MFA non è pending, reindirizza alla dashboard
        if (empty($_SESSION['mfa_pending']) || $_SESSION['mfa_pending'] !== true) {
            $this->response->redirect('/ui/dashboard');
            return;
        }

        // Altrimenti mostra la pagina MFA
        $this->view->mfaForm = $this->getForm("mfa");
        $this->view->pick('OPNsense/MfaCustom/index');
    }
}
