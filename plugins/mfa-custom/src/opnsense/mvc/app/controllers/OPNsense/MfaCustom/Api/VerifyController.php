<?php

namespace OPNsense\MfaCustom\Api;

use OPNsense\Base\ApiControllerBase;

class VerifyController extends ApiControllerBase
{
    public function indexAction()
    {
        $request = $this->request->getPost();
        $username = $_SESSION['mfa_username'] ?? null;
        $otp = $request['otp'] ?? null;

        if (empty($username) || empty($otp)) {
            return ['status' => 'error', 'message' => 'Missing parameters'];
        }

        $cmd = escapeshellcmd("/usr/local/opnsense/scripts/OPNsense/MfaCustom/verify_otp.py");
        $output = [];
        $exitCode = 0;
        exec("$cmd " . escapeshellarg($username) . " " . escapeshellarg($otp), $output, $exitCode);

        if ($exitCode === 0 && trim($output[0]) == 'OK') {
            $_SESSION['mfa_pending'] = false;
            return ['status' => 'success'];
            return $this->redirect('/ui/dashboard'); 
        } else {
            return ['status' => 'error', 'message' => 'Invalid OTP'];
        }
    }
}
