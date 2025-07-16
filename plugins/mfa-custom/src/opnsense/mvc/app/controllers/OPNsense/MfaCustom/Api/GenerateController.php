<?php

namespace OPNsense\MfaCustom\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\MfaCustom\Settings;
use Base32\Base32;

class GenerateController extends ApiControllerBase
{
    public function indexAction()
    {
        if (!isset($_SESSION['Username'])) {
            return ['status' => 'error', 'message' => 'User not authenticated'];
        }

        $username = $_SESSION['Username'];

        $model = new Settings();
        $userSecrets = [];

        if (!empty((string)$model->secrets)) {
            $userSecrets = json_decode((string)$model->secrets, true) ?: [];
        }

        if (!isset($userSecrets[$username])) {
            $secret = Base32::encodeUpper(random_bytes(10));
            $userSecrets[$username] = $secret;
            $model->secrets = json_encode($userSecrets);
            $model->serializeToConfig();
            Config::getInstance()->save();
        } else {
            $secret = $userSecrets[$username];
        }

        $issuer = 'OPNsense';
        $otpauth = "otpauth://totp/{$issuer}:{$username}?secret={$secret}&issuer={$issuer}";

        return [
            'status' => 'ok',
            'username' => $username,
            'secret' => $secret,
            'otpauth_url' => $otpauth
        ];
    }
}
