<?php

namespace OPNsense\MfaCustom\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\MfaCustom\Settings;

class ResetController extends ApiControllerBase
{
    public function indexAction()
    {
        if (!isset($_SESSION['Username'])) {
            return ['status' => 'error', 'message' => 'User not authenticated'];
        }

        $username = $_SESSION['Username'];

        $model = new Settings();
        $secrets = [];

        if (!empty((string)$model->secrets)) {
            $secrets = json_decode((string)$model->secrets, true) ?: [];
        }

        if (isset($secrets[$username])) {
            unset($secrets[$username]);
            $model->secrets = json_encode($secrets);
            $model->serializeToConfig();
            Config::getInstance()->save();
            return ['status' => 'ok', 'message' => 'Secret reset successfully'];
        } else {
            return ['status' => 'info', 'message' => 'No secret to reset'];
        }
    }
}
