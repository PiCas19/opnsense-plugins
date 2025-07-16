<?php

namespace OPNsense\AdvInspector;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class Settings extends BaseModel
{
    /**
     * Validazione con scope: general, rules, all
     */
    public function performValidation($validateFullModel = false, $scope = 'all')
    {
        $messages = parent::performValidation($validateFullModel);

        // === VALIDAZIONE SETTINGS ===
        if ($scope === 'all' || $scope === 'general') {
            if (
                ($validateFullModel || $this->general->enabled->isFieldChanged() || $this->general->interfaces->isFieldChanged()) &&
                (string)$this->general->enabled === "1"
            ) {
                if (empty((string)$this->general->interfaces)) {
                    $messages->appendMessage(new Message(
                        gettext('At least one interface must be selected when Advanced Packet Inspector is enabled.'),
                        'general.' . $this->general->interfaces->getInternalXMLTagName()
                    ));
                }
            }

            if ($validateFullModel || $this->general->homenet->isFieldChanged()) {
                $homenet = (string)$this->general->homenet;
                if (!empty($homenet)) {
                    $networks = explode(',', $homenet);
                    foreach ($networks as $network) {
                        $network = trim($network);
                        if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $network)) {
                            $messages->appendMessage(new Message(
                                sprintf(gettext('Invalid network format: %s'), $network),
                                'general.' . $this->general->homenet->getInternalXMLTagName()
                            ));
                        }
                    }
                }
            }
        }

        // === VALIDAZIONE RULES ===
        if ($scope === 'all' || $scope === 'rules') {
            foreach ($this->rules->rule->iterateItems() as $rule) {
                $uuid = $rule->getAttributes()["uuid"] ?? uniqid();

                if (empty((string)$rule->description) || strlen((string)$rule->description) > 255) {
                    $messages->appendMessage(new Message(
                        gettext("Description must be between 1 and 255 characters"),
                        "rules.rule.{$uuid}.description"
                    ));
                }

                // ✅ SOLO CIDR FORMATO VALIDO — IP singoli vietati
                if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', (string)$rule->source)) {
                    $messages->appendMessage(new Message(
                        gettext("Source must be in CIDR format (e.g. 192.168.1.0/24)"),
                        "rules.rule.{$uuid}.source"
                    ));
                }

                if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', (string)$rule->destination)) {
                    $messages->appendMessage(new Message(
                        gettext("Destination must be in CIDR format (e.g. 192.168.1.0/24)"),
                        "rules.rule.{$uuid}.destination"
                    ));
                }

                if (!empty((string)$rule->port) && !preg_match('/^[0-9,-]*$/', (string)$rule->port)) {
                    $messages->appendMessage(new Message(
                        gettext("Port must contain only numbers, commas or dashes"),
                        "rules.rule.{$uuid}.port"
                    ));
                }

                $validProtocols = [
                    "tcp", "udp", "icmp", "modbus_tcp", "dnp3", "iec104", "iec61850",
                    "profinet", "ethercat", "opcua", "mqtt", "bacnet", "s7comm"
                ];
                if (!in_array((string)$rule->protocol, $validProtocols)) {
                    $messages->appendMessage(new Message(
                        gettext("Invalid protocol selected"),
                        "rules.rule.{$uuid}.protocol"
                    ));
                }

                $validActions = ["allow", "block", "alert"];
                if (!in_array((string)$rule->action, $validActions)) {
                    $messages->appendMessage(new Message(
                        gettext("Invalid action selected"),
                        "rules.rule.{$uuid}.action"
                    ));
                }

                if (!in_array((string)$rule->log, ["0", "1"])) {
                    $messages->appendMessage(new Message(
                        gettext("Invalid value for log; must be 0 or 1"),
                        "rules.rule.{$uuid}.log"
                    ));
                }

                if (!in_array((string)$rule->enabled, ["0", "1"])) {
                    $messages->appendMessage(new Message(
                        gettext("Invalid value for enabled; must be 0 or 1"),
                        "rules.rule.{$uuid}.enabled"
                    ));
                }
            }
        }

        return $messages;
    }
}