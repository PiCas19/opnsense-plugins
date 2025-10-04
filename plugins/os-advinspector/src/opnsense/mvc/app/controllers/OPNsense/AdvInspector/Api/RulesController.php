<?php

/*
 * Copyright (C) 2025 Pierpaolo Casati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\AdvInspector\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * API controller for managing inspection rules
 *
 * Provides CRUD operations for packet inspection rules following Zero Trust
 * security principles. Enforces strict validation on all rule modifications.
 *
 * @package OPNsense\AdvInspector\Api
 */
class RulesController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'settings';
    protected static $internalModelClass = '\OPNsense\AdvInspector\Settings';

    /**
     * Search for rules
     *
     * @return array Search results
     */
    public function searchRuleAction()
    {
        return $this->searchBase('rules.rule', [
            'enabled', 'description', 'source', 'destination', 'port', 'protocol', 'action', 'log'
        ]);
    }

    /**
     * Get a specific rule by UUID
     *
     * @param string|null $uuid Rule identifier
     * @return array Rule data
     */
    public function getRuleAction($uuid = null)
    {
        return $this->getBase('rule', 'rules.rule', $uuid);
    }

    /**
     * Add a new inspection rule
     *
     * Creates a new rule with validation. Returns validation errors if any.
     *
     * @return array Result with validation status
     */
    public function addRuleAction()
    {
        $mdl = $this->getModel();
        $payloadRoot = $this->request->getPost("advinspector") ?? [];
        $payload = $payloadRoot["rules"]["rule"] ?? [];

        $node = $mdl->rules->rule->Add();
        foreach ($payload as $key => $value) {
            if ($node->$key !== null) {
                $node->$key = $value;
            }
        }

        return $this->finalizeAndSave($mdl);
    }

    /**
     * Update an existing rule
     *
     * @param string $uuid Rule identifier
     * @return array Result with validation status
     */
    public function setRuleAction($uuid)
    {
        try {
            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;
            $node = null;
            foreach ($collection->iterateItems() as $index => $item) {
                if ((string)$item->getAttributes()["uuid"] === $uuid) {
                    $node = $item;
                    break;
                }
            }

            if ($node === null) {
                return ["result" => "error", "message" => "Rule not found."];
            }
            $payloadRoot = $this->request->getPost("advinspector") ?? [];
            $payload = $payloadRoot["rules"]["rule"] ?? [];

            foreach ($payload as $key => $value) {
                if ($node->$key !== null) {
                    $node->$key = $value;
                }
            }

            return $this->finalizeAndSave($mdl);
        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Delete a single rule
     *
     * @param string $uuid Rule identifier
     * @return array Result status
     */
    public function delRuleAction($uuid)
    {
        try {
            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;
            foreach ($collection->iterateItems() as $index => $node) {
                if ((string)$node->getAttributes()["uuid"] === $uuid) {
                    $collection->del($index);
                    return $this->finalizeAndSave($mdl, ["result" => "deleted"]);
                }
            }

            return ["result" => "error", "message" => "Rule not found."];
        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Toggle rule enabled/disabled state
     *
     * @param string $uuid Rule identifier
     * @return array Result status
     */
    public function toggleRuleAction($uuid)
    {
        try {
            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;

            foreach ($collection->iterateItems() as $index => $node) {
                if ((string)$node->getAttributes()["uuid"] === $uuid) {
                    $node->enabled = ($node->enabled == "1") ? "0" : "1";
                    return $this->finalizeAndSave($mdl, ["result" => "toggled"]);
                }
            }

            return ["result" => "error", "message" => "Rule not found."];
        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Delete multiple rules in bulk
     *
     * @return array Result status with count of deleted rules
     */
    public function delRuleBulkAction()
    {
        try {
            $uuids = $this->request->getPost("uuids");
            if (!is_array($uuids)) {
                return ["result" => "error", "message" => "Invalid input"];
            }

            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;
            $found = false;

            $indicesToDelete = [];
            foreach ($collection->iterateItems() as $index => $node) {
                $nodeUuid = (string)$node->getAttributes()["uuid"];
                if (in_array($nodeUuid, $uuids)) {
                    $indicesToDelete[] = $index;
                    $found = true;
                }
            }

            // Delete from highest index to lowest to maintain integrity
            rsort($indicesToDelete);
            foreach ($indicesToDelete as $index) {
                $collection->del($index);
            }

            if ($found) {
                return $this->finalizeAndSave($mdl, ["result" => "deleted"]);
            } else {
                return ["result" => "error", "message" => "No matching rules found"];
            }

        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Reconfigure the inspection service with current rules
     *
     * @return array Status response
     */
    public function reconfigureAction()
    {
        $response = (new Backend())->configdRun("advinspector export_rules");
        return ["status" => $response];
    }

    /**
     * Finalize changes and save configuration
     *
     * Validates rules, saves to config, and triggers rule export.
     *
     * @param object $mdl Model instance
     * @param array $result Initial result array
     * @return array Final result with validation status
     */
    private function finalizeAndSave($mdl, $result = ["result" => "saved"])
    {
        $valMsgs = $mdl->performValidation(true, 'rules');

        if ($valMsgs->count() > 0) {
            $result = ["result" => "failed", "validations" => []];
            foreach ($valMsgs as $msg) {
                $field = $msg->getField();
                $result["validations"]["advinspector." . $field] = $msg->getMessage();
            }
            return $result;
        }
        $mdl->serializeToConfig();
        Config::getInstance()->save();
        (new Backend())->configdRun("advinspector export_rules");

        return $result;
    }
}
