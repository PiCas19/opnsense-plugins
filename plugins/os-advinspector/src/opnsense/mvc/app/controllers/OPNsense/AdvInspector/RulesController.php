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
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

namespace OPNsense\AdvInspector;

/**
 * Rules controller for Advanced Packet Inspector
 *
 * Manages the inspection rules interface following Zero Trust security principles.
 * Provides the UI for creating, editing, and managing packet inspection rules.
 *
 * @package OPNsense\AdvInspector
 */
class RulesController extends \OPNsense\Base\IndexController
{
    /**
     * Display the rules management page
     *
     * Loads the rule dialog form and prepares the view for rule management.
     * Separates field data from metadata for proper form rendering.
     *
     * @return void
     */
    public function indexAction()
    {
        $form = $this->getForm("dialogRule");

        // Extract only numeric keys (field definitions)
        $fieldsOnly = array_filter($form, function($key) {
            return is_int($key);
        }, ARRAY_FILTER_USE_KEY);

        $this->view->formDialogRuleFields = $fieldsOnly;
        $this->view->dialogRuleID = $form["id"];
        $this->view->dialogRuleLabel = $form["description"];
        $this->view->formDialogRule = $form;

        $this->view->pick('OPNsense/AdvInspector/rules');
    }
}