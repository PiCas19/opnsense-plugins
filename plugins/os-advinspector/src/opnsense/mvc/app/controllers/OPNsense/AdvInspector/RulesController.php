<?php

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