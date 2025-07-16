<?php

namespace OPNsense\AdvInspector;

/**
 * Class RulesController
 * @package OPNsense\AdvInspector
 */
class RulesController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {

        $form =  $this->getForm("dialogRule");

        $fieldsOnly = array_filter($form, function($key) {
            return is_int($key);
        }, ARRAY_FILTER_USE_KEY);

        $this->view->formDialogRuleFields = $fieldsOnly;
        $this->view->dialogRuleID = $form["id"];
        $this->view->dialogRuleLabel = $form["description"];
        // assegna il form del dialog alla view
        $this->view->formDialogRule = $form;

        // carica la vista
        $this->view->pick('OPNsense/AdvInspector/rules');
    }
}