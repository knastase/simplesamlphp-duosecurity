<?php
/**
 * Duo Security script
 *
 * This script displays a page to the user for two factor authentication
 *
 * @package simpleSAMLphp
 */
/**
 * In a vanilla apache-php installation is the php variables set to:
 *
 * session.cache_limiter = nocache
 *
 * so this is just to make sure.
 */
session_cache_limiter('nocache');

$globalConfig = SimpleSAML_Configuration::getInstance();

SimpleSAML_Logger::info('Duo Security - getduo: Accessing Duo interface');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML_Error_BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];

// sanitize the input
$sid = SimpleSAML_Utilities::parseStateID($id);
if (!is_null($sid['url'])) {
	SimpleSAML_Utilities::checkURLAllowed($sid['url']);
}

$state = SimpleSAML_Auth_State::loadState($id, 'duosecurity:request');

if (array_key_exists('core:SP', $state)) {
    $spentityid = $state['core:SP'];
} else if (array_key_exists('saml:sp:State', $state)) {
    $spentityid = $state['saml:sp:State']['core:SP'];
} else {
    $spentityid = 'UNKNOWN';
}

// Duo returned a good auth, pass the user on
if(isset($_POST['sig_response'])){
	$state['duo_complete'] = True;	
        SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
}

// Bypass Duo if auth source is not specified in config file
/*
$bypassDuo = False;
$authSources = $state['duosecurity:authSources'];
$authId = $state['sspmod_core_Auth_UserPassBase.AuthId'];
foreach($authSources as $source) {
	if($authId == trim($source)) {
		$bypassDuo = True;
	}
}
if($bypassDuo == True) {
	SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
}
*/

// Prepare attributes for presentation
$attributes = $state['Attributes'];
$para = array(
    'attributes' => &$attributes
);

// Make, populate and layout Duo form
$t = new SimpleSAML_XHTML_Template($globalConfig, 'duosecurity:duoform.php');
$t->data['akey'] = $state['duosecurity:akey'];
$t->data['ikey'] = $state['duosecurity:ikey'];
$t->data['skey'] = $state['duosecurity:skey'];
$t->data['host'] = $state['duosecurity:host'];
$t->data['srcMetadata'] = $state['Source'];
$t->data['dstMetadata'] = $state['Destination'];
$t->data['yesTarget'] = SimpleSAML_Module::getModuleURL('duosecurity/getduo.php');
$t->data['yesData'] = array('StateId' => $id);
$t->data['attributes'] = $attributes;

$t->show();
