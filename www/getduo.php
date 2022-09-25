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

$globalConfig = SimpleSAML\Configuration::getInstance();

SimpleSAML\Logger::info('Duo Security - getduo: Accessing Duo interface');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML\Error\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];

// sanitize the input
$sid = SimpleSAML\Utilities::parseStateID($id);
if (!is_null($sid['url'])) {
	SimpleSAML\Utilities::checkURLAllowed($sid['url']);
}

$state = SimpleSAML\Auth\State::loadState($id, 'duosecurity:request');

if (array_key_exists('core:SP', $state)) {
    $spentityid = $state['core:SP'];
} else if (array_key_exists('saml:sp:State', $state)) {
    $spentityid = $state['saml:sp:State']['core:SP'];
} else {
    $spentityid = 'UNKNOWN';
}

// Duo returned a good auth, pass the user on
if(isset($_POST['sig_response'])){
    require(SimpleSAML\Module::getModuleDir('duosecurity') . '/templates/duo_web.php');
    $resp = Duo::verifyResponse(
        $state['duosecurity:ikey'],
        $state['duosecurity:skey'],
        $state['duosecurity:akey'],
        $_POST['sig_response']
    );

    if (isset($state['Attributes'][$state['duosecurity:usernameAttribute']])) {
        $username = $state['Attributes'][$state['duosecurity:usernameAttribute']][0];
    }
    else {
        throw new SimpleSAML\Error\BadRequest('Missing required username attribute.');
    }

    if ($resp != NULL and $resp === $username) {
        $state['duo_complete'] = True;
        SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
    }
    else {
        throw new SimpleSAML\Error\BadRequest('Response verification failed.');
    }
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
$t = new SimpleSAML\XHTML\Template($globalConfig, 'duosecurity:duoform.php');
$t->data['akey'] = $state['duosecurity:akey'];
$t->data['ikey'] = $state['duosecurity:ikey'];
$t->data['skey'] = $state['duosecurity:skey'];
$t->data['host'] = $state['duosecurity:host'];
$t->data['usernameAttribute'] = $state['duosecurity:usernameAttribute'];
$t->data['srcMetadata'] = $state['Source'];
$t->data['dstMetadata'] = $state['Destination'];
$t->data['yesTarget'] = SimpleSAML\Module::getModuleURL('duosecurity/getduo.php');
$t->data['yesData'] = array('StateId' => $id);
$t->data['attributes'] = $attributes;

$t->show();
