simplesamlphp-duosecurity
=========================

Two factor authentication module using Duo Security for SimpleSAMLphp

Usage:
Set up a Web SDK integration on your Duo admin website.
see https://www.duosecurity.com/docs/duoweb for more information

In config/config.php, activate the Duo Security module by adding it to the
authentication filters section. (under 'authproc.idp')

            80 => array(
            'class' => 'duosecurity:Duosecurity',
            
            'akey' => 'SECRET KEY UNIQUE TO YOUR APP MUST BE 40 CHARACTERS',
            
            // The following values can be found on your Duo admin page
            
            'ikey' => '',
            
            'skey' => '',
            
            'host' => '',
        ),

Do not change the names of any files in the module
