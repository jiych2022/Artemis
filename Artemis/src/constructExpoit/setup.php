<?php
require 'config.php';
require 'vendor/autoload.php';

use DiDom\Document;
use WpOrg\Requests\Cookie\Jar;
use WpOrg\Requests\Hooks;
use WpOrg\Requests\Requests;
use WpOrg\Requests\Response;
use WpOrg\Requests\Session;

if (!function_exists('browser_redirect_compatibility')) {
    /**
     * @param string $location
     * @param array $req_headers
     * @param array $req_data
     * @param array $options
     * @param Response $return
     * @return void
     */
    function browser_redirect_compatibility(&$location, &$req_headers, &$req_data, &$options, $return)
    {
        // Browser compat
        if ($return->status_code === 302) {
            $options['type'] = Requests::GET;
        }
    }
}

if (!function_exists('handle_refresh')) {
    function handle_refresh(Response &$return, array $req_headers, array $req_data, array $options)
    {
        if ($refresh = $return->headers['refresh']) {
            // Check whether URL is present
            if (preg_match('/url=([^\s]+)/', $refresh, $matches)) {
                $url = $matches[1];
                $return->headers['location'] = $url;
                $return->status_code = 302;
            }
        }
    }
}
global $baseUrl, $user, $password, $logPath;
$hooks = new Hooks();
$hooks->register('requests.before_redirect', 'browser_redirect_compatibility');
//$hooks->register( 'requests.before_redirect_check', 'handle_refresh' );

// Login Setup Code
$jar = new Jar(
);
$session = new Session($baseUrl, [], [], ['hooks' => $hooks, 'verify' => false, 'cookies' => $jar]);

/*$hooks->register('requests.before_request', function (&$url, &$headers, &$data, &$type, &$options) use ($token) {
    $data['_token'] = $token;
});*/

return $session;