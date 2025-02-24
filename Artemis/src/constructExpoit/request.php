<?php

require 'vendor/autoload.php';

use WpOrg\Requests\Session;

require 'config.php';
global $baseUrl, $user, $password, $logPath;
// Login Setup Code
/** @var Session $session */
$session = require 'setup.php';
// End Login Setup Code

if (!file_exists('spec.json')) {
    echo "File spec.json not found\n";
    exit(1);
}

$spec = json_decode(file_get_contents('spec.json'), true);
if ($spec === null) {
    echo "Invalid JSON in spec.json. Please fix your previous JSON response.\n";
    exit(1);
}

$method = $spec['Method'];
$path = $spec['Path'];
// Remove first / if exists
$path = ltrim($path, '/');
$data = $spec['Data'];
// If data is escaped json string, decode it
if (is_string($data)) {
    $data = json_decode($data, true);
    if ($data === null) {
        echo "Invalid JSON in Data\n";
        exit(1);
    }
}

if (array_key_exists('Header', $spec) && !empty($spec['Header'])) {
    $headers = $spec['Header'];
    if (!is_array($headers)) {
        echo "Invalid Header\n";
        exit(1);
    }
}
else {
    $headers = [];
}


//var_dump(http_build_query($data));

$log_prev = file($logPath);
try {
    switch (strtoupper($method)) {
        case 'GET':
            // For each field in data, if it is "key": "val", turn it into a query parameter
            foreach ($data as $key => $val) {
                if (is_string($key) && is_string($val)) {
                    $path .= (strpos($path, '?') === false ? '?' : '&') . urlencode($key) . '=' . urlencode($val);
                }
            }
            $response = $session->get($path, $headers);
            break;
        case 'POST':
            if (array_key_exists('_wpnonce', $data)) {
                $path .= (strpos($path, '?') === false ? '?' : '&') . '_wpnonce=' . $data['_wpnonce'];
            }
            // If data is JSON
            if (array_key_exists('Content-Type', $headers) && $headers['Content-Type'] === 'application/json') {
                $data = json_encode($data);
            }
            $response = $session->post($path, $headers, $data);
            break;
        case 'PUT':
            $response = $session->put($path, $headers, $data);
            break;
        case 'DELETE':
            $response = $session->delete($path, $headers);
            break;
        default:
            echo "Invalid method $method\n";
            exit(1);
    }
}
catch (\WpOrg\Requests\Exception $e) {
    echo "Request Exception: " . $e->getMessage() . "\n";
    $response = new WpOrg\Requests\Response();
}

$triggered = false;
if (strpos($response->body, "Secret!!!") !== false) {
    $triggered = true;
}
$log_after = file($logPath);
// Check difference
if ($log_prev === false) {
    $log_prev = [];
}

if ($log_after === false) {
    $log_after = [];
}

$diff = array_diff($log_after, $log_prev);
if (count($diff) > 0) {
    $triggered = true;
}

if ($triggered) {
    echo "Triggered\n";
} else {
    echo "Request URL: " . $response->url . "\n";
    echo "Status code: " . $response->status_code . "\n";
    if ($response->status_code !== 404) {
        // echo "Response: " . $response->body . "\n";
        if (empty($response->body)) {
            echo "Empty response\n";
            return;
        }
        try {
            $response->decode_body();
            // Truncate long responses
            if (strlen($response->body) > 1000) {
                echo "Response: " . substr($response->body, 0, 1000) . "...\n";
            } else {
                echo "Response: " . $response->body . "\n";
            }
            return;
        } catch (\WpOrg\Requests\Exception $e) {
        }
        // Try parse response as html
        try {
            $doc = new DiDom\Document($response->body);
            $title = $doc->first('title');
            if ($title) {
                if ($title instanceof DiDom\Element) {
                    echo "Title: " . $title->text() . "\n";
                } else {
                    echo "Title: " . $title . "\n";
                }
                $body = $doc->first('body');
                if ($body) {


                // Extract hx tags
                for ($i = 1; $i <= 6; $i++) {
                    $hx = $doc->first('h' . $i);
                    if ($hx) {
                        echo "H$i: " . $hx->text() . "\n";
                    }
                }
                }
            }
            else {
                if (strlen($response->body) > 1000) {
                    echo "Response: " . substr($response->body, 0, 1000) . "...\n";
                } else {
                    echo "Response: " . $response->body . "\n";
                }
            }
        } catch (\Exception $e) {
            if (strlen($response->body) > 1000) {
                echo "Response: " . substr($response->body, 0, 1000) . "...\n";
            } else {
                echo "Response: " . $response->body . "\n";
            }
        }
    }
}



