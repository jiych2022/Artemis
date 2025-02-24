<?php

use Construct\ChatGPT;

require 'vendor/autoload.php';
require 'tools.php';
require 'parseInput.php';
require 'config.php';
global $user, $password, $repoBase;
const REQUEST = true;

if (file_exists("api_key.txt")) {
    $apiKey = file_get_contents("api_key.txt");
} else {
    $apiKey = getenv("OPENAI_API_KEY");
}
if (!$apiKey) {
    echo "API key not found. ";
    exit(1);
}

if (file_exists('log.txt')) {
    // Move to log.txt.bak
    rename('log.txt', 'log.txt.bak');
}

$chatgpt = new ChatGPT($apiKey);

$chatgpt->set_params([
    'temperature' => 1.0,
    'max_tokens' => 1024,
    'frequency_penalty' => 0,
    'presence_penalty' => 0
]);
$chatgpt->savefunction('saveFunction');
$chatgpt->add_function('getFileOrDir');
$chatgpt->add_function('searchKeywords');
$chatgpt->add_function('getPhpFileSummary');
$chatgpt->add_function('getMethodFromFile');
$chatgpt->add_function('executePhpCode');

$systemPrompt = <<<PROMPT
You are an expert on PHP web security. 
You will be given PHP code snippets. 
Your task is to analyze the potential server-side request forgery (SSRF) vulnerability in the code snippet. 
When there is an SSRF, construct a potential exploit input. 
After that, retrieve relevant information with appropriate tool to figure out the API (route) and the parameter values in the actual request to trigger SSRF.
If the code indicate the use of a well-known framework, such as WordPress or Laravel, make full use of your domain knowledge about them in your analysis.

Only consider standard PHP behavior where file-related functions such as `file_get_contents` or `file` can send requests when reading an HTTP URL, but other operations, like `stat` or writing only works for local files, i.e, `file://` protocol.

In our definition, SSRF happens when 1) input can change the request destination so that attacker can induce the server-side application to make HTTP requests to an internal resource not accessible by attacker or 2) the input uses `file://` protocol and can read arbitrary file or directory such as `/etc/passwd` or `/secret-dir`. 

In the system, the current user credential is username/email: $user, password: $password.
The base address for the code base is $repoBase.

Think step by step and provide concise results. Do not provide advice.
PROMPT;
$chatgpt->smessage($systemPrompt);

$userPrompt = <<<PROMPT
Here's the code snippets of functions (and their position in files) containing a path from source (user input) to sink (a function that may send a request or read files). 
Statements involved in the taint path are marked with comment `// Tainted` above the line. 
Pay attention to conditions required to reach statements that may trigger SSRF. 
Analyze the code, especially the taint path and construct the input that may trigger SSRF. 
Note that user input can be from various sources, such as GET/POST parameters, cookies, or other headers such as HTTP Host. 
If there are prefix before the input, try figure out its value to construct proper input. 
Do not assume the value of prefixes can always lead to SSRF. 
i.e., in cases of `\$prefix. \$input`, you need to figure out the value of `\$prefix` with the provided tools to determine whether SSRF is indeed possible and if it is possible, construct the input.
If exploit is not possible, respond with `Not possible` and reasons. 

You can assume sink (request-sending) functions do not have SSRF protection. 
When constructing input, consider input as HTTP URL first. 
For HTTP URLs, as long as the request can be sent, it is considered exploitable. Any check after the request is sent can be ignored.
Only construct file input when http input is not possible. 
For example, `file_get_contents` accepts both HTTP URL and file path, in this case, construct HTTP URL as input.

In your payload, assume the internal service is located at `http(s)://127.0.0.1:8888` and the file to read is `/secret.txt`. 
If you need a domain which resolves to `127.0.0.1:8888`, use `http(s)://127.0.0.1.traefik.me:8888`.
In your generated payload, if the input is a full URL, be sure to always include schema (http(s):// or file://) in it. 
Note that when the input is not a full URL, but part of the domain in a URL, you can use a delimiter like `/` to make the string resolves to input.
For example, suppose the URL is `http://[input].existing.tld/...`, if you use `127.0.0.1` as input, the domain still points to `existing.tld`. 
But if you use `127.0.0.1:8888/`. Now the URL becomes `http(s)://127.0.0.1:8888/.existing.tld/...`. and will resolve to our target service instead of `existing.tld` because `existing.tld` is not part of domain anymore.
Be aware that certain applications require the input to be https only.
 
Try construct a minimal input where only necessary fields are populated.  
Focus on constructing input and do not infer the route/API in this step. 
If you need to perform calculation such as base64, or if the input is not a full HTTP URL, generate PHP code and execute it with the `executePhpCode` function to get the calculation result and check the result of `parse_url` to see whether the input can make the host part in the URL points to `127.0.0.1`.
When both `http(s)://` and `file://` are possible, always generate `http(s)://` only. `file://` is only used when `http://` is not possible.

In your result, first briefly state the vulnerability path and how it is triggered. 
Specifically, analyze how the SSRF is triggered by a sink function marked by the `// Tainted` comment. In your analysis, present the involved sink function and make sure it is marked by a `// Tainted` comment.   
Then provide the constructed input.
Do not assume the value of prefixes can always lead to SSRF. 
When a prefix is present, figure out the potential values of the prefix with the provided tools and the reason why it can or cannot lead to SSRF.
Note that in this case only consider HTTP requests. 
Unless explicitly tainted, prefixes are always not controllable by user input, but they are not always safe.
For example, suppose prefix is `http://example.com`, even though the host part seems to be fixed, by using `.127.0.0.1.traefik.me:8888` (i.e, use a dot before user input to make existing prefix a subdomain) as input, the fixed host becomes a subdomain and results in `http://example.com.127.0.0.1.traefik.me:8888` which resolves to `127.0.0.1:8888`.
However, if the prefix is `http://example.com/`, SSRF is not possible because now the input belongs to path segment.
You must use `parse_url` function to see whether the user input still belongs to host part in the URL to verify your conclusions.
Before code verification, make sure you have figured out any values that can be statically figured out.
```
%s
```
PROMPT;
if ($argc > 1) {
    $input = file_get_contents($argv[1]);
} else {
    global $taintResult;
    $input = $taintResult;
}
$lines = extractFileAndLineInfo($input);

// Merge lines in the same file
$fileLineMap = [];
foreach ($lines as $line) {
    $file = $line[0];
    if (strpos($file, 'wp-includes') !== false || strpos($file, 'wp-admin') !== false) {
        continue;
    }
    $lineNumber = $line[1];
    if (!array_key_exists($file, $fileLineMap)) {
        $fileLineMap[$file] = [];
    }
    $fileLineMap[$file][] = $lineNumber;
}
$code = '';
$taintedFunctions = [];
$taintedLines = [];
foreach ($fileLineMap as $file => $lineNumbers) {
    $codeData = getCodeData($file, $lineNumbers);
    $modifiedCode = $codeData['modifiedCode'];
    $code .= "// $file\n";
    $code .= $modifiedCode;
    $code .= "\n";
    $taintedFunctions = array_merge($taintedFunctions, $codeData['taintedNames']);
    $taintedLines = array_merge($taintedLines, $codeData['taintedCallLines']);
}
if (false) {
    echo $code;
    print_r($taintedFunctions);
    print_r($taintedLines);
    exit(0);
}
$chatgpt->umessage(sprintf($userPrompt, $code));

$response = $chatgpt->response_with_retry()->content . PHP_EOL;
//echo "SSRF response:";
//echo $response;
//echo "===============================================================" . PHP_EOL;

$userPrompt = <<<PROMPT
Now try to infer the API (route) to trigger this SSRF. This route would trigger the previously provided code.
Here the route is the part after the base address (e.g., `/api/to/route` in `http://example.com/base/api/to/route`).
You can always assume the existence of topmost index.php unless it is a WordPress site. (e.g. `http://example.com/index.php`).
Use appropriate tools to get information that you need.

To identify the route, use the following process:
1. If the vulnerable code is not in a function/method, it may be in a standalone script, and the file can be executed directly, the route is the path to the file from the base address.
For WordPress plugins, they are installed under wp-content/plugins/[name]/ directory.
To confirm this, check whether there are checks such as defined constants or use of global variables without inclusion.
If there are, the script is not standalone and must be included in another script.
In this case, the route may be the parent script that includes the given script, which can be found by searching for the script name.
If not reference is found, more complex routing logic may be involved, and you need to analyze the code as specified in step 4.

2. If the code is not standalone, try to find out whether the application is using known frameworks/libraries or a well-known application. 
   2.1 When `composer.json` is present, you can use the `getFileOrDir` tool to retrieve and analyze the third-party dependencies.
   2.2 When `composer.json` is not present or does not reveal the framework, the framework may be directly included in the codebase.
       Therefore, in this case you need to use the `getFileOrDir` tool to get the root directory listing, then analyze the folder names and look for known framework names.
   If known frameworks/libraries are used, including but not limited to WordPress, Laravel, ezcomponents, make use of your domain knowledge about them when locating the route and parameters.
    
3. Because functions that are tainted may not be the entry point function called by the route, you need to find out potential callers, then find the routes.
   Note that the caller may use certain request parameters to determine which class to use. Be sure to check the caller's code to understand how the route is determined.

4. If the application is not using a known framework, or it uses a known framework as well as additional routing logic,
 4.1 First check the codebase to find out the route. 
     Specifically, look for routing related code to understand how requests are routed to controller code.
     Note that in some cases the route may be enhanced by .htaccess or nginx configuration.
     Note that you may also find the route from client-side code, such as JavaScript code that sends the request.
     When performing your search, you may need to make adjustments. For example, `file1.php` may be come `file1` in routes.
 4.2 If you cannot identify the exact route from code, you can use the `getPageLinks` tool to get the links from a specific page for hints. You can start with `index.php`.

For WordPress ajax routes, if it is a POST request, the action should also be specified in POST body.
Note that WordPress also supports registering REST api, which are under `/wp-json` path. Be aware of the namespace and versions of the rest routes.
Another possibility in WordPress is that the tainted function is called in a specified page, in this case, the route is the page URL defined by `add_menu_page`.
What you need to do is to analyze the code that is called by the page to determine the route.

After you have determined the route, briefly analyze how it reaches the previously vulnerable code and double check your result.

First present your plan, then execute it accordingly.

Do not guess the route.
PROMPT;
$chatgpt->force_tool_choice("auto");
$chatgpt->add_function('getPageLinks');
$chatgpt->umessage($userPrompt);
$response = $chatgpt->response_with_retry()->content . PHP_EOL;
/*echo "Route response:";
echo $response;
echo "===============================================================" . PHP_EOL;*/

$userPrompt = <<<PROMPT
Now check the generated request, aside from the URL-related field, try to obtain a valid value for the other fields if they are required for the request to be sent.
Be sure to analyze additional constraints along the route path.
Additionally, certain headers may also be required. For example, if the request is an ajax request, the `X-Requested-With` header may be required. Another example is when request body is JSON, the `Content-Type` header should be set to `application/json`.
Note that constraints after the request is sent can be safely ignored. 
For example, consider the following code:
```php
\$url = \$_GET['url'];
\$b = \$_GET['b'];
\$token = \$_GET['token'];
if (empty(\$b)) {
  return;
}
file_get_contents(\$url);
```
In this case, the `b` parameter is required to be non-empty for the request to be sent, so you need to fill some value for `b` in your request.
On the other hand, the `token` parameter is not used in the code, so you can ignore it.

Determine the values using the following process:
1. Identify the input fields that are required for the request to be sent (if any). If the field is related to the current session such as CSRF token, ignore it and assume a valid value will be provided. Exception is WordPress nonce.
2. Check whether the identified field requires a value that is limited by code only or the value is a value from database
3. If the field is limited by code only, use code-related tools to find out the constraints and infer a valid value. Specifically, first try to look for how the route is called from client side (like from JavaScript) to infer its usage. If this is not enough, explore the PHP codebase to find out the constraints.
4. If the field is related to config value, try search for the key to find out their values.
5. If the field is a value from database, use database-related tools to figure out the table that the required value belongs to, then figure out the conditions of the valid value, finally generate SQL statement to get a valid value.
6. If the field is a nonce in WordPress, identify the related action and call the `calculate_custom_nonce` function to generate a valid nonce. Note that REST requests in WordPress requires nonce calculated with action `wp_rest` and is added to the `_wpnonce` query parameter.

For each field, generate a concise plan. Then execute the plan accordingly.

If all fields already have a valid value (after ignoring token/session related fields except for WordPress nonce), return `Completed`.
PROMPT;

$chatgpt->add_function('getTableNames');
$chatgpt->add_function('getTableSchema');
$chatgpt->add_function('executeSql');
$chatgpt->add_function('calculate_custom_nonce');
$chatgpt->umessage($userPrompt);
$response = $chatgpt->response_with_retry()->content . PHP_EOL;


$userPrompt = <<<PROMPT
Now conclude your result in JSON format as specified below, be sure to use concrete values.
Note that for GET request, all query parameters should also be included in the `Path` field.
Request body should be included in the `Data` field. 
When it is POST form data, it should be in the form of key-value pairs encoded as valid JSON.
When both `http://` and `file://` are possible, always generate `http://` only. `file://` is only used when `http://` is not possible.

Example Response schema:
```json
{
  "Method" : "Request method",
  "Path": "/api/to/route?with=params",
  "Data": {
    "field1": "value1",
    "field2": "value2"         
   },
   "Cookie": {
     "key1": "value1"
   },
   "Header": {
     "Key": "Value"
   }
}
```
PROMPT;
$chatgpt->umessage($userPrompt);
$responseFormat = [
    'type' => 'json_schema',
    'json_schema' =>
        [
            'name' => 'payload_response',
            'schema' =>
                [
                    'type' => 'object',
                    'properties' =>
                        [
                            'Method' =>
                                [
                                    'type' => 'string',
                                    'description' => 'Request method to use, like GET or POST'
                                ],
                            'Path' =>
                                [
                                    'type' => 'string',
                                    'description' => 'The request route to use, such as /api/to/route'
                                ],
                            'Data' =>
                                [
                                    'type' => 'string',
                                    'description' => 'The request body to use, in proper JSON format'
                                ],
                        ],
                    'required' => ['Method', 'Path', 'Data'],
                    'additionalProperties' => false,
                ],
            'strict' => true,
        ],
];
$responseFormat = ['type' => 'json_object'];
$chatgpt->set_param("response_format", $responseFormat);
$chatgpt->force_tool_choice("none");
$response = $chatgpt->response_with_retry()->content . PHP_EOL;
// Clean up response in case ```json ``` is added
$response = str_replace('```json', '', $response);
$response = str_replace('```', '', $response);
file_put_contents("spec.json", trim($response));
if (!REQUEST) {
    exit(0);
}

$attempt = 0;
const TRACE = false;
$diffFunctions = $prevDiffFunctions = [];
$diffLines = $prevDiffLines = [];
$formFuncAdded = false;
while ($attempt < 4) {
    $attempt++;
    $output = shell_exec("/home/jiych1/.phpbrew/php/php-8.1.11/bin/php request.php");
    if (strpos($output, "Triggered") !== false) {
        echo "Triggered\n";
        exit(0);
    } else {
        echo "Not triggered\n";
        echo $output;
    }
    if (TRACE) {
    list($calledTaintedFunctions, $calledTaintedLines) = compareTrace($taintedFunctions, $taintedLines);
    $prevDiffFunctions = $diffFunctions;
    $prevDiffLines = $diffLines;
    $diffFunctions = array_diff($calledTaintedFunctions, $taintedFunctions);
    $diffLines = array_diff($calledTaintedLines, $taintedLines);
    $funcImprovement = count($prevDiffFunctions) - count($diffFunctions);
    $lineImprovement = count($prevDiffLines) - count($diffLines);
    if ($attempt !== 0 && $funcImprovement <= 0 && $lineImprovement <= 0) {
        echo "No improvement";
        exit(1);
    }
    if (empty($calledTaintedFunctions) || empty($calledTaintedLines)) {
        $userPrompt = <<<PROMPT
The tainted lines/functions are not present in the trace. The route you generated is not correct.
Please check the error message and try to fix the route. You can try collect links using the `getPageLinks` tool.

The response of your generated request is:
```
$output;
```
PROMPT;
    } elseif (empty($diffFunctions) && empty($diffLines)) {
        $userPrompt = <<<PROMPT
The SSRF is not triggered. The input you generated for URL/file path is not correct. 
Review your analysis and fix it.
The response of your generated request is:
```
$output;
```
PROMPT;
    } else {
        $diffFunctionsString = implode("\n", $diffFunctions);
        $userPrompt = <<<PROMPT
Request with above input results in a failure without triggering SSRF. 
The following functions are not triggered in the runtime trace:
```
$diffFunctionsString
```
Please check the error message and review your analysis:
```
$output;
```
PROMPT;
    }}

$userPrompt = <<<PROMPT
The request does not trigger SSRF. The response is:
```
$output
```

Note that the response here is the raw response from server (long responses are truncated). 

Using the response, try to fix the input and route. If it is your first attempt to fix, follow the instructions below, otherwise, continue on your previous fix.

Double check for any framework/library used in the code to make sure the routing is correct.
If custom routing mechanism is used, use the `getPageLinks` tool to get links from a specific page for hints and the `extractForms` tool to get the forms on a specified page.
Note that although there may not be direct reference to our target route, comparing existing route structures and the directory structures may give insights about how routes are mapped to php files.
For example, suppose you have collected `/foo/bar/...` and the the directory structure get by using `getFileOrDir` is `/foomod/barController.php`, you can infer that the route name is mod/controller by removing mod and controller postfix. 

When status code is not 200, make sure the route is correct first, then check the input values.
Think carefully about what you might have missed in your analysis, give a concise fix plan and execute it.

You also need to review the constraints and the values you generated for the request and fix any potential errors.
Specifically, remember to use `executePhpCode` to validate your assumptions about the input fields.
Note that you can always assume session-related fields (such as CSRF tokens) are provided with valid values.
PROMPT;
    $chatgpt->force_tool_choice("auto");
    if (!$formFuncAdded) {
        $chatgpt->add_function('extractForms');
        $formFuncAdded = true;
    }

    $chatgpt->umessage($userPrompt);
    $params = $chatgpt->get_params();
    unset($params['response_format']);
    $chatgpt->set_params($params);
    $response = $chatgpt->response_with_retry()->content . PHP_EOL;

    $userPrompt = <<<PROMPT
Now conclude your fixed result in JSON format as specified below, be sure to use concrete values.
Note that for GET request, all query parameters should also be included in the `Path` field.
Request body should be included in the `Data` field. 
When it is POST form data, it should be in the form of key-value pairs encoded as valid JSON.
When both `http://` and `file://` are possible, always generate `http://` only. `file://` is only used when `http://` is not possible.

Example Response schema:
```json
{
  "Method" : "Request method",
  "Path": "/api/to/route?with=params",
  "Data": {
    "field1": "value1",
    "field2": "value2"         
   },
   "Cookie": {
     "key1": "value1"
   },
   "Header": {
     "Key": "Value"
   }
}
```
PROMPT;
    $chatgpt->umessage($userPrompt);
    $responseFormat = [
        'type' => 'json_schema',
        'json_schema' =>
            [
                'name' => 'payload_response',
                'schema' =>
                    [
                        'type' => 'object',
                        'properties' =>
                            [
                                'Method' =>
                                    [
                                        'type' => 'string',
                                    ],
                                'Path' =>
                                    [
                                        'type' => 'string',
                                    ],
                                'Data' =>
                                    [
                                        'type' => 'string',
                                    ],
                            ],
                        'required' => ['Method', 'Path', 'Data'],
                        'additionalProperties' => false,
                    ],
                'strict' => true,
            ],
    ];
    $responseFormat = ['type' => 'json_object'];
    $chatgpt->force_tool_choice("none");
    $chatgpt->set_param("response_format", $responseFormat);
    $response = $chatgpt->response_with_retry()->content . PHP_EOL;
    // Clean up response in case ```json ``` is added
    $response = str_replace('```json', '', $response);
    $response = str_replace('```', '', $response);
    file_put_contents("spec.json", $response);
}
$output = shell_exec("/home/jiych1/.phpbrew/php/php-8.1.11/bin/php request.php");
if (strpos($output, "Triggered") !== false) {
    echo "Triggered\n";
    exit(0);
} else {
    echo "Not triggered\n";
    echo $output;
}







