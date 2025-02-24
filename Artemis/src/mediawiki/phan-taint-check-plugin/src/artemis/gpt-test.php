<?php
include "ChatGPT.php";

/**
 * Execute PHP code. Return the result as string.
 *
 * @param string $code Code to execute
 * @return string Return value of the code, or "Execution failed" on error
 */
function executePHPCode(string $code) : string {
    //echo "Executing: $code" . PHP_EOL;
    if (strpos($code, "<?php")===false) {
        $code = "<?php " . $code;
    }
    file_put_contents("tmp.php", $code);
    exec("php tmp.php 2>&1", $output, $returnCode);
    $fullResult = implode(PHP_EOL, $output);
    //echo "Result: $fullResult" . PHP_EOL;
    if ($returnCode !== 0) {
        //echo "Failed to execute" . PHP_EOL;
        return "Execution failed. Error code: $returnCode\n Error message: $fullResult\n Please fix your code or json and try again.";
    }
    return $fullResult;
}

function doChat($conds, $code)
{
    if (file_exists("api_key.txt")) {
        $apiKey = file_get_contents("api_key.txt");
    }
    else {
        $apiKey = getenv("OPENAI_API_KEY");
    }
    if (!$apiKey) {
        echo "API key not found. ";
        return "";
    }
    $chatgpt = new ChatGPT($apiKey);
    $chatgpt->set_params([
        'temperature' => 1.0,
        'max_tokens' => 1024,
        'frequency_penalty' => 0,
        'presence_penalty' => 0
    ]);
    $chatgpt->add_function("executePHPCode");
    $systemPrompt = <<< 'SYSTEM_PROMPT'
You are an expert on PHP web security. 
You will be given some code snippets and relevant documentation (if any). When document is given, pay attention to its notes/tips involving its behavior. 
Your task is to first analyze the potential SSRF vulnerability in the first code snippet.
Then, additional code snippets of conditions that input must satisfy will be given. You need to analyze them and infer the constraints.
Finally, you need to determine whether it is possible to satisfy all the constraints at the same time while triggering SSRF. 
Only consider standard PHP behavior. 
Think step by step and provide concise results. Do not provide advice.
SYSTEM_PROMPT;
    $chatgpt->smessage($systemPrompt);

    $userPrompt = <<< 'USER_PROMPT'
Tell me the requirements for the following code snippet to trigger a server-side request forgery (SSRF) vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an internal resource not accessible by attacker. 
Assume existing domains and their subdomains presented in the code all resolve to public resources that are safe. 
But other domains that attacker controls can resolve to arbitrary host/resource. 
As an example, suppose evil.com is attacker controlled, then evil.com can resolve to any resource including private/reserved ip ranges. 
Assume standard DNS behavior. Pay attention to how the URL host (domain) part is consisted of.
```
%s
```
USER_PROMPT;
    $chatgpt->umessage(sprintf($userPrompt, $code));
    $response = $chatgpt->response()->content . PHP_EOL;
//echo "SSRF response:";
//echo $response;
//echo "===============================================================" . PHP_EOL;

foreach ($conds as $cond) {
    $userPrompt = <<< 'USER_PROMPT'
Tell me the requirements to satisfy the following statement.
```
%s
```
USER_PROMPT;
    $chatgpt->umessage(sprintf($userPrompt, $cond));
    $response = $chatgpt->response()->content . PHP_EOL;
    //echo "Condition response:";
    //echo $response;
    //echo "===============================================================" . PHP_EOL;
}
    $userPrompt = <<< 'USER_PROMPT'
Now take all the code snippets into account. Is it possible to satisfy all of their requirements at the same time while triggering SSRF?
USER_PROMPT;
    $chatgpt->umessage(sprintf($userPrompt, json_encode($code)));
    $response = $chatgpt->response()->content . PHP_EOL;
    //echo "Result response:";
    //echo $response;
    //echo "===============================================================" . PHP_EOL;

    $userPrompt = <<< 'USER_PROMPT'
Review the analysis above carefully. Consider the following:
Only standard DNS behavior should be considered. 
Existing domains present in code and all of their subdomains are all safe.
When complex conditions are involved, you can generate some example code and use `executePHPCode` to run them. 
Note that to see the code output, use print_r to print the results.
Properly escape the generated code to fit in json format and print out the result.
USER_PROMPT;
    $chatgpt->umessage($userPrompt);
    $response = $chatgpt->response()->content . PHP_EOL;
    //echo "Review response:";
    //echo $response;
    //echo "===============================================================" . PHP_EOL;


    $userPrompt = <<< 'USER_PROMPT'
Conclude your analysis in a json format. For example:
```
{
  "Satisfy": false
}
```
Or
```
{
  "Satisfy": true,
  "Example": "example that satisfies all the requirements"
}
```
Do not include other fields
USER_PROMPT;
    $chatgpt->umessage(sprintf($userPrompt, $code));
    $response = $chatgpt->response()->content . PHP_EOL;
    //echo "Conclusion response:";
    //echo $response;

    // Strip ``` if they exist
    $response = str_replace("`", "", $response);
    return $response;
}
