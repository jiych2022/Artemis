<?php

namespace PhanPlugin;
use Phan\CodeBase;
use Phan\Exception\FQSENException;
use Phan\Language\FQSEN\FullyQualifiedFunctionName;
use Phan\Language\FQSEN\FullyQualifiedMethodName;

class KeywordSinkPlugin extends AbstractKeywordPlugin
{
    private const MODEL = 'gpt-4o-2024-08-06';
    public function finalizeProcess(CodeBase $code_base): void
    {
        $printPredicate = function () {
            return false;
        };
        $finalResults = [];
        foreach (KeywordSinkVisitor::$resultSet as $result => $type) {
            if ($type === "function") {
                try {
                    $methodFQSEN = FullyQualifiedFunctionName::fromFullyQualifiedString($result);
                    if (!$code_base->hasFunctionWithFQSEN($methodFQSEN)) {
                        $this->conditionalPrint( "Function $result not found" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $method = $code_base->getFunctionByFQSEN(FullyQualifiedFunctionName::fromFullyQualifiedString($result));

                    if (empty($method->getDocComment())) {
                        $this->conditionalPrint( "Function $result has no doc comment" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $this->conditionalPrint(  "Match found in function: $result" . PHP_EOL, $printPredicate);
                    $finalResults[$result] = $method->getDocComment();
                } catch (FQSENException $e) {
                }
            } else if ($type === "method") {
                try {
                    $fqsen = FullyQualifiedMethodName::fromFullyQualifiedString($result);
                    if (!$code_base->hasMethodWithFQSEN($fqsen)) {
                        $this->conditionalPrint(  "Method $result not found" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $method = $code_base->getMethodByFQSEN($fqsen);
                    // Handles the case where the method is defined in a trait
                    $real = $method->getRealDefiningFQSEN();
                    $method = $code_base->getMethodByFQSEN($real);

                    if (empty($method->getDocComment()) && !$method->isNewConstructor()) {
                        $this->conditionalPrint(  "Method $result has no doc comment" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $this->conditionalPrint(  "Match found in method: $result" . PHP_EOL, $printPredicate);
                    $finalResults[$result] = $method->getDocComment();
                } catch (FQSENException $e) {
                }
            }
        }
        $this->getFinalResults($finalResults, 'keyword-sink-results.txt');
    }

    public static function getPostAnalyzeNodeVisitorClassName(): string
    {
        return KeywordSinkVisitor::class;
    }

    public function queryGPT(string $name, string $comment, array $pairs): bool
    {
        $printPredicate = function () {
            return false;
        };
        if (file_exists("api_key.txt")) {
            $apiKey = file_get_contents("api_key.txt");
        }
        else {
            $apiKey = getenv("OPENAI_API_KEY");
        }
        if (!$apiKey) {
            //echo "API key not found. ";
            return true;
        }
        $openAi = new OpenAi($apiKey);
        $openAi->setBaseURL('https://api.gptsapi.net');
        $promptUser = <<< 'EOPROMPT'
You will be given a list of PHP functions/methods from PHP web applications along with their doc comments. 
Your task is to determine whether the given PHP function/method is a potential taint sink for SSRF according to its fully qualified name and doc comment. 
Here taint sink is defined to be a function/method that will send a request to an external server.
Different functions/methods will be divided by a line of dashes.  

For example:
```
Name: \GuzzleHttp\Client::get
Comment: Create and send an HTTP GET request. Use an absolute path to override the base path of the client, or a relative path to append to the base path of the client. The URL can contain the query string as well. @param string|UriInterface $uri     URI object or string. @param array               $options Request options to apply. @throws GuzzleException
```
This is a sink because it may send a request.
-----------------------------------------------------------------------------------------
```
Name: \phpbb\request\request_interface::get_super_global
Comment: Returns the original array of the requested super global@param \phpbb\request\request_interface::POST|GET|REQUEST|COOKIE       $super_globalThe super global which will be returned@return     array   The original array of the requested super global.
```
This returns false because it will not send a request.


If you cannot decide according to the given data, regard it as true.
Pay attention to the doc comment.
Think step by step.
EOPROMPT;

        $complete = $openAi->chat([
            'model' => self::MODEL,
            'messages' => [
                [
                    "role" => "system",
                    "content" => "You are an expert on PHP and taint analysis."
                ],
                [
                    "role" => "user",
                    "content" => $promptUser
                ],
                [
                    "role" => "assistant",
                    "content" => "Yes, I understand. I will determine whether the given PHP functions/methods are potential taint sinks based on their fully qualified names and doc comments. The output will be a JSON array containing true or false for each function/method."
                ],
                [
                    "role" => "user",
                    "content" => "```Name: $name\n Comment: $comment```"
                ],
            ],
            'temperature' => 1.0,
            'max_tokens' => 1024,
            'frequency_penalty' => 0,
            'presence_penalty' => 0
        ]);
        if (!is_string($complete)) {
            //echo "Complete failed\n";
            return true;
        }
        $result = json_decode($complete);
        if (!isset($result->choices)) {
            //echo "No choices\n";
            //var_dump($result);
            return true;
        }
        $result = $result->choices[0]->message->content;
        if (strpos($result, "```") !== false) {
            if (strpos($result, "true") !== false) {
                return true;
            }
        }
        //echo "Checking $name...\n Raw Response: $result" . PHP_EOL;
        $messages[] = [
            "role" => "assistant",
            "content" => $result
        ];
        $messages[] = [
            "role" => "user",
            "content" => <<< 'SUMMARIZE'
Summarize in json with the following schema: DO NOT CHANGE RESULT!!!
```
{
    "isTaintSource": Boolean
}
```
SUMMARIZE
        ];

        $complete = $openAi->chat([
            'model' => self::MODEL,
            'messages' => $messages,
            "response_format"=> [ "type"=> "json_object" ],
            'temperature' => 1.0,
            'max_tokens' => 1024,
            'frequency_penalty' => 0,
            'presence_penalty' => 0
        ]);
        if (!is_string($complete)) {
            //echo "Complete failed\n";
            return true;
        }
        $result = json_decode($complete);
        if (!isset($result->choices)) {
            //echo "No choices\n";
            //var_dump($result);
            return true;
        }
        $result = $result->choices[0]->message->content;
        $result = trim($result);
        //echo "JSON Response:\n $result" . PHP_EOL;
        $result = json_decode($result);
        if (empty($result)) {
            //echo "Result decode failed\n";
            return true;
        }
        foreach ($result as $value) {
            if (is_bool($value)) {
                if ($value === false) {
                    echo "$name returns false\n";
                }
                return $value;
            }

        }
        //echo "Result format incorrect";
        return true;
    }
}

return new KeywordSinkPlugin();