<?php

namespace PhanPlugin;
use Phan\CodeBase;
use Phan\Exception\FQSENException;
use Phan\Language\FQSEN\FullyQualifiedFunctionName;
use Phan\Language\FQSEN\FullyQualifiedMethodName;
use Phan\Language\FQSEN\FullyQualifiedPropertyName;
use Phan\Language\Type;

class KeywordSourcePlugin extends AbstractKeywordPlugin
{
    private const MODEL = 'gpt-4o-2024-08-06';
    public function finalizeProcess(CodeBase $code_base): void
    {
        $printPredicate = function () {
            return false;
        };
        $finalResults = [];
        foreach (KeywordSourceVisitor::$resultSet as $result => $type) {
            if ($type === "function") {
                try {
                    $methodFQSEN = FullyQualifiedFunctionName::fromFullyQualifiedString($result);
                    if (!$code_base->hasFunctionWithFQSEN($methodFQSEN)) {
                        $this->conditionalPrint(  "Function $result not found" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $method = $code_base->getFunctionByFQSEN(FullyQualifiedFunctionName::fromFullyQualifiedString($result));
                    $returnTypes = $method->getUnionType();
                    $typeSet = $returnTypes->getTypeSet();
                    $nonScalarTypes = array_filter($typeSet, function (Type $type) {
                        return !$type->isScalar() || in_array($type->getName(), ['string', 'mixed', 'null']);
                    });
                    if (count($nonScalarTypes) === 0) {
                        $this->conditionalPrint(  "Function $result only returns scalar" . PHP_EOL, $printPredicate);
                    } else {
                        if (empty($method->getDocComment())) {
                            $this->conditionalPrint(  "Function $result has no doc comment" . PHP_EOL, $printPredicate);
                            continue;
                        }
                        $this->conditionalPrint(  "Match found in function: $result" . PHP_EOL, $printPredicate);
                        $finalResults[$result] = $method->getDocComment();
                    }
                } catch (FQSENException $e) {
                }
            }
            else if ($type === "method") {
                try {
                    $fqsen = FullyQualifiedMethodName::fromFullyQualifiedString($result);
                    if (!$code_base->hasMethodWithFQSEN($fqsen)) {
                        $this->conditionalPrint(  "Method $result not found" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $method = $code_base->getMethodByFQSEN($fqsen);
                    $returnTypes = $method->getUnionType();
                    $typeSet = $returnTypes->getTypeSet();
                    $nonScalarTypes = array_filter($typeSet, function (Type $type) {
                        return !$type->isScalar() || in_array($type->getName(), ['string', 'mixed', 'null']);
                    });
                    if (count($nonScalarTypes) === 0) {
                        $this->conditionalPrint(  "Method $result only returns scalar" . PHP_EOL, $printPredicate);
                    } else {
                        if (empty($method->getDocComment())) {
                            $this->conditionalPrint(  "Method $result has no doc comment" . PHP_EOL, $printPredicate);
                            continue;
                        }
                        $this->conditionalPrint(  "Match found in method: $result" . PHP_EOL, $printPredicate);
                        $finalResults[$result] = $method->getDocComment();

                    }
                } catch (FQSENException $e) {
                }
            }
            else {
                try {
                    $fqsen = FullyQualifiedPropertyName::fromFullyQualifiedString($result);
                    if (!$code_base->hasPropertyWithFQSEN($fqsen)) {
                        $this->conditionalPrint(  "Property $result not found" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $property = $code_base->getPropertyByFQSEN($fqsen);
                    if (empty($property->getDocComment())) {
                        $this->conditionalPrint(  "Property $result has no doc comment" . PHP_EOL, $printPredicate);
                        continue;
                    }
                    $this->conditionalPrint(  "Match found in property: $result" . PHP_EOL, $printPredicate);
                    $finalResults[$result] = $property->getDocComment();
                } catch (FQSENException $e) {
                }
            }
        }
        $this->getFinalResults($finalResults, 'keyword-source-results.txt');
    }

    public static function getPostAnalyzeNodeVisitorClassName(): string
    {
        return KeywordSourceVisitor::class;
    }

    public function queryGPT(string $name, string $comment, array $pairs) : bool {
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
You will be given PHP functions/methods/properties from PHP web applications along with their doc comments. 
Your task is to determine whether the given PHP functions/methods/properties is a taint source in SSRF vulnerability according to its name and doc comment.
Here taint source is defined as functions/methods/properties that can return user-controlled data from a request. 
In a request, if data is coming from any of 
1. query strings (GET data/request URL)
2. headers
3. cookies
4. POST data (request body) 
then they should be considered user-controlled.

The input format is shown in the examples below:
```
Name: \db\migration\exception::getParameters
Comment: /**
 * Get the parameters
 * @return array
 */
```
This example is not a taint source because it returns data of an exception raised in a database context instead of from an incoming request.

```
Name: \request\request_interface::get_super_global
Comment: /**
 * Returns the original array of the requested super global
 * @param \phpbb\request\request_interface::POST|GET|REQUEST|COOKIE       $super_global The super global which will be returned
 * @return     array   The original array of the requested super global.
 */
```
This example is a taint source because it returns user input from an incoming request.

Pay attention to the doc comment.
Think step by step.
EOPROMPT;

        $assistant = <<< 'ASSISTANT'
Alright, I'm ready to analyze the next function, method, or property. Please provide the details for me to determine if it's a taint source in SSRF vulnerability.
ASSISTANT;


        $messages = [
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
                "content" => $assistant
            ],
            [
                "role" => "user",
                "content" => "Now check the input below:\n```\nName: $name\n Comment: $comment\n```"
            ],
        ];
        $complete = $openAi->chat([
            'model' => self::MODEL,
            'messages' => $messages,
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
        //echo "Checking $name...\n Raw Response: $result" . PHP_EOL;
        $messages[] = [
            "role" => "assistant",
            "content" => $result
        ];
        $messages[] = [
            "role" => "user",
            "content" => <<< 'SUMMARIZE'
According to your previous answer, summarize in json with the following schema:
```
{
    "isTaintSource": true/false
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
                    //echo "$name returns false\n";
                }
                return $value;
            }

        }
        //echo "Result format incorrect";
        return true;
    }
}



return new KeywordSourcePlugin();
