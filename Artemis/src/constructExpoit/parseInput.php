<?php
require 'vendor/autoload.php';
use Construct\Visitors\TaintedCommentVisitor;
use Construct\Visitors\TaintedTopLevelVisitor;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;

function extractFileAndLineInfo($input) {
    $fileLines = [];

    // Match `/path/to/file.php:line` and `/path/to/file.php +line;` formats
    preg_match_all('/((\/[\S\/]+\.php):(\d+))|((\/[\S\/]+\.php)\s*\+(\d+))/', $input, $matches);

    // var_dump($matches);
    // Handle colon-separated file and line format
    for ($i = 0; $i < count($matches[2]); $i++) {
        if (!empty($matches[2][$i]) && !empty($matches[3][$i])) {
            $fileLines[] = [$matches[2][$i], (int)$matches[3][$i]];
        }
    }

    // Handle plus-separated file and line format
    for ($i = 0; $i < count($matches[5]); $i++) {
        if (!empty($matches[5][$i]) && !empty($matches[6][$i])) {
            $fileLines[] = [$matches[5][$i], (int)$matches[6][$i]];
        }
    }

    return $fileLines;
}

/**
 * @return array{modifiedCode: string, filePath: string, taintedCallLines: string[], taintedNames: string[]}
 */
function getCodeData($filePath, $lineNumbers): array
{
    $code = file_get_contents($filePath);
    $parser = (new ParserFactory)->createForNewestSupportedVersion();
    $ast = $parser->parse($code);

    $traverser = new NodeTraverser();
    $visitor = new NameResolver(null, [
        'replaceNodes' => false,
    ]);
    $traverser->addVisitor($visitor);
    $traverser->addVisitor(new ParentConnectingVisitor());
    $traverser->traverse($ast);


    $traverser = new NodeTraverser();
    $visitor = new TaintedCommentVisitor($lineNumbers);
    $traverser->addVisitor($visitor);
    $traverser->traverse($ast);
    $topLevelLines = $visitor->getTopLevelLines();
    $methods = $visitor->getTaintedFunctionNodes();
    $taintedCallLines = $visitor->getTaintedCallLines();
    $taintedCallLines = array_map(function ($line) use ($filePath) {
        return "$filePath: $line";
    }, $taintedCallLines);
    $taintedNames = $visitor->getTaintedFunctionNames();


    $traverser = new NodeTraverser();
    $visitor = new TaintedTopLevelVisitor($topLevelLines);
    $traverser->addVisitor($visitor);
    $traverser->traverse($ast);

    $topLevelStmts = $visitor->getTaintedFunctions();
    $methods = array_merge($methods, $topLevelStmts);

    $prettyPrinter = new Standard();
    $modifiedCode = $prettyPrinter->prettyPrint($methods);

    $result = [
        'modifiedCode' => $modifiedCode,
        'filePath' => $filePath,
        'taintedCallLines' => $taintedCallLines,
        'taintedNames' => $taintedNames
    ];

    return $result;
}

/*$input = <<<'INPUT'
/home/jiych1/PhpstormProjects/projs/linkace/LinkAce/app/Http/Controllers/FetchController.php:138 SecurityCheck-CUSTOM1 Calling method \Illuminate\Http\Client\PendingRequest::get() in \App\Http\Controllers\FetchController::htmlForUrl that outputs using tainted argument #1 ($url). (Caused by: Builtin-\Illuminate\Http\Client\PendingRequest::get) (Caused by: /home/jiych1/PhpstormProjects/projs/linkace/LinkAce/app/Http/Controllers/FetchController.php +132; Builtin-\Illuminate\Http\Request::input)
INPUT;*/
/*$input = <<<'INPUT'
/home/jiych1/PhpstormProjects/projs/espocrm/espocrm/application/Espo/Tools/Attachment/Api/PostFromImageUrl.php:68 SecurityCheck-CUSTOM1 Calling method \Espo\Tools\Attachment\UploadUrlService::uploadImage() in \Espo\Tools\Attachment\Api\PostFromImageUrl::process that outputs using tainted argument #1 (`$url`). (Caused by: /home/jiych1/PhpstormProjects/projs/espocrm/espocrm/application/Espo/Tools/Attachment/UploadUrlService.php +75; /home/jiych1/PhpstormProjects/projs/espocrm/espocrm/application/Espo/Tools/Attachment/UploadUrlService.php +139; /home/jiych1/PhpstormProjects/projs/espocrm/espocrm/application/Espo/Tools/Attachment/UploadUrlService.php +123) (Caused by: /home/jiych1/PhpstormProjects/projs/espocrm/espocrm/application/Espo/Tools/Attachment/Api/PostFromImageUrl.php +52; /home/jiych1/PhpstormProjects/projs/espocrm/espocrm/application/Espo/Tools/Attachment/Api/PostFromImageUrl.php +50; Builtin-\Espo\Core\Api\Request::getParsedBody)
INPUT;
$lines = extractFileAndLineInfo($input);
//var_dump($lines);
// Merge lines in the same file
$fileLineMap = [];
foreach ($lines as $line) {
    $file = $line[0];
    $lineNumber = $line[1];
    if (!array_key_exists($file, $fileLineMap)) {
        $fileLineMap[$file] = [];
    }
    $fileLineMap[$file][] = $lineNumber;
}
$code = '';
foreach ($fileLineMap as $file => $lineNumbers) {
    $modifiedCode = getModifiedCode($file, $lineNumbers);
    $code .= "// $file\n";
    $code .= $modifiedCode;
    $code .= "\n";
}
echo $code;*/