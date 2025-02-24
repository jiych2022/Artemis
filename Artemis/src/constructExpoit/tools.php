<?php
require 'vendor/autoload.php';
require 'config.php';

use Construct\TraceParser;
use Construct\Visitors\MethodExtractorVisitor;
use Construct\Visitors\PhpFileSummaryVisitor;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use WpOrg\Requests\Session;

/**
 * Get the links from a page, including href links and form action links
 *
 * @param string $path The path of the page, do not include base URL
 * @return string The href links of the page
 */
function getPageLinks(string $path): string
{
    echo "Getting links from path $path\n";
    /** @var Session $session */
    $session = require 'setup.php';
    $response = $session->get($path);
    try {
        $document = new \DiDom\Document($response->body);
        $hrefs = $document->find('a');
        $output = [];
        foreach ($hrefs as $href) {
            $hrefContent = $href->text();
            if (empty($hrefContent)) {
                $hrefContent = "No content";
            }
            $link = $href->attr('href');
            if (empty($link)) {
                continue;
            }
            $output[] = "Href: $link, Content: $hrefContent";
        }
        $forms = $document->find('form');
        foreach ($forms as $form) {
            $formId = $form->attr('id');
            if (empty($formId)) {
                $formId = "No ID";
            }
            $action = $form->attr('action');
            if (empty($action)) {
                continue;
            }
            $output[] = "Form link: $action, Form ID: $formId";
        }
        return implode("\n", $output);
    } catch (Exception $e) {
        return "Error parsing HTML";
    }
}

/**
 * Extracts forms from the page
 *
 * @param string $path The path of the page, do not include the base URL.
 * @return string The forms found in the page
 */
function extractForms(string $path): string {
    echo "Getting forms from page $path\n";
    /** @var Session $session */
    $session = require 'setup.php';
    $response = $session->get($path);
    try {
        $document = new \DiDom\Document($response->body);
        $forms = $document->find('form');
        $output = [];
        foreach ($forms as $form) {
            $doc = $form->toDocument()->getDocument();
            $html = $doc->saveHTML();
            $output[] = $html;
        }
        if (count($output) > 0) {
            return implode("\n", $output);
        }
    }
    catch (Exception $e) {

    }
    return "No forms found";
}

function processFilename($filename)
{
    global $repoBase;

    // Normalize filename
    $filename = ltrim($filename, '/');
    if (substr($repoBase, -1) !== '/') {
        $repoBase .= '/';
    }

    if (file_exists($repoBase . $filename)) {
        return realpath($repoBase . $filename);
    } elseif (file_exists('/' . $filename)) {
        return realpath('/' . $filename);
    } elseif (file_exists($filename)) {
        $path = realpath($filename);
        if (strpos($path, $repoBase) === false) {
            return false;
        }
        return realpath($filename);
    }

    return false;
}

/**
 * Get the content of a file or directory listing (up to 3-level deep)
 *
 * @param string $path The path of the file or directory. Should be either an absolute path or a path relative to the repository base
 * @return string The content of the file or directory listing (up to 3-level deep)
 */
function getFileOrDir(string $path): string
{
    echo "Getting path $path\n";
    $path = processFilename($path);
    if ($path) {
        if (is_dir($path)) {
            // Check if path is relative to the repository base
            global $repoBase;
            $normalizedRepoBase = rtrim($repoBase, '/');
            if (strpos($path, $normalizedRepoBase) === 0) {
                // Get the relative path properly
                $path = substr($path, strlen($normalizedRepoBase));
                $path = ltrim($path, '/');
            } else {
                return "Path is not within the repository base";
            }
            $level = 3;
            while ($level > 0) {
                $command = "cd $repoBase && tree -L $level -f -i -n $path";
                $output = shell_exec($command);
                // Check of output contains more than 200 lines
                $lines = explode("\n", $output);
                $count = count($lines);
                if ($count > 200) {
                    $level--;
                } else {
                    break;
                }
            }
            return $output ?? "No result";
        }
        if (is_file($path)) {
            // Check file size to be smaller than 300KB
            $size = filesize($path);
            $maxSize = 300000;
            if ($size > $maxSize) {
                return "File size too large to analyze. Likely a file that is minified.";
            }
            return file_get_contents($path);
        }

    }
    return "Path $path not found";
}

/**
 * Search for a specified keyword in files.
 * This method use regular expression to search for the keyword. You don't need to perform escaping.
 * Variant of keyword might be required to search for similar keywords.
 * To limit the result count, you need to be specific about the keyword.
 * For example, if you want to search for function definition, be sure to use format `function xxx`
 * If you want to search for function call, use `xxx(`
 *
 * @param string $keyword The keyword to search for
 * @param string $type The file type to search in, such as php or js, use empty string for any known type
 * @return string The search results
 */
function searchKeywords(string $keyword, string $type = "")
{
    global $repoBase;
    $tyeStr = empty($type) ?"all":$type;
    echo "Searching for $keyword in type $tyeStr\n";
    // Escape keyword for use in regular expression
    $keyword = preg_quote($keyword, '/');
    // Escape keyword for commandline
    $keyword = escapeshellarg($keyword);
    // Remove leading and trailing single quotes
    $keyword = trim($keyword, "'");
    if (empty($type)) {
        $type = "-k";
    }
    else {
        $type = "-t $type";
    }
    $ignoreDirs = ['tests', 'test', '.idea', 'cache', 'storage', 'upload', 'cli'];
    $command = "cd $repoBase && ack ";
    foreach ($ignoreDirs as $dir) {
        $command .= "--ignore-dir=\"$dir\" ";
    }
    $command .= "--nocolor $type -o \".{0,100}$keyword.{0,100}\"";
    $output = shell_exec($command);
    if ($output === null) {
        return "No results found. Please refine your search and try again.";
    }
    // Count lines
    $lines = explode("\n", $output);
    $count = count($lines);
    if ($count > 200) {
        return "Too many results. Please refine your search and try again.";
    } elseif ($count === 0) {
        return "No results found. Please refine your search and try again.";
    }
    foreach ($lines as &$line) {
        // If line contains more than 500 characters, truncate it
        if (strlen($line) > 500) {
            $line = substr($line, 0, 500) . "...";
        }
    }
    $output = implode("\n", $lines);
    return $output;
}

/**
 * Get the summary of a PHP file, including class names, function names, and method names
 *
 * @param string $filename The name of the PHP file
 * @return string Summary of the PHP file
 */
function getPhpFileSummary(string $filename)
{
    echo "Getting summary of $filename\n";

    $filename = processFilename($filename);
    if (!$filename) {
        return "File $filename not found";
    }
    if (!strpos($filename, '.php')) {
        return "Not a PHP file";
    }
    $code = file_get_contents($filename);
    $parser = (new ParserFactory)->createForNewestSupportedVersion();
    $ast = $parser->parse($code);

    $traverser = new NodeTraverser();
    $visitor = new PhpFileSummaryVisitor($filename);
    $traverser->addVisitor($visitor);
    $traverser->traverse($ast);
    $fileSummary = $visitor->getFileSummary();
    if ($fileSummary->isEmpty()) {
        return "No classes, functions, or methods found in $filename, this is a pure script file.";
    }
    return $fileSummary->__toString();
}

/**
 * Get the specified method from a PHP file. Specify either method name or line number
 * Line number takes precedence over method name.
 *
 * @param string $filename The name of the PHP file
 * @param string $nameOrLineNo The name of the method
 *
 * @return string The method code
 */
function getMethodFromFile(string $filename, string $nameOrLineNo): string
{
    echo "Getting method $nameOrLineNo from $filename\n";
    // Check whether methodname can be casted to int
    $lineNo = -1;
    if (is_numeric($nameOrLineNo)) {
        $lineNo = (int)$nameOrLineNo;
        $nameOrLineNo = '';
    }

    $filename = processFilename($filename);
    if (!$filename) {
        return "File $filename not found";
    }

    $code = file_get_contents($filename);
    $parser = (new ParserFactory)->createForNewestSupportedVersion();
    $ast = $parser->parse($code);

    $traverser = new NodeTraverser();
    $visitor = new MethodExtractorVisitor($nameOrLineNo, $lineNo);
    $traverser->addVisitor($visitor);
    $traverser->traverse($ast);

    $methodNode = $visitor->getMethodNode();
    if ($methodNode === null && $lineNo === -1) {
        return "Method $nameOrLineNo not found in $filename line $lineNo\n 
        Maybe the target is in a top-level statement in the file.";
    }
    if ($methodNode === null && $lineNo !== -1) {
        return file_get_contents($filename);
    }

    $prettyPrinter = new Standard();
    return $prettyPrinter->prettyPrint([$methodNode]);
}

/**
 * Execute PHP code. Return the result as string.
 * To get output, use print_r to print out any required result.
 *
 * @param string $code Code to execute
 * @return string Return value of the code, or "Execution failed" on error
 */
function executePhpCode(string $code): string
{
    echo "Executing: $code" . PHP_EOL;
    if (strpos($code, "<?php") === false) {
        $code = "<?php " . $code;
    }
    if (file_exists("tmp.php")) {
        // Rename to a unique name
        $tmpFile = "tmp" . uniqid() . ".php";
        rename("tmp.php", $tmpFile);
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

/**
 * Get the names of the tables in the database
 *
 * @return string The names of the tables
 */
function getTableNames()
{
    echo "Getting table names\n";
    global $dbName, $dbUser, $dbPass, $dbHost;
    $mysqli = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
    if ($mysqli->connect_error) {
        return "Connection failed: " . $mysqli->connect_error;
    }
    $result = $mysqli->query("SHOW TABLES");
    $tables = [];
    while ($row = $result->fetch_row()) {
        $tables[] = $row[0];
    }
    $result->close();
    $mysqli->close();
    $output = implode("\n", $tables);
    return $output;
}

/**
 * Get the schema (DDL) of the specified table
 *
 * @param string $tableName The name of the table
 * @return string The schema of the table
 */
function getTableSchema(string $tableName)
{
    echo "Getting schema of table $tableName\n";
    global $dbName, $dbUser, $dbPass, $dbHost;
    $mysqli = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
    if ($mysqli->connect_error) {
        return "Connection failed: " . $mysqli->connect_error;
    }
    try {
        $mysqli->query("SELECT 1 FROM $tableName LIMIT 1");
    } catch (Exception $e) {
        return "Table $tableName not found";
    }
    $result = $mysqli->query("show create table $tableName");
    $schema = [];
    while ($row = $result->fetch_row()) {
        $schema[] = $row[1];
    }
    $result->close();
    $mysqli->close();
    $output = implode("\n", $schema);
    return $output;
}

/**
 * Execute the specified SQL query
 *
 * @param string $sql The SQL query to execute
 * @return string The result of the query
 */
function executeSql(string $sql)
{
    echo "Executing SQL: $sql\n";
    global $dbName, $dbUser, $dbPass, $dbHost;
    $mysqli = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
    if ($mysqli->connect_error) {
        return "Connection failed: " . $mysqli->connect_error;
    }
    try {
        $result = $mysqli->query($sql);
    } catch (Exception $e) {
        return "Error: " . $mysqli->error . "\n Please fix your SQL";
    }
    if ($result === false) {
        return "Error: " . $mysqli->error . "\n Please fix your SQL";
    }
    if ($result === true) {
        return "Query executed successfully";
    }
    $output = [];
    while ($row = $result->fetch_assoc()) {
        $output[] = $row;
    }
    $result->close();
    $mysqli->close();
    return json_encode($output, JSON_PRETTY_PRINT);
}
const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS = 60 * MINUTE_IN_SECONDS;
const DAY_IN_SECONDS = 24 * HOUR_IN_SECONDS;
/**
 * Calculates a custom nonce in WordPress
 *
 * @param string $action The action the nonce belongs to
 * @return string The calculated nonce
 */
function calculate_custom_nonce(string $action)
{
    echo "Calculating custom nonce for action $action\n";
    $user_id = 1;
    $token = "VfUgY6ON94avFLy2wriFgvMOzLCX5osrSXfb1HWaheM";
    $nonce_salt = '0dc50cfc88f8a7f365f5c54858c29fb791cb4c4b7fbd9a0d3fe925013af1d1e45bdf95a580ed75cb';

    $tick = ceil(time() / (DAY_IN_SECONDS / 2));
    $data = $tick . '|' . $action . '|' . $user_id . '|' . $token;
    $hash = hash_hmac('md5', $data, $nonce_salt);

    return substr($hash, -12, 10);
}

function compareTrace($taintedFunctions, $taintedLines) {
    global $repoBase, $serverCodeBase, $traceLogPath;
    $parser = new TraceParser();
    $parser->parse($traceLogPath);
    $calledTaintedFunctions = array_filter($taintedFunctions, function ($function) use ($parser) {
        return $parser->callInTrace($function);
    });
    $taintedLines = array_map(function ($line) use ($repoBase, $serverCodeBase) {
        list($file, $lineNo) = explode(': ', $line);
        $file = str_replace($repoBase, $serverCodeBase, $file);
        return "$file: $lineNo";
    }, $taintedLines);

    $calledTaintedLines = array_filter($taintedLines, function ($line) use ($parser) {
        return $parser->lineInTrace($line);
    });

    return [
        $calledTaintedFunctions,
        $calledTaintedLines
    ];
}

$logFile = "log.txt";

function setLogName($name) {
    global $logFile;
    $logFile = $name;
}

function saveFunction($message, $chatId)
{
    // Append message to log file
    global $logFile;
    if (!file_exists($logFile)) {
        file_put_contents($logFile, "");
    }
    $log = file_get_contents($logFile);
    $log .= date("Y-m-d H:i:s") . " - Chat ID: $chatId\n";
    $message = (array)$message;
    if (array_key_exists(0, $message) && is_string($message[0])) {
        $message = $message[0];
        echo "Message: $message\n";
        $log .= $message . "\n";
    }
    if (is_array($message) && array_key_exists('content', $message)) {
        $role = $message['role'];
        $log .= $message['content'] . "\n";
        if (!in_array($role, ['system', 'user', 'tool'])) {
            echo "Message: " . $message['content'] . "\n";
        }

    }

    file_put_contents($logFile, $log);
}

//$result = compareTrace(['cmsUploader->uploadFromLink'], ['/home/jiych1/PhpstormProjects/fp-check/green/icms2/system/core/uploader.php: 294', '/home/jiych1/PhpstormProjects/fp-check/green/icms2/system/core/uploader.php: 334']);
//print_r($result);
//echo calculate_custom_nonce("wp_rest");
//echo shell_exec("php request.php");
// echo getFileOrDir('/home/jiych1/PhpstormProjects/fp-test/proj/livehelperchat/lhc_web');
//echo getFileOrDir("");
//echo getTableSchema('fcs_product');
//echo getTableNames();
//echo executeSql("Select id_product from fcs_product limit 2;");

//echo getPhpFileSummary('/home/jiych1/PhpstormProjects/projs/pixelfed/app/Util/ActivityPub/Helpers.php');
// echo getMethodFromFile('includes/functions.php', '3712', 3712);
//echo searchKeywords('church_admin_import_csv');
//echo retrieveCode('/home/jiych1/PhpstormProjects/projs/foodcoopshop/plugins/Network/src/Controller/ApiController.php', 124,409);
// echo getPageLinks('/index.php');
//echo extractForms('/ucp.php?i=ucp_profile&mode=avatar');
// echo searchKeywords("function isPathValid(", "php");


