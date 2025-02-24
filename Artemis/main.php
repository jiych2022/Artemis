<?php
if ($argc < 3) {
    echo "Usage: php main.php <sourcePaths> <libraryPaths>\n";
    exit(1);
}

if (empty($argv[1])) {
    echo "Usage: php main.php <sourcePaths> <libraryPaths>\n";
    exit(1);
}
if (getenv("OPENAI_API_KEY") === false) {
    echo "OpenAi key is absent\n";
    exit(1);
}
$sourcePaths = explode(';', $argv[1]);
if (empty($argv[2])) {
    $libraryPaths = [];
}
else {
    $libraryPaths = explode(';', $argv[2]);
}

$directoryList = [];
foreach ($sourcePaths as $sourcePath) {
    $directoryList[] = $sourcePath;
}
foreach ($libraryPaths as $libraryPath) {
    $directoryList[] = $libraryPath;
}
$directoryListString = '[\'' . implode("',\n        '", $directoryList) . '\']';


$excludeAnalysisDirectoryList = [];
foreach ($libraryPaths as $libraryPath) {
    $excludeAnalysisDirectoryList[] = $libraryPath;
}
if (empty($excludeAnalysisDirectoryList)) {
    $excludeAnalysisDirectoryListString = '[]';
}
else {
    $excludeAnalysisDirectoryListString = '[\'' . implode("',\n        '", $excludeAnalysisDirectoryList) . '\']';
}

$config = <<< EOL
<?php
\$seccheckPath = 'src/plugin';

/**
 * This configuration will be read and overlaid on top of the
 * default configuration. Command-line arguments will be applied
 * after this file is read.
 */
return [
    // Supported values: `'5.6'`, `'7.0'`, `'7.1'`, `'7.2'`, `'7.3'`,
    // `'7.4'`, `'8.0'`, `'8.1'`, `null`.
    // If this is set to `null`,
    // then Phan assumes the PHP version which is closest to the minor version
    // of the php executable used to execute Phan.
    //
    // Note that the **only** effect of choosing `'5.6'` is to infer
    // that functions removed in php 7.0 exist.
    'target_php_version' => 7.4,

    // A list of directories that should be parsed for class and
    // method information. After excluding the directories
    // defined in exclude_analysis_directory_list, the remaining
    // files will be statically analyzed for errors.
    //
    // Thus, both first-party and third-party code being used by
    // your application should be included in this list.
    'directory_list' => $directoryListString,

    'whitelist_issue_types' => [
        'SecurityCheck-CUSTOM1',
        'SecurityCheckDebugTaintedness'
    ],

    'quick_mode' => true,

    'plugins' => [
        "\$seccheckPath/KeywordSourcePlugin.php",
        "\$seccheckPath/KeywordSinkPlugin.php"
    ],

    // A regex used to match every file name that you want to
    // exclude from parsing. Actual value will exclude every
    // "test", "tests", "Test" and "Tests" folders found in
    // "vendor/" directory.
    'exclude_file_regex' => 
        '@(^vendor/.*/(tests?|Tests?)/)|(lessc\.inc\.php)|(functions_jabber\.php)|(AppsApp\.php)|(.*/HTMLPurifier/)|(HTMLPurifier.*)|(plugin_api\.inc\.php)|(.*/install/)|(tecnickcom/)@',


    // A directory list that defines files that will be excluded
    // from static analysis, but whose class and method
    // information should be included.
    //
    // Generally, you'll want to include the directories for
    // third-party code (such as "vendor/") in this list.
    //
    // n.b.: If you'd like to parse but not analyze 3rd
    //       party code, directories containing that code
    //       should be added to both the `directory_list`
    //       and `exclude_analysis_directory_list` arrays.
    'exclude_analysis_directory_list' => $excludeAnalysisDirectoryListString,
];
EOL;

file_put_contents('config1.php', $config);

echo "Identifying sources and sinks...\n";
$output = shell_exec('src/bin/phan -d . -k config1.php 2> /dev/null');
echo $output;

$config = <<< EOL
<?php

\$seccheckPath = 'src/mediawiki/phan-taint-check-plugin/';

/**
 * This configuration will be read and overlaid on top of the
 * default configuration. Command-line arguments will be applied
 * after this file is read.
 */
return [
    // Supported values: `'5.6'`, `'7.0'`, `'7.1'`, `'7.2'`, `'7.3'`,
    // `'7.4'`, `'8.0'`, `'8.1'`, `null`.
    // If this is set to `null`,
    // then Phan assumes the PHP version which is closest to the minor version
    // of the php executable used to execute Phan.
    //
    // Note that the **only** effect of choosing `'5.6'` is to infer
    // that functions removed in php 7.0 exist.
    'target_php_version' => 7.4,

    // A list of directories that should be parsed for class and
    // method information. After excluding the directories
    // defined in exclude_analysis_directory_list, the remaining
    // files will be statically analyzed for errors.
    //
    // Thus, both first-party and third-party code being used by
    // your application should be included in this list.
    'directory_list' => $directoryListString,

    'whitelist_issue_types' => [
        'SecurityCheck-CUSTOM1',
        'SecurityCheckDebugTaintedness',
    ],

    'quick_mode' => false,

    'plugins' => [
        "\$seccheckPath/SSrfFindPosPlugin.php",
    ],

    // A regex used to match every file name that you want to
    // exclude from parsing. Actual value will exclude every
    // "test", "tests", "Test" and "Tests" folders found in
    // "vendor/" directory.
    'exclude_file_regex' =>
        '@(^vendor/.*/(tests?|Tests?)/)|(lessc\.inc\.php)|(functions_jabber\.php)|(AppsApp\.php)|(.*/HTMLPurifier/)|(HTMLPurifier.*)|(plugin_api\.inc\.php)|(.*/install/)|(tecnickcom/)@',


    // A directory list that defines files that will be excluded
    // from static analysis, but whose class and method
    // information should be included.
    //
    // Generally, you'll want to include the directories for
    // third-party code (such as "vendor/") in this list.
    //
    // n.b.: If you'd like to parse but not analyze 3rd
    //       party code, directories containing that code
    //       should be added to both the `directory_list`
    //       and `exclude_analysis_directory_list` arrays.
    'exclude_analysis_directory_list' => $excludeAnalysisDirectoryListString,
];
EOL;

file_put_contents('config.php', $config);
echo "Performing Taint Analysis...";
$output = shell_exec('src/bin/phan -d . -k config.php 2> /dev/null');
// Split output by new line
$reports = explode("\n", $output);
echo "Checking False Positives...";
foreach ($reports as $report) {
    $command = "java -jar ./src/bin/fp-check.jar \"$report\"";
    $output = shell_exec($command);
    if (strpos($output, '[[FP]]') === false) {
        echo $report;
        echo "\n";
    }
}
