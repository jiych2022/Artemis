<?php
require 'vendor/autoload.php';
require 'gpt-test.php';

use Extract\ConditionExtractor;
use Extract\SinkExtractor;
use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Parser;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;

const DEBUG_LOG = false;
/*$testcaseFolder = 'testcases/base';
$testcases = [
    'testcase1.php' => 6,
    '/home/jiych1/PhpstormProjects/fp-yellow/alltube/classes/Controller/JsonController.php' => 33,
    //'testcase3.php' => 10,
    //'testcase4.php' => 20,
    //'testcase5.php' => 7,
];

foreach ($testcases as $fileName => $lineNumber) {
    $file = $testcaseFolder . DIRECTORY_SEPARATOR . $fileName;
    if (!file_exists($file)) {
        $file = $fileName;
    }
    echo "Extracting conditions from $file\n";
    doExtract($file, $lineNumber);
}*/

$file = $argv[1];
$lineNumber = $argv[2];
$path = $argv[3];
// Split path using comma to get line numbers
$lineNumbers = explode(",", $path);
[$conditions, $sink] = doExtract($file, $lineNumber, $lineNumbers);
// print_r ($sink);
$conds = [];
foreach ($conditions as $condition) {
    $conds[] = $condition['source'];
}

echo doChat($conds, $sink);

function doExtract(string $file, int $lineNumber, array $lineNumbers = [])
{
    $parser = (new ParserFactory)->createForNewestSupportedVersion();
    $cfgParser = new Parser($parser);


    $script = file_get_contents($file);
    $block = $cfgParser->parse($script, $file);
    $traverser = new PHPCfg\Traverser();
    $traverser->traverse($block);

    $foundBlock = findBasicBlock($block->main->cfg, $lineNumber);
    foreach ($block->functions as $func) {
        $foundBlock = findBasicBlock($func->cfg, $lineNumber, $foundBlock);
    }


    if ($foundBlock === null) {
        echo "No block found\n";
        exit(1);
    }
    $conditions = extractConditionsToReach($foundBlock);

    $conditionPairs = [];
    /** @var Op $condition */
    foreach ($conditions as $condition_pair) {
        $condition = $condition_pair['condition'];
        [$start, $end] = $condition->getLines();
        if ($start === -1) {
            continue;
        }
        debugLog("Condition found on line $start");
        $conditionPairs[] = [$start, $condition_pair['logic']];
    }

    try {
        $ast = $parser->parse($script);
        $traverser = new NodeTraverser;
        $conditionExtractor = new ConditionExtractor($conditionPairs);
        $sinkExtractor = new SinkExtractor($lineNumbers);
        $traverser->addVisitor($conditionExtractor);
        $traverser->addVisitor($sinkExtractor);
        $traverser->traverse($ast);

        $conditions = $conditionExtractor->getExtractedConditions();
        //print_r($conditions);
        //echo "===================" . PHP_EOL;
        return [$conditions, $sinkExtractor->getStatement()];
    } catch (Error $error) {
        echo "Parse error: {$error->getMessage()}\n";
    }
}

function findBasicBlock(Block $initialBlock, int $lineNumber, ?Block $closestBlock = null): ?Block
{
    $blockQueue = new SplQueue();
    $visitedBlocks = new SplObjectStorage();
    $blockQueue->enqueue($initialBlock);

    while (!$blockQueue->isEmpty()) {
        /** @var Block $block */
        $block = $blockQueue->dequeue();
        if ($visitedBlocks->contains($block)) {
            continue;
        }
        $visitedBlocks->attach($block);

        if (isset($block->start_line) && isset($block->end_line)) {
            // Check if the block's line range includes the line number
            if ($block->start_line <= $lineNumber && $block->end_line >= $lineNumber) {
                // Update closestBlock if this block is closer to the line number
                if ($closestBlock === null || $block->start_line > $closestBlock->start_line) {
                    $closestBlock = $block;
                }
            }
        }

        // Enqueue the next blocks for checking
        foreach ($block->children as $op) {
            foreach ($op->getSubBlocks() as $blockName) {
                $sub = $op->{$blockName};
                if (is_array($sub)) {
                    foreach ($sub as $subBlock) {
                        if (!$subBlock) {
                            continue;
                        }
                        $blockQueue->enqueue($subBlock);
                    }
                } elseif ($sub) {
                    $blockQueue->enqueue($sub);
                }
            }
        }
    }

    return $closestBlock;
}

function extractConditionsToReach(Block $targetBlock): array
{
    $conditions = [];
    $visitedBlocks = new SplObjectStorage();
    $blockQueue = new SplQueue();
    $blockQueue->enqueue($targetBlock);
    $blocksOnPathToTarget = new SplObjectStorage();
    $blocksOnPathToTarget->attach($targetBlock);

    $shouldSkip = false;
    while (!$blockQueue->isEmpty()) {
        /** @var Block $block */
        $block = $blockQueue->dequeue();

        // Skip if we have already visited this block
        if ($visitedBlocks->contains($block)) {
            continue;
        }
        $visitedBlocks->attach($block);

        // Check each operation in the block
        foreach ($block->children as $op) {
            // Add conditional operations to the conditions array
            if ($op instanceof Op\Stmt\JumpIf) {
                $ifTarget = $blocksOnPathToTarget->contains($op->if);
                $elseTarget = $blocksOnPathToTarget->contains($op->else);

                if (!$shouldSkip) {
                    debugLog("Adding condition block# " . $block->id);
                    $conditions[] = [
                        'condition' => $op,
                        'logic' => ($ifTarget ? 'if' : 'else'),
                    ];
                }
                $shouldSkip = false;
            }
        }

        $allJump = true;
        foreach ($block->parents as $parent) {
            if (isJumpBlock($parent) && !$parent->dead) {
                debugLog("Enqueueing parent block# %d", $parent);
            } else {
                debugLog("Parent block# %d is not a conditional jump", $parent);
            }
            // Check whether thr last op of block is not jump
            $lastOp = $parent->children[count($parent->children) - 1];
            if (!$lastOp instanceof Op\Stmt\Jump ) {
                $allJump = false;
            }
            $blockQueue->enqueue($parent);
            $blocksOnPathToTarget->attach($parent);
        }

        //Count the number of non dead parents
        $numParents = 0;
        $possibleLoop = false;
        foreach ($block->parents as $parent) {
            if (!$parent->dead) {
                $numParents++;
            }
            if ($parent->id > $block->id) {
                debugLog(sprintf("Parent block# %d is after block# %d", $parent->id, $block->id));
                $possibleLoop = true;
            }
        }
        if ($numParents > 1 && $allJump && !$possibleLoop) {
            debugLog("All parent blocks of block# %d are jump blocks, skip next if", $block);
            $shouldSkip = true;
        }
    }

    return $conditions;
}

// Function to determine if a block is a jump block
function isJumpBlock(Block $block): bool
{
    foreach ($block->children as $op) {
        if ($op instanceof Op\Stmt\JumpIf || $op instanceof Op\Stmt\Jump) {
            return true;
        }
    }
    return false;
}

function debugLog(string $messageTemplate, Block $block = null)
{
    if (!defined("DEBUG_LOG") || !DEBUG_LOG) {
        return;
    }
    if ($block === null) {
        echo $messageTemplate . PHP_EOL;
        return;
    }
    /*if (isset($block->start_line)) {
        $message = sprintf($messageTemplate, $block->start_line);
    } else {
        $message = sprintf($messageTemplate, -1);
    }*/
    $message = sprintf($messageTemplate, $block->id);
    echo $message . PHP_EOL;
}
