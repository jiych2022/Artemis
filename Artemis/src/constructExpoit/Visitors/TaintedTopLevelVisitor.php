<?php

namespace Construct\Visitors;

use PhpParser\Node\Stmt;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;

class TaintedTopLevelVisitor extends NodeVisitorAbstract
{
    private $topLevelLines = [];

    private $taintedFunctions = [];

    public function __construct($topLevelLines) {
        $this->topLevelLines = $topLevelLines;
    }

    public function enterNode($node) {
        if ($node instanceof Stmt) {
            $startLine = $node->getStartLine();
            $endLine = $node->getEndLine();
            foreach ($this->topLevelLines as $line) {
                if ($line >= $endLine) {
                    $this->taintedFunctions[] = $node;
                    return NodeVisitor::DONT_TRAVERSE_CHILDREN;
                }
            }
            if ($startLine !== $endLine) {
                // For multi-line statements, check whether any of the lines are tainted
                foreach ($this->topLevelLines as $line) {
                    if ($line >= $startLine && $line <= $endLine) {
                        $this->taintedFunctions[] = $node;
                        return NodeVisitor::DONT_TRAVERSE_CHILDREN;
                    }
                }
            }
        }
        return null;
    }

    public function getTaintedFunctions() {
        return $this->taintedFunctions;
    }
}