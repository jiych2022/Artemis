<?php

namespace Construct\Visitors;

use PhpParser\Node;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;

class MethodExtractorVisitor extends NodeVisitorAbstract {
    private string $methodName;
    private $methodNode = null;

    private $line = -1;

    public function __construct(string $methodName, int $line) {
        $this->methodName = $methodName;
        $this->line = $line;
    }

    public function enterNode(Node $node) {
        if (($node instanceof ClassMethod || $node instanceof Function_)) {
            $startLine = $node->getStartLine();
            $endLine = $node->getEndLine();
            if ($this->line !== -1 && ($this->line >= $startLine && $this->line <= $endLine)) {
                $this->methodNode = $node;
                return NodeVisitor::STOP_TRAVERSAL;
            }
            if ($node->name->toString() === $this->methodName) {
                $this->methodNode = $node;
                return NodeVisitor::STOP_TRAVERSAL;
            }
        }
    }

    public function getMethodNode() {
        return $this->methodNode;
    }
}