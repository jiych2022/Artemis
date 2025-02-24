<?php

namespace Extract;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;

class SinkExtractor extends NodeVisitorAbstract
{
    private $lineNumbers;
    private $statement = "";

    public function __construct(array $lineNumbers)
    {
        $this->lineNumbers = $lineNumbers;
    }

    public function enterNode(Node $node)
    {
        if (!$node instanceof Node\Stmt) {
            return;
        }
        if (in_array($node->getStartLine(), $this->lineNumbers)) {
            $prettyPrinter = new Standard();
            $this->statement .= $prettyPrinter->prettyPrint([$node]);
            $this->statement .= "\n";
        }
    }

    public function getStatement(): ?string
    {
        return $this->statement;
    }
}