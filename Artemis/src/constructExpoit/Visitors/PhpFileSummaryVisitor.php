<?php

namespace Construct\Visitors;

use Construct\ClassSummary;
use Construct\FileSummary;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class PhpFileSummaryVisitor extends NodeVisitorAbstract {
    private ?FileSummary $fileSummary = null;

    public function __construct(string $fileName) {
        $this->fileSummary = new FileSummary();
        $this->fileSummary->fileName = $fileName;
    }

    public function enterNode(Node $node) {
        if ($node instanceof Node\Stmt\Class_) {
            $classSummary = new ClassSummary();
            $classSummary->className = $node->name->toString();
            $this->fileSummary->classes[] = $classSummary;
        } elseif ($node instanceof Node\Stmt\Function_) {
            $this->fileSummary->functions[] = $node->name->toString();
        } elseif ($node instanceof Node\Stmt\ClassMethod) {
            $className = end($this->fileSummary->classes);
            if ($className) {
                $visibility = $node->isPublic() ? 'public' : ($node->isProtected() ? 'protected' : 'private');
                $static = $node->isStatic() ? ' static' : '';
                // Construct parameter list
                $parameters = [];
                foreach ($node->params as $param) {
                    $parameters[] = '$' . $param->var->name;
                }
                $method = $visibility . $static . ' function ' . $node->name->toString() . '(' . implode(', ', $parameters) . ')';
                $className->methods[] = $method;

            }
        }
    }

    public function getFileSummary(): FileSummary
    {
        return $this->fileSummary ?? new FileSummary();
    }


}