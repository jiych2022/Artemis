<?php

namespace Construct\Visitors;

use PhpParser\Comment;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;

class TaintedCommentVisitor extends NodeVisitorAbstract
{
    /**
     * @var int[]
     */
    private array $linesToTaint;

    /**
     * @var ClassMethod[]|Function_[]
     */
    private array $taintedFunctionNodes = [];

    /**
     * @var string[]
     */
    private array $taintedFunctionNames = [];

    /**
     * @var int[]
     */
    private array $scopedLines = [];

    /**
     * @var ClassMethod[]|Function_[]
     */
    private array $scopeStack = [];

    /**
     * @var int[]
     */
    private array $taintedCallLines = [];

    private string $classContext = "";

    public function __construct($linesToTaint) {
        $this->linesToTaint = $linesToTaint;
    }

    public function enterNode(Node $node) {
        if ($node instanceof Stmt\ClassLike) {
            $this->classContext = $node->namespacedName ?? (string)$node->name;
        }

        if ($node instanceof Expr && $node->getStartLine() && in_array($node->getStartLine(), $this->linesToTaint)) {
            $parent = $node->getAttribute('parent');
            // Find the Stmt containing this expr
            while ($parent && !$parent instanceof Stmt) {
                $parent = $parent->getAttribute('parent');
            }
            if ($parent) {
                // Adding comment for taint
                $parent->setAttribute('comments', [
                    new Comment('// Tainted')
                ]);
            }
        }

        if ($node instanceof Stmt &&$node->getStartLine() && in_array($node->getStartLine(), $this->linesToTaint)) {
            // Adding comment for taint
            $node->setAttribute('comments', [
                new Comment('// Tainted')
            ]);
        }

        if ($node instanceof Node\Expr\CallLike && $node->getStartLine() && in_array($node->getStartLine(), $this->linesToTaint)) {
            $this->taintedCallLines[] = $node->getStartLine();
        }

        // Track function/method for tainted line
        if ($node instanceof ClassMethod || $node instanceof Function_) {
            $this->scopeStack[] = $node;
            $startLine = $node->getStartLine();
            $endLine = $node->getEndLine();

            foreach ($this->linesToTaint as $line) {
                if ($line >= $startLine && $line <= $endLine) {
                    $this->taintedFunctionNodes[] = $node;
                    if (empty($this->classContext) || $node instanceof Function_) {
                        $this->taintedFunctionNames[] = (string)$node->name;
                    } else {
                        if ($node->isStatic()) {
                            $this->taintedFunctionNames[] = $this->classContext . '::' . $node->name;
                        } else {
                            $this->taintedFunctionNames[] = $this->classContext . '->' . $node->name;
                        }
                    }
                    break;
                }
            }
            foreach ($this->linesToTaint as $line) {
                if ($line >= $startLine && $line <= $endLine) {
                    $this->scopedLines[] = $line;
                }
            }
        }

/*        if (empty($this->scopeStack) && $node instanceof Stmt &&
            !$node instanceof Stmt\Property && !$node instanceof Stmt\Const_ && !$node instanceof Stmt\Declare_) {
            $endLine = $node->getEndLine();
            foreach ($this->linesToTaint as $line) {
                if ($line >= $endLine) {
                    $this->taintedFunctions[] = $node;
                    return NodeVisitor::DONT_TRAVERSE_CHILDREN;
                }
            }
        }*/
    }

    public function leaveNode(Node $node)
    {
        if ($node instanceof ClassMethod || $node instanceof Function_) {
            array_pop($this->scopeStack);
        }
        if ($node instanceof Stmt\ClassLike) {
            $this->classContext = "";
        }
    }

    /**
     * @return ClassMethod[]|Function_[]
     */
    public function getTaintedFunctionNodes(): array
    {
        return $this->taintedFunctionNodes;
    }

    /**
     * @return int[]
     */
    public function getTopLevelLines(): array
    {
        $this->scopedLines = array_unique($this->scopedLines);
        return array_diff($this->linesToTaint, $this->scopedLines);
    }

    /**
     * @return int[]
     */
    public function getTaintedCallLines(): array
    {
        return $this->taintedCallLines;
    }

    /**
     * @return string[]
     */
    public function getTaintedFunctionNames(): array
    {
        return $this->taintedFunctionNames;
    }
}