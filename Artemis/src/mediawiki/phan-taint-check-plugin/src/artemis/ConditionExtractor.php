<?php
namespace Extract;

require_once 'vendor/autoload.php';

use PhpParser\Error;
use PhpParser\Node\Expr\BinaryOp\BooleanAnd;
use PhpParser\Node\Expr\BinaryOp\BooleanOr;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Expr\BinaryOp\Greater;
use PhpParser\Node\Expr\BinaryOp\GreaterOrEqual;
use PhpParser\Node\Expr\BinaryOp\Identical;
use PhpParser\Node\Expr\BinaryOp\LogicalAnd;
use PhpParser\Node\Expr\BinaryOp\LogicalOr;
use PhpParser\Node\Expr\BinaryOp\NotEqual;
use PhpParser\Node\Expr\BinaryOp\NotIdentical;
use PhpParser\Node\Expr\BinaryOp\Smaller;
use PhpParser\Node\Expr\BinaryOp\SmallerOrEqual;
use PhpParser\Node\Expr\BooleanNot;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Name;
use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter;
class ConditionExtractor extends NodeVisitorAbstract {

    /**
     * @var array{array{int,string}} $conditionPairs The line numbers to extract conditions from
     */
    private array $conditionPairs;

    /**
     * @var array{string} $extractedConditions The extracted conditions in source code
     */
    private $extractedConditions = [];

    /**
     * @var PrettyPrinter\Standard $prettyPrinter The pretty printer to convert nodes to source code
     */
    private $prettyPrinter;

    public function __construct($conditionPairs) {
        $this->conditionPairs = $conditionPairs;
        $this->prettyPrinter = new PrettyPrinter\Standard();
    }

    public function enterNode(Node $node) {
        $conditionPair = null;
        foreach ($this->conditionPairs as $pair) {
            if ($node->getLine() === $pair[0]) {
                $conditionPair = $pair;
                break;
            }
        }
        if (($node instanceof Node\Stmt\If_ || $node instanceof Node\Stmt\ElseIf_) && $conditionPair !== null) {
            if ($conditionPair[1] === 'else') {
                $node->cond = $this->negateCondition($node->cond);
            }
            $conditionSource = $this->prettyPrinter->prettyPrintExpr($node->cond);
            $this->extractedConditions[] = [
                "source" => $conditionSource,
                "line" => $conditionPair[0],
                "logic" => $conditionPair[1]
            ];
        }
    }

    /**
     * Get the extracted conditions in source code
     *
     * @return array{string} The extracted conditions in source code
     */
    public function getExtractedConditions(): array
    {
        return $this->extractedConditions;
    }

    private function negateCondition(Node\Expr $node) : Node\Expr {
        /*return match (true) {
            $node instanceof Greater => new SmallerOrEqual($node->left, $node->right),
            $node instanceof Smaller => new GreaterOrEqual($node->left, $node->right),
            $node instanceof GreaterOrEqual => new Smaller($node->left, $node->right),
            $node instanceof SmallerOrEqual => new Greater($node->left, $node->right),
            $node instanceof Equal => new NotEqual($node->left, $node->right),
            $node instanceof NotEqual => new Equal($node->left, $node->right),
            $node instanceof Identical => new NotIdentical($node->left, $node->right),
            $node instanceof NotIdentical => new Identical($node->left, $node->right),
            $node instanceof LogicalAnd => new LogicalOr($this->negateCondition($node->left), $this->negateCondition($node->right)),
            $node instanceof LogicalOr => new LogicalAnd($this->negateCondition($node->left), $this->negateCondition($node->right)),
            $node instanceof BooleanAnd => new BooleanOr($this->negateCondition($node->left), $this->negateCondition($node->right)),
            $node instanceof BooleanOr => new BooleanAnd($this->negateCondition($node->left), $this->negateCondition($node->right)),
            $node instanceof BooleanNot => $node->expr,
            $node instanceof ConstFetch => match (strtolower($node->name->toString())) {
                'true' => new ConstFetch(new Name('false')),
                'false' => new ConstFetch(new Name('true')),
                default => new BooleanNot($node),
            },
            default => new BooleanNot($node),
        };*/
        // Use PHP 7
        if ($node instanceof Greater) {
            return new SmallerOrEqual($node->left, $node->right);
        } elseif ($node instanceof Smaller) {
            return new GreaterOrEqual($node->left, $node->right);
        } elseif ($node instanceof GreaterOrEqual) {
            return new Smaller($node->left, $node->right);
        } elseif ($node instanceof SmallerOrEqual) {
            return new Greater($node->left, $node->right);
        } elseif ($node instanceof Equal) {
            return new NotEqual($node->left, $node->right);
        } elseif ($node instanceof NotEqual) {
            return new Equal($node->left, $node->right);
        } elseif ($node instanceof Identical) {
            return new NotIdentical($node->left, $node->right);
        } elseif ($node instanceof NotIdentical) {
            return new Identical($node->left, $node->right);
        } elseif ($node instanceof LogicalAnd) {
            return new LogicalOr($this->negateCondition($node->left), $this->negateCondition($node->right));
        } elseif ($node instanceof LogicalOr) {
            return new LogicalAnd($this->negateCondition($node->left), $this->negateCondition($node->right));
        } elseif ($node instanceof BooleanAnd) {
            return new BooleanOr($this->negateCondition($node->left), $this->negateCondition($node->right));
        } elseif ($node instanceof BooleanOr) {
            return new BooleanAnd($this->negateCondition($node->left), $this->negateCondition($node->right));
        } elseif ($node instanceof BooleanNot) {
            return $node->expr;
        } elseif ($node instanceof ConstFetch) {
            if (strtolower($node->name->toString()) === 'true') {
                return new ConstFetch(new Name('false'));
            } elseif (strtolower($node->name->toString()) === 'false') {
                return new ConstFetch(new Name('true'));
            } else {
                return new BooleanNot($node);
            }
        } else {
            return new BooleanNot($node);
        }
    }
}

// Usage
/*$code = file_get_contents('test.php');
$parser = (new ParserFactory)->createForNewestSupportedVersion();
try {
    $ast = $parser->parse($code);
    $traverser = new NodeTraverser;
    $conditionExtractor = new ConditionExtractor([3,6]);
    $traverser->addVisitor($conditionExtractor);
    $traverser->traverse($ast);

    $conditions = $conditionExtractor->getExtractedConditions();
    print_r($conditions); // Process or display the conditions
} catch (Error $error) {
    echo "Parse error: {$error->getMessage()}\n";
}*/
