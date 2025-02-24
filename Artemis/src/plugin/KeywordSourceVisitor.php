<?php

namespace PhanPlugin;
use ast\Node;
use Phan\AST\ContextNode;
use Phan\Exception\CodeBaseException;
use Phan\Exception\FQSENException;
use Phan\Exception\IssueException;
use Phan\Exception\NodeException;
use Phan\Exception\UnanalyzableException;
use Phan\Language\Element\FunctionInterface;
use Phan\PluginV3\PluginAwarePostAnalysisVisitor;

class KeywordSourceVisitor extends PluginAwarePostAnalysisVisitor
{
    private array $keywords = ['request', 'input', 'param'];

    public static array $resultSet = [];

    public function visitCall(Node $node): void
    {
        $expression = $node->children['expr'];
        $ctx = new ContextNode(
            $this->code_base,
            $this->context,
            $expression
        );
        $methods = $ctx->getFunctionFromNode();
        /** @var FunctionInterface $method */
        foreach ($methods as $method) {
            $functionName = $method->getFQSEN()->getName();
            $result = $this->checkName($functionName);
            if ($result) {
                // This function or method call matches one of the keywords.
                // Collect this information as needed.
                if (!array_key_exists($functionName, KeywordSourceVisitor::$resultSet)) {
                    KeywordSourceVisitor::$resultSet[$functionName] = "function";
                    //echo "Match found in function call: $functionName" . PHP_EOL;
                }
            }
        }
    }

    public function visitStaticCall(Node $node)
    {
        $class = $node->children['class'];
        // Make sure the class name is a string
        if (!($class instanceof Node && $class->kind === \ast\AST_NAME)) {
            return;
        }
        $className = $class->children['name'];

        // Make sure method name is a string
        $methodName = $node->children['method'];
        if (!is_string($methodName)) {
            return;
        }
        $ctx = new ContextNode(
            $this->code_base,
            $this->context,
            $class
        );
        try {
            $className = $ctx->getQualifiedName();
        } catch (FQSENException $e) {
            echo $e->getMessage() . PHP_EOL;
        }
        $result = $this->checkName($className) | $this->checkName($methodName);
        if ($result) {
            // This function or method call matches one of the keywords.
            // Collect this information as needed.
            $fullName = "$className::$methodName";
            if (!array_key_exists($fullName, KeywordSourceVisitor::$resultSet)) {
                KeywordSourceVisitor::$resultSet[$fullName] = "method";
                //echo "Match found in static call: $fullName" . PHP_EOL;
            }
        }
    }

    public function visitMethodCall(Node $node): void
    {
        $methodName = $node->children['method'];
        if (!is_string($methodName)) {
            return;
        }
        // Get the class name of the method call
        $ctx = new ContextNode(
            $this->code_base,
            $this->context,
            $node
        );
        try {
            $method = $ctx->getMethod($methodName, false, true);
            if (!$method->isPublic()) {
                return;
            }
            $fqsen = $method->getFQSEN()->__toString();
            $result = $this->checkName($fqsen);
            if ($result) {
                // This function or method call matches one of the keywords.
                // Collect this information as needed.
                if (!array_key_exists($fqsen, KeywordSourceVisitor::$resultSet)) {
                    KeywordSourceVisitor::$resultSet[$fqsen] = "method";
                    //echo "Match found in static call: $fullName" . PHP_EOL;
                }
            }
        } catch (CodeBaseException|IssueException|NodeException $e) {
        }
    }

    public function visitProp(Node $node)
    {
        $ctx = new ContextNode(
            $this->code_base,
            $this->context,
            $node
        );
        try {
            $property = $ctx->getProperty($node->kind === \ast\AST_STATIC_PROP);
            if (!$property->isPublic()) {
                return;
            }
            $fqsen = $property->getFQSEN()->__toString();
            $result = $this->checkName($fqsen);
            if ($result) {
                // This function or method call matches one of the keywords.
                // Collect this information as needed.
                if (!array_key_exists($fqsen, KeywordSourceVisitor::$resultSet)) {
                    KeywordSourceVisitor::$resultSet[$fqsen] = "property";
                }
            }
        } catch (IssueException|UnanalyzableException|NodeException $e) {
        }
    }

    private function checkName(string $name): bool
    {
        $excludeKeywords = ['exception', 'db', 'debug', 'session'];
        foreach ($this->keywords as $keyword) {
            foreach ($excludeKeywords as $exclude) {
                if (stripos($name, $exclude) !== false) {
                    return false;
                }
            }
            if (stripos($name, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }
}