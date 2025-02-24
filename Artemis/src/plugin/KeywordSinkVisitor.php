<?php

namespace PhanPlugin;
use ast\Node;
use Phan\AST\ContextNode;
use Phan\Exception\CodeBaseException;
use Phan\Exception\FQSENException;
use Phan\Exception\IssueException;
use Phan\Exception\NodeException;
use Phan\Language\Element\FunctionInterface;
use Phan\Language\Element\Parameter;
use Phan\PluginV3\PluginAwarePostAnalysisVisitor;

class KeywordSinkVisitor extends PluginAwarePostAnalysisVisitor
{
    use HelperTrait;
    private $sinkKeywords = ['request', 'client', 'curl', 'download', 'remote', 'file'];

    private $sinkArgKeywords = ['url', 'host', 'uri'];

    public static array $resultSet = [];

    private function isBuiltin(string $functionName) : bool {
        return stripos($functionName, 'curl_') !== false;
    }

    private function checkSinkName(string $name): bool
    {
        foreach ($this->sinkKeywords as $keyword) {
            if (stripos($name, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    private function checkSinkArgName(string $name): bool
    {
        foreach ($this->sinkArgKeywords as $keyword) {
            if (stripos($name, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    public function visitCall(Node $node)
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
            if ($this->isBuiltin($functionName)) {
                return;
            }
            $result = false;
            // Get function argument names
            $argNames = $method->getParameterList();
            /** @var Parameter $argName */
            foreach ($argNames as $argName) {
                $result |= $this->checkSinkArgName($argName->getName());
            }

            $result &= $this->checkSinkName($functionName);
            if ($result) {
                // This function or method call matches one of the keywords.
                // Collect this information as needed.
                if (!array_key_exists($functionName, KeywordSinkVisitor::$resultSet)) {
                    KeywordSinkVisitor::$resultSet[$functionName] = "function";
                }
            }
        }
    }

    public function visitMethodCall(Node $node)
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
            $methodName = $method->getFQSEN()->__toString();
            $result = false;
            // Get function argument names
            $argNames = $method->getParameterList();
            /** @var Parameter $argName */
            foreach ($argNames as $argName) {
                $result |= $this->checkSinkArgName($argName->getName());
            }
            $argNames = $method->getRealParameterList();
            /** @var Parameter $argName */
            foreach ($argNames as $argName) {
                $result |= $this->checkSinkArgName($argName->getName());
            }

            $result &= $this->checkSinkName($methodName);
            if ($result) {
                // This function or method call matches one of the keywords.
                // Collect this information as needed.
                if (!array_key_exists($methodName, KeywordSinkVisitor::$resultSet)) {
                    KeywordSinkVisitor::$resultSet[$methodName] = "method";
                }
            }
        } catch (CodeBaseException|IssueException|NodeException $e) {
        }
    }

    public function visitStaticCall(Node $node)
    {
        $class = $node->children['class'];
        // Make sure the class name is a string
        if (!($class instanceof Node && $class->kind === \ast\AST_NAME)) {
            return;
        }
        // Make sure method name is a string
        $methodName = $node->children['method'];
        if (!is_string($methodName)) {
            return;
        }
        $ctx = new ContextNode(
            $this->code_base,
            $this->context,
            $node
        );
        try {
            $method = $ctx->getMethod($methodName, true, true);
            $methodName = $method->getFQSEN()->__toString();
        } catch (CodeBaseException|IssueException|NodeException|FQSENException $e) {
            return;
        }
        $result = false;
        // Get function argument names
        $argNames = $method->getParameterList();
        /** @var Parameter $argName */
        foreach ($argNames as $argName) {
            $result |= $this->checkSinkArgName($argName->getName());
        }
        // Get actual argument names
        $args = $node->children['args']->children;
        foreach ($args as $arg) {
            if ($arg instanceof Node && $arg->kind === \ast\AST_VAR) {
                $argName = $arg->children['name'];
                if (is_string($argName)) {
                    $result |= $this->checkSinkArgName($argName);
                }
            }
        }

        $result &= $this->checkSinkName($methodName);

        if ($result) {
            // This function or method call matches one of the keywords.
            // Collect this information as needed.
            if (!array_key_exists($methodName, KeywordSinkVisitor::$resultSet)) {
                KeywordSinkVisitor::$resultSet[$methodName] = "method";
                //echo "Match found in static call: $fullName" . PHP_EOL;
            }
        }
    }

    public function visitNew(Node $node)
    {
        $ctxNode = new ContextNode(
            $this->code_base,
            $this->context,
            $node
        );

        if (!$node->children['class'] instanceof Node) {
            // Syntax error, don't crash
            return;
        }

        try {
            // Get __construct()
            $constructor = $ctxNode->getMethod(
                '__construct',
                false,
                false,
                true
            );
        } catch (NodeException|CodeBaseException|IssueException $_) {
            return;
        }
        $methodName = $constructor->getFQSEN()->__toString();
        $result = false;
        // Get function argument names
        $argNames = $constructor->getParameterList();
        /** @var Parameter $argName */
        foreach ($argNames as $argName) {
            $result |= $this->checkSinkArgName($argName->getName());
        }

        $result &= $this->checkSinkName($methodName);
        if ($result) {
            // This function or method call matches one of the keywords.
            // Collect this information as needed.
            if (!array_key_exists($methodName, KeywordSinkVisitor::$resultSet)) {
                KeywordSinkVisitor::$resultSet[$methodName] = "method";
            }

        }
    }
}