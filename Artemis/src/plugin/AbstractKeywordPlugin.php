<?php

namespace PhanPlugin;
use Phan\CodeBase;
use Phan\Exception\CodeBaseException;
use Phan\Exception\FQSENException;
use Phan\Language\Element\Method;
use Phan\Language\FQSEN\FullyQualifiedClassName;
use Phan\PluginV3;


abstract class AbstractKeywordPlugin extends PluginV3
    implements PluginV3\PostAnalyzeNodeCapability,
    PluginV3\FinalizeProcessCapability,
    PluginV3\AnalyzeMethodCapability
{

    use HelperTrait;
    abstract public static function getPostAnalyzeNodeVisitorClassName(): string;

    abstract public function finalizeProcess(CodeBase $code_base): void;

    abstract public function queryGPT(string $name, string $comment, array $pairs) : bool;

    public function getFinalResults(array $finalResults, string $resultFileName): void
    {
        $printPredicate = function () {
            return false;
        };
        $count = 0;
        $content = "";
        foreach ($finalResults as $name => $comment) {
//            if (!empty($comment)) {
//                // Clean up doc comments by removing the leading /** and trailing */ as well as * from each line, also trim whitespace
//                $comment = trim(preg_replace('/\s*\*\s*/', '', preg_replace('/^\/\*\*|\*\/$/', '', $comment)));
//            }
//            else {
//                $comment = "";
//            }
            if (!$this->queryGPT($name, $comment, [])) {
                // echo "skip $name\n";
                continue;
            }
            $this->conditionalPrint("Name: $name" . PHP_EOL, $printPredicate );
            $this->conditionalPrint("Comment: $comment" . PHP_EOL,$printPredicate );
            $this->conditionalPrint( "-----------------------------------" . PHP_EOL,$printPredicate );
            $count++;
            //$content .= "Name: $name\nComment: $comment\n";
            $content .= "Name: $name\n";
        }
        $this->conditionalPrint("Found $count matches" . PHP_EOL,$printPredicate );
        //file_put_contents($resultFileName, $content);
        echo $content;
    }

    public function analyzeMethod(
        CodeBase $code_base,
        Method $method
    ): void {
        $docComment = $method->getDocComment();
        $depth = 0;
        // When this method does not have doc comment, or it has doc comment and has an inheritdoc tag
        $shouldProcess = empty($docComment) || (stripos($docComment, '@inheritdoc') !== false);
        while ($shouldProcess && $depth < 3) {
            // Method is not defined in this class, but in a parent class or trait
            if (empty($docComment)) {
                try {
                    $realDocComment = $method->getDefiningClass($code_base)->getMethodByName($code_base, $method->getName())->getDocComment();
                    $method->setDocComment($realDocComment);
                } catch (CodeBaseException $e) {
                }
            }
            $docComment = $method->getDocComment();
            $parentMethod = $this->getParentMethod($code_base, $method);
            $interfaceMethod = $this->getInterfaceMethod($code_base, $method);
            $realMethod = $parentMethod ?? $interfaceMethod;
            if ($realMethod) {
                $realDocComment = $realMethod->getDocComment();
                if ($realDocComment) {
                    $new_doc_comment = empty($docComment) ? $realDocComment : str_ireplace('@inheritdoc', $realDocComment, $docComment);
                    $method->setDocComment($new_doc_comment);
                    $depth++;
                }
                else {
                    break;
                }
            }
            else {
                break;
            }
        }
    }

    private function getParentMethod(CodeBase $code_base, Method $method): ?Method
    {
        $printPredicate = function () use ($method) {
            return false;
        };
        try {
            $parent_type_option = $method->getDefiningClass($code_base)->getParentTypeOption();
        } catch (CodeBaseException $e) {
            $this->conditionalPrint("Exception {$e->getMessage()}" . PHP_EOL, $printPredicate);
            return null;
        }
        if ($parent_type_option->isDefined()) {
            $parent_fqsen = $parent_type_option->get()->asFQSENString();
            try {
                $parent_fqsen = FullyQualifiedClassName::fromFullyQualifiedString($parent_fqsen);
                if ($code_base->hasClassWithFQSEN($parent_fqsen)) {
                    $parent_class = $code_base->getClassByFQSEN($parent_fqsen);
                    if ($parent_class->hasMethodWithName($code_base, $method->getName())) {
                        try {
                            return $parent_class->getMethodByName($code_base, $method->getName());
                        } catch (CodeBaseException $e) {
                            return null;
                        }
                    }
                    else {
                        $this->conditionalPrint("Parent class {$parent_class->getFQSEN()} does not have method {$method->getName()}" . PHP_EOL, $printPredicate);
                    }
                }
                else {
                    $this->conditionalPrint("Parent class not found for method {$method->getFQSEN()}" . PHP_EOL, $printPredicate);
                }
            } catch (FQSENException $e) {
                return null;
            }
        }
        else {
            $this->conditionalPrint("Parent type not defined for method {$method->getFQSEN()}" . PHP_EOL, $printPredicate);
        }
        return null;
    }

    private function getInterfaceMethod(CodeBase $codeBase, Method $method): ?Method
    {
        $printPredicate = function () use ($method) {
            return false;
        };
        try {
            $class = $method->getDefiningClass($codeBase);
        } catch (CodeBaseException $e) {
            return null;
        }
        $interfaces = $class->getInterfaceFQSENList();
        /** @var FullyQualifiedClassName $interface */
        foreach ($interfaces as $interface) {
            if ($codeBase->hasClassWithFQSEN($interface)) {
                $interface = $codeBase->getClassByFQSEN($interface);
                if ($interface->hasMethodWithName($codeBase, $method->getName())) {
                    try {
                        return $interface->getMethodByName($codeBase, $method->getName());
                    } catch (CodeBaseException $e) {
                        return null;
                    }
                }
                else {
                    $this->conditionalPrint("Interface {$interface->getFQSEN()} does not have method {$method->getName()}" . PHP_EOL, $printPredicate);
                }
            }
            else {
                $this->conditionalPrint("Interface not found for method {$method->getFQSEN()}" . PHP_EOL, $printPredicate);
            }
        }
        return null;
    }
}

