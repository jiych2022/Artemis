<?php
namespace SecurityCheckPlugin;

use ast\Node;
use Phan\Exception\IssueException;
use Phan\Exception\NodeException;
use Phan\Language\Element\FunctionInterface;
use Phan\Language\FQSEN\FullyQualifiedFunctionLikeName;
use const ast\AST_CONST;

class SSrfVisitor extends TaintednessVisitor
{
    public function handleMethodCall(FunctionInterface $func, FullyQualifiedFunctionLikeName $funcName, array $args, bool $computePreserve = true, $isHookHandler = false): ?TaintednessWithError
    {
        if ($funcName->getName() === "fopen") {
            if ($this->isFopenSafe($args)) {
                return TaintednessWithError::newEmpty();
            }
        }
        if ($funcName->getName() === "curl_setopt") {
            try {
                $this->handleCurlSetOpt($args);
            } catch (IssueException|NodeException $e) {
            }
        }
        if ($funcName->getName() === 'curl_setopt_array') {
            try {
                $this->handleCurlSetOptArray($args);
            } catch (IssueException|NodeException $e) {
            }
        }
        if ($funcName->getName() === 'preg_match_all') {
            $this->handlePregMatchAll($args);
        }
        $ret = parent::handleMethodCall($func, $funcName, $args, $computePreserve, $isHookHandler);
        if ($funcName->getName() == "curl_init") {
            // Skip check when no argument
            if (count($args) == 0) {
                return $ret;
            }
            $url = $args[0];
            if ($url instanceof Node) {$ret->mergeWith($this->getTaintednessNode($url));}
        }
        return $ret;
    }

    private function handlePregMatchAll(array $args) {
        if (count($args) < 3) {
            return;
        }
        $subject = $args[1];
        $output = $args[2];
        if ($subject instanceof Node) {
            $subjectTaint = $this->getTaintednessNode($subject);
            if ($output instanceof Node) {
                $outputTaint = $this->getTaintednessNode($output);
                // Output taint is treated as array with subject
                $outputTaintedness = Taintedness::newFromArray([$subjectTaint->getTaintedness(), $subjectTaint->getTaintedness()]);
                $outputError = $outputTaint->getError()->asMergedWith($subjectTaint->getError());
                $outputMethodLinks = $subjectTaint->getMethodLinks()->asMaybeMovedAtOffset(1);
                try {
                    $element = $this->getCtxN($output)->getVariable();
                } catch (IssueException|NodeException $e) {
                  return;
                }
                self::setTaintednessRaw($element, $outputTaintedness);
                self::setCausedByRaw($element, $outputError);
                self::setMethodLinks($element, $outputMethodLinks);
            }
        }
    }

    private function isFopenSafe(array $args) : bool {
        if (count($args) < 2) {
            return false;
        }
        $mode = $args[1];
        if (!is_string($mode)) {
            return false;
        }
        if (strpos($mode, 'w') !== false || strpos($mode, 'a') !== false) {
            return true;
        }
        return false;
    }

    private function handleCurlSetOpt(array $args)
    {
        $ch = $args[0];
        $opt = $args[1];
        $url = $args[2];
        if ($opt instanceof Node) {
            if ($opt->kind === AST_CONST) {
                $optName = $opt->children['name']->children['name'];
                if ($optName === "CURLOPT_URL") {
                    if (!$url instanceof Node) {
                        return;
                    }
                    $urlTaintNode = $this->getTaintednessNode($url);

                    $urlTaint = $urlTaintNode->getTaintedness();
                    $chNode = $this->getTaintednessNode($ch);
                    //$chTaint = $chNode->getTaintedness();
                    $chNode->mergeWith($urlTaintNode);

                    $realCh = $this->getCtxN($ch)->getVariable();
                    /*$realChTaintNode = $this->getTaintednessNode($realCh);
                    $realChTaintNode->mergeWith($urlTaintNode);*/
                    self::setTaintednessRaw($realCh, $chNode->getTaintedness());
                    self::setCausedByRaw($realCh, $chNode->getError());
                    self::setMethodLinks($realCh, $chNode->getMethodLinks());
                    /*                        $chTaint->add($urlTaint->get());
                                            self::setTaintednessRaw($this->getCtxN($ch)->getVariable(), $chTaint);*/
                }
            }
        }
    }

    private function handleCurlSetOptArray(array $args)
    {
        if (count($args) < 2) {
            return;
        }
        $optArray = $args[1];
        if ($optArray instanceof Node) {
            $optArrayTaint = $this->getTaintednessNode($optArray);
            $urlTaint = $optArrayTaint->getTaintedness()->getTaintednessForOffsetOrWhole(CURLOPT_URL);
            // Set array taint as if only [CURLOPT_URL=>$url]
            $optArrayVar = $this->getCtxN($optArray)->getVariable();

            self::setTaintednessRaw($optArrayVar, Taintedness::newFromArray([CURLOPT_URL=>$urlTaint]));
            self::setCausedByRaw($optArrayVar, $optArrayTaint->getError());
            $urlLinks = $optArrayTaint->getMethodLinks()->getForDim(CURLOPT_URL);
            $newLinks = MethodLinks::newEmpty();
            $newLinks->mergeWith($urlLinks);
            self::setMethodLinks($optArrayVar, $newLinks);
        }
    }
}