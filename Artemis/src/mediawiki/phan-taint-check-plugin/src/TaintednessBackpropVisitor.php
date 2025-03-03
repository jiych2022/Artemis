<?php

namespace SecurityCheckPlugin;

use ast\Node;
use Exception;
use Phan\CodeBase;
use Phan\Exception\CodeBaseException;
use Phan\Exception\FQSENException;
use Phan\Exception\IssueException;
use Phan\Exception\NodeException;
use Phan\Language\Context;
use Phan\Language\Element\TypedElementInterface;
use Phan\Language\Element\Variable;
use Phan\PluginV3\PluginAwareBaseAnalysisVisitor;

class TaintednessBackpropVisitor extends PluginAwareBaseAnalysisVisitor {
	use TaintednessBaseVisitor;

	/** @var Taintedness */
	private $taintedness;

	/** @var CausedByLines|null */
	private $additionalError;

	/**
	 * @inheritDoc
	 * @param Taintedness $taintedness
	 * @param CausedByLines|null $additionalError
	 */
	public function __construct(
		CodeBase $code_base,
		Context $context,
		Taintedness $taintedness,
		CausedByLines $additionalError = null
	) {
		parent::__construct( $code_base, $context );
		$this->taintedness = $taintedness;
		$this->additionalError = $additionalError;
	}

	/**
	 * @inheritDoc
	 */
	public function visitProp( Node $node ): void {
        $el = $this->getPropFromNode($node);
        if (isset($node->safePath) && $node->safePath) {
            if ($el !== null) {
                $el->safePath = true;
            }
        }
		$this->doBackpropElements( $el );
	}

	/**
	 * @inheritDoc
	 */
	public function visitNullsafeProp( Node $node ): void {
		$this->doBackpropElements( $this->getPropFromNode( $node ) );
	}

	/**
	 * @inheritDoc
	 */
	public function visitStaticProp( Node $node ): void {
		$this->doBackpropElements( $this->getPropFromNode( $node ) );
	}

	/**
	 * @inheritDoc
	 */
	public function visitVar( Node $node ): void {
		$cn = $this->getCtxN( $node );
		if ( Variable::isHardcodedGlobalVariableWithName( $cn->getVariableName() ) ) {
			return;
		}

		try {
            $el = $cn->getVariable();
            if (isset($node->safePath) && $node->safePath) {
                $el->safePath = true;
            }
			$this->doBackpropElements( $el);
		} catch ( NodeException | IssueException $e ) {
			$this->debug( __METHOD__, "variable not in scope?? " . $this->getDebugInfo( $e ) );
            // Check if prefix of variable name is in extract, prefix is in the form of xxx_
            $varName = $cn->getVariableName();
            if (stripos($varName, '_') !== false) {
                $prefix = substr($varName, 0, strpos($varName, '_'));
            }
            else {
                $prefix = '[No prefix]';
            }
            $this->debug( __METHOD__, "Extract handling for $varName, prefix is $prefix" );
            if (isset(PreTaintednessVisitor::$extract[$prefix])) {
                try {
                    $this->doBackpropElements(PreTaintednessVisitor::$extract[$prefix]);
                    return;
                }
                catch ( NodeException | IssueException $e ) {
                    $this->debug( __METHOD__, "Extract handling fail " . $this->getDebugInfo( $e ) );
                }
            }
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitEncapsList( Node $node ): void {
		foreach ( $node->children as $child ) {
			if ( !is_object( $child ) ) {
				continue;
			}
			$this->recurse( $child );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitArray( Node $node ): void {
		foreach ( $node->children as $child ) {
			if ( !is_object( $child ) ) {
				continue;
			}
			$this->recurse( $child );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitArrayElem( Node $node ): void {
		$key = $node->children['key'];
		if ( $key instanceof Node ) {
			$this->recurse( $key, $this->taintedness->asKeyForForeach() );
		}
		$value = $node->children['value'];
		if ( $value instanceof Node ) {
			$this->recurse( $value, $this->taintedness->getTaintednessForOffsetOrWhole( $key ) );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitCast( Node $node ): void {
		// Future todo might be to ignore casts to ints, since
		// such things should be safe. Unclear if that makes
		// sense in all circumstances.
		if ( $node->children['expr'] instanceof Node ) {
			$this->recurse( $node->children['expr'] );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitDim( Node $node ): void {
		if ( $node->children['expr'] instanceof Node ) {
			// For now just consider the outermost array.
			// FIXME. doesn't handle tainted array keys!
			$offs = $node->children['dim'];
            if (is_string($offs) && $offs === "tmp_name") {
                return;
            }
			$realOffs = $offs !== null ? $this->resolveOffset( $offs ) : null;
			$this->recurse( $node->children['expr'], $this->taintedness->asMaybeMovedAtOffset( $realOffs ) );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitUnaryOp( Node $node ): void {
		if ( $node->children['expr'] instanceof Node ) {
			$this->recurse( $node->children['expr'] );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitBinaryOp( Node $node ): void {
		if ( $node->children['left'] instanceof Node ) {
            $node->children['left']->safePath = true;
			$this->recurse( $node->children['left'] );
		}
		if ( $node->children['right'] instanceof Node ) {
            $node->children['right']->safePath = true;
			$this->recurse( $node->children['right'] );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitConditional( Node $node ): void {
		if ( $node->children['true'] instanceof Node ) {
			$this->recurse( $node->children['true'] );
		}
		if ( $node->children['false'] instanceof Node ) {
			$this->recurse( $node->children['false'] );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function visitCall( Node $node ): void {
		$this->handleCall( $node );
	}

	/**
	 * @inheritDoc
	 */
	public function visitMethodCall( Node $node ): void {
		$this->handleCall( $node );
	}

	/**
	 * @inheritDoc
	 */
	public function visitStaticCall( Node $node ): void {
		$this->handleCall( $node );
	}

	/**
	 * @inheritDoc
	 */
	public function visitNullsafeMethodCall( Node $node ): void {
		$this->handleCall( $node );
	}

	/**
	 * @param Node $node
	 */
	private function handleCall( Node $node ): void {
		$ctxNode = $this->getCtxN( $node );
		// @todo Future todo might be to still return arguments when catching an exception.
		if ( $node->kind === \ast\AST_CALL ) {
			if ( $node->children['expr']->kind !== \ast\AST_NAME ) {
				// TODO Handle this case!
				return;
			}
			try {
				$func = $ctxNode->getFunction( $node->children['expr']->children['name'] );
			} catch ( IssueException | FQSENException $e ) {
				$this->debug( __METHOD__, "FIXME func not found: " . $this->getDebugInfo( $e ) );
				return;
			}
		} else {
			$methodName = $node->children['method'];
			try {
				$func = $ctxNode->getMethod( $methodName, $node->kind === \ast\AST_STATIC_CALL, true );
                $this->debug( __METHOD__, "Handling call $methodName" );
			} catch ( NodeException | CodeBaseException | IssueException $e ) {
				$this->debug( __METHOD__, "FIXME method not found: " . $this->getDebugInfo( $e ) );
				return;
			}
		}
		// intentionally resetting options to []
		// here to ensure we don't recurse beyond
		// a depth of 1.
		try {
			$retObjs = $this->getReturnObjsOfFunc( $func );
		} catch ( Exception $e ) {
			$this->debug( __METHOD__, "FIXME: " . $this->getDebugInfo( $e ) );
			return;
		}
		$this->doBackpropElements( ...$retObjs );
	}

	/**
	 * @inheritDoc
	 */
	public function visitPreDec( Node $node ): void {
		$this->handleIncOrDec( $node );
	}

	/**
	 * @inheritDoc
	 */
	public function visitPreInc( Node $node ): void {
		$this->handleIncOrDec( $node );
	}

	/**
	 * @inheritDoc
	 */
	public function visitPostDec( Node $node ): void {
		$this->handleIncOrDec( $node );
	}

	/**
	 * @inheritDoc
	 */
	public function visitPostInc( Node $node ): void {
		$this->handleIncOrDec( $node );
	}

	/**
	 * @param Node $node
	 */
	private function handleIncOrDec( Node $node ): void {
		$children = $node->children;
		assert( count( $children ) === 1 );
		$this->recurse( reset( $children ) );
	}

	/**
	 * Wrapper for __invoke. Allows changing the taintedness before recursing, and restoring later.
	 *
	 * @param Node $node
	 * @param Taintedness|null $taint
	 */
	private function recurse( Node $node, Taintedness $taint = null ): void {
		if ( !$taint ) {
			$this( $node );
			return;
		}
		$oldTaint = $this->taintedness;
		$this->taintedness = $taint;
		try {
			$this( $node );
		} finally {
			$this->taintedness = $oldTaint;
		}
	}

	/**
	 * @param TypedElementInterface|null ...$elements
	 */
	private function doBackpropElements( ?TypedElementInterface ...$elements ): void {
		foreach ( array_unique( array_filter( $elements ) ) as $el ) {
			$this->markAllDependentMethodsExec( $el, $this->taintedness, $this->additionalError );
		}
	}
}
