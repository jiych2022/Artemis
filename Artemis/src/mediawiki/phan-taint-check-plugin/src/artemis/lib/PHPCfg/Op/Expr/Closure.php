<?php

declare(strict_types=1);

/**
 * This file is part of PHP-CFG, a Control flow graph implementation for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPCfg\Op\Expr;

use PHPCfg\Func;
use PHPCfg\Op\CallableOp;
use PHPCfg\Op\Expr;

class Closure extends Expr implements CallableOp
{
    public Func $func;

    public array $useVars;

    public function __construct(Func $func, array $useVars, array $attributes = [])
    {
        parent::__construct($attributes);
        $this->func = $func;
        $this->useVars = $this->addReadRefs(...$useVars);
    }

    public function getVariableNames(): array
    {
        return ['useVars', 'result'];
    }

    public function getFunc(): Func {
        return $this->func;
    }
}
