<?php

declare(strict_types=1);

/**
 * This file is part of PHP-CFG, a Control flow graph implementation for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPCfg\Op\Expr;

use PHPCfg\Op\Expr;
use PhpCfg\Operand;

class PropertyFetch extends Expr
{
    public Operand$var;

    public Operand$name;

    public function __construct(Operand $var, Operand $name, array $attributes = [])
    {
        parent::__construct($attributes);
        $this->var = $this->addReadRef($var);
        $this->name = $this->addReadRef($name);
    }

    public function getVariableNames(): array
    {
        return ['var', 'name', 'result'];
    }
}
