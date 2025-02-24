<?php

declare(strict_types=1);

/**
 * This file is part of PHP-CFG, a Control flow graph implementation for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPCfg\Op\Terminal;

use PHPCfg\Op\Terminal;
use PHPCfg\Operand;

class Throw_ extends Terminal
{
    public Operand $expr;

    public function __construct(Operand $expr, array $attributes = [])
    {
        parent::__construct($attributes);
        $this->expr = $this->addReadRef($expr);
    }

    public function getVariableNames(): array
    {
        return ['expr'];
    }

}
