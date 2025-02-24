<?php

declare(strict_types=1);

/**
 * This file is part of PHP-CFG, a Control flow graph implementation for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPCfg;

use PHPCfg\Op\Expr\Eval_;
use PHPCfg\Op\Expr\FuncCall;
use PHPCfg\Op\Expr\Include_;
use PHPCfg\Op\Expr\InstanceOf_;
use PHPCfg\Op\Expr\MethodCall;
use PHPCfg\Op\Expr\New_;
use PHPCfg\Op\Expr\NsFuncCall;
use PHPCfg\Op\Expr\StaticCall;
use PHPCfg\Op\Expr\StaticPropertyFetch;

class Block
{
    /** @var Op[] */
    public $children = [];

    /** @var Block[] */
    public $parents = [];

    /** @var Op\Phi[] */
    public $phi = [];

    public $dead = false;

    /** @var int */
    public int $start_line;

    /** @var int */
    public int $end_line;

    /** @var bool Flag that represents if the block points to other blocks (e.g., function calls, includes, callbacks, etc.) */
    public bool $expandable = false;

    /** @var int Calculated weight of the block based on its expansions and reaching potential */
    public int $weight = 0;

    /**
     * @var int The id of the block
     * */
    public int $id;

    static int $idCounter = 0;

    public function __construct(self $parent = null)
    {
        if ($parent) {
            $this->parents[] = $parent;
        }
        $this->id = self::$idCounter;
        self::$idCounter++;
    }

    public function create()
    {
        return new static();
    }

    public static function ResetIdCounter(): void
    {
        self::$idCounter = 0;
    }

    public function addParent(self $parent)
    {
        if (! in_array($parent, $this->parents, true)) {
            $this->parents[] = $parent;
        }
    }

    public function addChild(Op $child) {
        list($start_line, $end_line) = $child->getLines();
        // Assumes the sequential traversal of Block Ops
        if (!isset($this->start_line) && $start_line > 0) {
            $this->start_line = $start_line;
        }
        if ($end_line > 0) {
            $this->end_line = $end_line;
        }

        if (Op::isExpandable($child)) {
            $this->expandable = true;
        }
        $child_weight = $this->get_weight($child);
        $this->weight += $child_weight;

        $this->children[] = $child;
    }

    protected function get_weight(Op $op) {
        // Check for expandable Ops and calculate the weight
        $weight = 1;
        if (Op::isExpandable($op)) {
            $weight = Op::$expandable_ops[get_class($op)];
        }
        return $weight;
    }

}
