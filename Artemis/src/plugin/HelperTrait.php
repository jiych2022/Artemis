<?php

namespace PhanPlugin;
trait HelperTrait
{
    public function conditionalPrint(string $message, \Closure $predicate): void
    {
        if ($predicate()) {
            echo $message . PHP_EOL;
        }
    }
}