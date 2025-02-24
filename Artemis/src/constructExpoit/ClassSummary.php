<?php

namespace Construct;

class ClassSummary
{
    public string $className;

    /**
     * @var array<string>
     */
    public array $methods = [];

    public function __toString()
    {
        $output = "Class: $this->className\n";
        foreach ($this->methods as $method) {
            $output .= "Method: $method\n";
        }
        return $output;
    }
}