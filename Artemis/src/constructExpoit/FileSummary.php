<?php
namespace Construct;
class FileSummary
{
    /**
     * @var string
     */
    public string $fileName;

    /**
     * @var array<ClassSummary>
     */
    public array $classes = [];


    /**
     * @var array<string>
     */
    public array $functions = [];

    public function __toString()
    {
        $output = "File: $this->fileName\n" . implode('', $this->classes);
        foreach ($this->functions as $function) {
            $output .= "Function: $function\n";
        }
        return $output;
    }

    public function isEmpty():bool
    {
        return empty($this->classes) && empty($this->functions);
    }

}

