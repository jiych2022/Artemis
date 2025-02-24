<?php
namespace Construct;
class TraceParser
{
    private $calledFunctions = [];

    private $lines = [];

    public function parse(string $traceFile)
    {
        $handle = fopen($traceFile, 'r');

        if (!$handle) {
            throw new Exception('Unable to open the trace file.');
        }

        while (($line = fgets($handle)) !== false) {
            $this->processLine($line);
        }
        $this->calledFunctions = array_unique($this->calledFunctions);
        $this->lines = array_unique($this->lines);

        fclose($handle);
    }

    private function processLine(string $line)
    {
        $parts = explode("\t", $line);

        if (count($parts) < 5) {
            return;
        }

        $recordType = $parts[2];

        if ($recordType === '0') {
            $functionName = $parts[5];
            $fileName = $parts[8];
            $lineNo = $parts[9];

            $this->lines[] = "$fileName: $lineNo";
            $this->calledFunctions[] = $functionName;
        }
    }

    public function callInTrace(string $functionName): bool
    {
        return in_array($functionName, $this->calledFunctions);
    }

    public function lineInTrace(string $line): bool
    {
        return in_array($line, $this->lines);
    }
}

/*$traceParser = new TraceParser();
$traceParser->parse('/home/jiych1/PhpstormProjects/fp-check/green/icms2/trace.2450497807.xt');
$functionName = 'cmsUploader->uploadFromLink';
$line = '/opt/lampp/htdocs/system/core/uploader.php: 334';
if ($traceParser->callInTrace($functionName)) {
    echo "Function $functionName called in trace\n";
} else {
    echo "Function $functionName not called in trace\n";
}

if ($traceParser->lineInTrace($line)) {
    echo "Line $line called in trace\n";
} else {
    echo "Line $line not called in trace\n";
}*/