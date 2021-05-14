<?php

namespace Blindnet\BlindnetSDKPHP\Exception;

use Exception;

class BlindnetException extends Exception {

    public function __construct($excMsg) {
        parent::__construct($excMsg, 0, null);
    }

    public function __toString() {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }
}

?>