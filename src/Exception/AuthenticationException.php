<?php

namespace Blindnet\BlindnetSDKPHP\Exception;

use Exception;

class AuthenticationException extends Exception {

    public function __construct() {
        parent::__construct('Failed authenitcation to blindnet. Make sure you are using the correct application key and application id.', 0, null);
    }

    public function __toString() {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }
}

?>