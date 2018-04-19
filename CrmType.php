<?php
namespace NC\NcHobbyCrmservice\Lib\IFDConnect;

class Crmtype {

    public $value;
    public $key;
    public function __construct($key , $value) {
        $this->key = $key;
        $this->value = $value;
    }
}

?>
