<?php
class CrmEntityReference extends CrmType {
	
	public $entityName;
	public function __construct($key , $value, $entity) {
		$this->key = $key;
		$this->value = $value;
		$this->entityName = $entity;
		
	}
	
}
?>