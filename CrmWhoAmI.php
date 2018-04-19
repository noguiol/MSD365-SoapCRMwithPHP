<?php

function WhoAmI($authHeader, $url) {
	$xml = "<s:Body>";
	$xml .= "<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\">";
	$xml .= "<request i:type=\"c:WhoAmIRequest\" xmlns:b=\"http://schemas.microsoft.com/xrm/2011/Contracts\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:c=\"http://schemas.microsoft.com/crm/2011/Contracts\">";
	$xml .= "<b:Parameters xmlns:d=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\"/>";
	$xml .= "<b:RequestId i:nil=\"true\"/>";
	$xml .= "<b:RequestName>WhoAmI</b:RequestName>";
	$xml .= "</request>";
	$xml .= "</Execute>";
	$xml .= "</s:Body>";
	
	$executeSoap = new CrmExecuteSoap ();
	$response = $executeSoap->ExecuteSOAPRequest ( $authHeader, $xml, $url );
	$responsedom = new DomDocument ();
	$responsedom->loadXML ( $response );
	
	
	$values = $responsedom->getElementsbyTagName ( "KeyValuePairOfstringanyType" );
	
	
	foreach ( $values as $value ) {
		if ($value->firstChild->textContent == "UserId") {
			return $value->lastChild->textContent;
		}
	}
	return null;
}

?>