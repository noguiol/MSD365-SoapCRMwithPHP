<?php

function CrmGetUserName($authHeader, $id, $url) {
	$xml = "<s:Body>";
	$xml .= "<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">";
	$xml .= "<request i:type=\"a:RetrieveRequest\" xmlns:a=\"http://schemas.microsoft.com/xrm/2011/Contracts\">";
	$xml .= "<a:Parameters xmlns:b=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">";
	$xml .= "<a:KeyValuePairOfstringanyType>";
	$xml .= "<b:key>Target</b:key>";
	$xml .= "<b:value i:type=\"a:EntityReference\">";
	$xml .= "<a:Id>" . $id . "</a:Id>";
	$xml .= "<a:LogicalName>systemuser</a:LogicalName>";
	$xml .= "<a:Name i:nil=\"true\" />";
	$xml .= "</b:value>";
	$xml .= "</a:KeyValuePairOfstringanyType>";
	$xml .= "<a:KeyValuePairOfstringanyType>";
	$xml .= "<b:key>ColumnSet</b:key>";
	$xml .= "<b:value i:type=\"a:ColumnSet\">";
	$xml .= "<a:AllColumns>false</a:AllColumns>";
	$xml .= "<a:Columns xmlns:c=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">";
	$xml .= "<c:string>firstname</c:string>";
	$xml .= "<c:string>lastname</c:string>";
	$xml .= "</a:Columns>";
	$xml .= "</b:value>";
	$xml .= "</a:KeyValuePairOfstringanyType>";
	$xml .= "</a:Parameters>";
	$xml .= "<a:RequestId i:nil=\"true\" />";
	$xml .= "<a:RequestName>Retrieve</a:RequestName>";
	$xml .= "</request>";
	$xml .= "</Execute>"; 
	$xml .= "</s:Body>";
	
	$executeSoap = new CrmExecuteSoap ();
	
	$response = $executeSoap->ExecuteSOAPRequest ( $authHeader, $xml, $url );
	
	$responsedom = new DomDocument ();
	$responsedom->loadXML ( $response );
	
	$firstname = "";
	$lastname = "";
	
	$values = $responsedom->getElementsbyTagName ( "KeyValuePairOfstringanyType" );
	
	foreach ( $values as $value ) {
		if ($value->firstChild->textContent == "firstname") {
			$firstname = $value->lastChild->textContent;
		}
		
		if ($value->firstChild->textContent == "lastname") {
			$lastname = $value->lastChild->textContent;
		}
	}
	
	return $firstname . " " . $lastname;
}
?>