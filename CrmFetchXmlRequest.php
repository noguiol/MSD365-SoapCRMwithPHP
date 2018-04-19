<?php

function fetchXmlRequest($fetchXml,$authHeader,$url) {

	$fetchXmlDoc = simplexml_load_string($fetchXml);

	if(!isset($fetchXmlDoc->attributes()['page']))  {
		$fetchXmlDoc->addAttribute("page","1");
	}

	$xml  = "<s:Body>";
	$xml .= "<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\">";
	$xml .= "<request i:type=\"c:ExecuteFetchRequest\" xmlns:b=\"http://schemas.microsoft.com/xrm/2011/Contracts\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:c=\"http://schemas.microsoft.com/crm/2011/Contracts\">";
	$xml .= "<b:Parameters xmlns:d=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">";
	$xml .= "<b:KeyValuePairOfstringanyType>";
	$xml .= "<d:key>FetchXml</d:key>";
	$xml .= "<d:value i:type=\"e:string\" xmlns:e=\"http://www.w3.org/2001/XMLSchema\">";
	$xml .= htmlentities($fetchXmlDoc->asXML());   
	$xml .= "</d:value>";
	$xml .= "</b:KeyValuePairOfstringanyType>";
	$xml .= "</b:Parameters><b:RequestId i:nil=\"true\"/>";
	$xml .= "<b:RequestName>ExecuteFetch</b:RequestName>";
	$xml .= "</request>";
	$xml .= "</Execute>";
	$xml .= "</s:Body>";
		
	$executeSoap = new CrmExecuteSoap ();
	
	$response = $executeSoap->ExecuteSOAPRequest ( $authHeader, $xml, $url );
	
	$responsedom = new DomDocument ();
	$responsedom->loadXML ( $response );
	$results = $responsedom->getElementsbyTagName("value");	
    $resultXml = $results->item(0)->nodeValue;
    
   	$xml = simplexml_load_string($resultXml);
	$page = $fetchXmlDoc['page'];
	
	if($xml['morerecords'] == 1) {
		$fetchXmlDoc['page'] = $page+1;
		if(!isset($fetchXmlDoc->attributes()['paging-cookie'])) {
			$fetchXmlDoc->addAttribute("paging-cookie",$xml['paging-cookie']);	
		} else {
			$fetchXmlDoc["paging-cookie"] = $xml['paging-cookie'];		
		}
		$responseXml = fetchXmlRequest ($fetchXmlDoc->asXML(), $authHeader, $url);
		$resultXml = str_replace("</resultset>",preg_replace("/<resultset.+>/U","",$responseXml),$resultXml);
	}

	return $resultXml;
	
}
?>