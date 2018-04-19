<?php

/*php Microsoft Dynamics Crm 4.0 IFD authentication library

    Copyright (c) 2009 Zenithies

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
*/


  class MSCrmIFD {
    public $usr;
    public $pwd;
    public $org;
    public $domain;
    public $url;
    
    public $crmHost;
    public $crmHostPort;
    private $crmTicket;
    private $cURLHandle;
	private $crmAuthHeader;
	private $currentEntity;
    
    // performs login
    public function getAccess() {
            
            $crmAuth = new crmAuth();
            $deploymentType = "ifdonpremise";
            
            $authHeader = $crmAuth->GetHeader($this->usr, $this->pwd, $this->url, $deploymentType);

            if (isset($authHeader->Header)) {
                $this->crmAuthHeader = $authHeader;
                return true;
            } else {
                throw new Exception('MSCrmIFD::getAccess() IFD auth failed');
            }
    }
    
    public function request($request, $action) {
        $headers = array(
            "POST /MSCrmServices/2007/MSCrmServices/2007/CrmService.asmx HTTP/1.1",
            "Host: hobby.crm.hobby-caravan.de",
            'Connection: keep-alive',
            "SOAPAction: " . $action,
            "Content-type: text/xml;charset=utf-8",
            "Content-length: ".strlen($request),
        );
        
        
        $this->cURLHandle = curl_init($this->crmHost . "/MSCrmServices/2007/CrmService.asmx");
        curl_setopt($this->cURLHandle, CURLOPT_SSL_VERIFYPEER , false );
        curl_setopt($this->cURLHandle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($this->cURLHandle, CURLOPT_POST, 1);
        curl_setopt($this->cURLHandle, CURLOPT_POSTFIELDS, $request);
        curl_setopt($this->cURLHandle, CURLOPT_RETURNTRANSFER, 1);
        // ticket is set into cookie, with that you dont need him in soap header anymore
        // in fact this row is most important in whole struggle with this-
        curl_setopt($this->cURLHandle, CURLOPT_COOKIE, 'MSCRMSession=ticket=' . $this->crmTicket . ';'); 

        $response = curl_exec($this->cURLHandle);            
        $responseHeaders = curl_getinfo($this->cURLHandle);
        /*
        if ($responseHeaders['http_code'] != 200) {
            print_r($response);
            die('MSCrmIFD::__doRequest() failed');
        }
        */
        return $response;
    }    
    
    public function getAuthHeader() {
        $header = '<soap:Header>
                    <CrmAuthenticationToken xmlns="http://schemas.microsoft.com/crm/2007/WebServices">
                        <AuthenticationType xmlns="http://schemas.microsoft.com/crm/2007/CoreTypes">2</AuthenticationType>
                        <OrganizationName xmlns="http://schemas.microsoft.com/crm/2007/CoreTypes">' . $this->org . '</OrganizationName>
                    </CrmAuthenticationToken>
                </soap:Header>';
                
        return $header;
    }  
    
    public function closeConnection() {
        curl_close($this->cURLHandle);
    }    
     public function createRequest ($entityName,$attributeArray) {
    	    // prepare some request, put into request auth header
  $request = '<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
     ' . $this->getAuthHeader() . '
        <soap:Body>
            <Create xmlns="http://schemas.microsoft.com/crm/2007/WebServices">
                <entity xsi:type="'.$entityName.'">
                '.$this->toXml($attributeArray).'
                </entity>
            </Create>
        </soap:Body>
    </soap:Envelope>';
    
      $response = $this->request($request, 'http://schemas.microsoft.com/crm/2007/WebServices/Create');      
  
      return $response;
     }
	public function updateRequest ($entityName,$attributeArray) {
		    $this->currentEntity = $entityName;
    	    // prepare some request, put into request auth header
			$xml   = "<s:Body>";
			$xml  .= "<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\">";
			$xml  .= "<request i:type=\"b:UpdateRequest\" xmlns:b=\"http://schemas.microsoft.com/xrm/2011/Contracts\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">";
			$xml  .= "<b:Parameters xmlns:c=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">";
			$xml  .= "<b:KeyValuePairOfstringanyType>";
			$xml  .= "<c:key>Target</c:key>";
			$xml  .= "<c:value i:type=\"b:Entity\">";
			$xml  .= "<b:Attributes>";
			$xml  .= $this->toXml($attributeArray);
			$xml  .= "</b:Attributes>";
			$xml  .= "<b:EntityState i:nil=\"true\"/>";
			$xml  .= "<b:FormattedValues/>";
			$xml  .= "<b:Id>00000000-0000-0000-0000-000000000000</b:Id>";
			$xml  .= "<b:KeyAttributes xmlns:d=\"http://schemas.microsoft.com/xrm/7.1/Contracts\"/>";
			$xml  .= "<b:LogicalName>".$entityName."</b:LogicalName>";
			$xml  .= "<b:RelatedEntities/>";
			$xml  .= "<b:RowVersion i:nil=\"true\"/>";
			$xml  .= "</c:value>";
			$xml  .= "</b:KeyValuePairOfstringanyType>";
			$xml  .= "</b:Parameters><b:RequestId i:nil=\"true\"/>";
			$xml  .= "<b:RequestName>Update</b:RequestName>";
			$xml  .= "</request>";
			$xml  .= "</Execute>";
			$xml  .= "</s:Body>";
    
			$executeSoap = new CrmExecuteSoap ();
			$response = $executeSoap->ExecuteSOAPRequest ( $this->crmAuthHeader, $xml, $this->url );
						
			return $response;
     }
	 
	 public function deleteRequest ($entityName,$id) {
    	    // prepare some request, put into request auth header
		$xml   = "<s:Body>";
		$xml  .= "<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\">";
		$xml  .= "<request i:type=\"b:DeleteRequest\" xmlns:b=\"http://schemas.microsoft.com/xrm/2011/Contracts\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">";
		$xml  .= "<b:Parameters xmlns:c=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">";
		$xml  .= "<b:KeyValuePairOfstringanyType>";
		$xml  .= "<c:key>Target</c:key>";
		$xml  .= "<c:value i:type=\"b:EntityReference\">";
		$xml  .= "<b:Id>".$id."</b:Id>";
		$xml  .= "<b:KeyAttributes xmlns:d=\"http://schemas.microsoft.com/xrm/7.1/Contracts\"/>";
		$xml  .= "<b:LogicalName>".$entityName."</b:LogicalName>";
		$xml  .= "<b:Name i:nil=\"true\"/>";
		$xml  .= "<b:RowVersion i:nil=\"true\"/>";
		$xml  .= "</c:value>";
		$xml  .= "</b:KeyValuePairOfstringanyType>";
		$xml  .= "</b:Parameters>";
		$xml  .= "<b:RequestId i:nil=\"true\"/>";
		$xml  .= "<b:RequestName>Delete</b:RequestName>";
		$xml  .= "</request>";
		$xml  .= "</Execute>";
		$xml  .= "</s:Body>";

		$executeSoap = new CrmExecuteSoap ();
		$response = $executeSoap->ExecuteSOAPRequest ( $this->crmAuthHeader, $xml, $this->url );
					
		return $response;
     }
	 
	    public function createViaExecuteRequest ($entityName,$attributeArray) {
            // prepare some request, put into request auth header
            
           
            $xml = "<s:Body>";
            $xml  .= "<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\">";
            $xml  .= "<request i:type=\"b:CreateRequest\" xmlns:b=\"http://schemas.microsoft.com/xrm/2011/Contracts\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">";
            $xml  .= "<b:Parameters xmlns:c=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">";
            $xml  .= "<b:KeyValuePairOfstringanyType>";
            $xml  .= "<c:key>Target</c:key>";
            $xml  .= "<c:value i:type=\"b:Entity\">";
            $xml  .= "<b:Attributes>";
            $xml  .= $this->toXml($attributeArray);
            $xml  .= "</b:Attributes>";
            $xml  .= "<b:EntityState i:nil=\"true\"/>";
            $xml  .= "<b:FormattedValues/><b:Id>00000000-0000-0000-0000-000000000000</b:Id>";
            $xml  .= "<b:KeyAttributes xmlns:d=\"http://schemas.microsoft.com/xrm/7.1/Contracts\"/>";
            $xml  .= "<b:LogicalName>".$entityName."</b:LogicalName>";
            $xml  .= "<b:RelatedEntities/>";
            $xml  .= "<b:RowVersion i:nil=\"true\"/>";
            $xml  .= "</c:value>";
            $xml  .= "</b:KeyValuePairOfstringanyType>";
            $xml  .= "<b:KeyValuePairOfstringanyType>";
            $xml  .= "<c:key>SuppressDuplicateDetection</c:key>";
            $xml  .= "<c:value i:type=\"d:boolean\" xmlns:d=\"http://www.w3.org/2001/XMLSchema\">true</c:value>";
            $xml  .= "</b:KeyValuePairOfstringanyType>";
            $xml  .= "</b:Parameters>";
            $xml  .= "<b:RequestId i:nil=\"true\"/>";
            $xml  .= "<b:RequestName>Create</b:RequestName>";
            $xml  .= "</request>";
            $xml  .= "</Execute>";
            $xml  .= "</s:Body>"; 

            $executeSoap = new CrmExecuteSoap ();
            $response = $executeSoap->ExecuteSOAPRequest ( $this->crmAuthHeader, $xml, $this->url );
                        
            return $response;
     }
     
    public function fetchRequest ($fetchXml) {
        $fetchXmlDoc = simplexml_load_string($fetchXml);

        $attributes = $fetchXmlDoc->attributes();
        $issetPageAttribute = isset($attributes['page']);

        if(!$issetPageAttribute)  {
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
        $response = $executeSoap->ExecuteSOAPRequest ( $this->crmAuthHeader, $xml, $this->url );
        $responsedom = new DomDocument ();
        $responsedom->loadXML ( $response );
        $results = $responsedom->getElementsbyTagName("value");	
        $resultXml = $results->item(0)->nodeValue;
        
           $xml = simplexml_load_string($resultXml);
        $page = $fetchXmlDoc['page'];
        
        if($xml['morerecords'] == 1) {
            $fetchXmlDoc['page'] = $page+1;
            $attributes = $fetchXmlDoc->attributes();
            $issetPagingCookieAttribute = isset($attributes['paging-cookie']);
            if(!$issetPagingCookieAttribute) {
                $fetchXmlDoc->addAttribute("paging-cookie",$xml['paging-cookie']);	
            } else {
                $fetchXmlDoc["paging-cookie"] = $xml['paging-cookie'];		
            }
            $responseXml = $this->fetchRequest ($fetchXmlDoc->asXML());
            $resultXml = str_replace("</resultset>",preg_replace("/<resultset.+>/U","",$responseXml),$resultXml);
        }
    
        return $resultXml;
    }
    	public function toXml($data, $rootNodeName = 'data', $xml=null)
	{
		$xml = "";

        
		// loop through the data passed in.
		foreach($data as $key => $value)
		{
			// no numeric keys in our xml please!
			if (is_numeric($key))
			{
				// make string key...
				$key = "unknownNode_". (string) $key;
			}
			
			// replace anything not alpha numeric
			$key = preg_replace('/[^a-z_1-9]/i', '', $key);
			
			$xml  .= "<b:KeyValuePairOfstringanyType>";
			$xml  .= "<c:key>".$key."</c:key>";
			
			if (is_object($value)) {
				$className = strtolower( substr(strrchr(get_class($value), "\\"), 1));
			} else {
				$className = "string";
			}
			//Get class name without namespace
			

			switch ($className) {
				case 'crmdouble':
				$xml  .= "<c:value i:type=\"d:double\" xmlns:d=\"http://www.w3.org/2001/XMLSchema\">";
				$xml  .= $value->value;
				$xml  .= "</c:value>";
					break;
				case 'crmboolean':
					$xml  .= "<c:value i:type=\"d:boolean\" xmlns:d=\"http://www.w3.org/2001/XMLSchema\">";
					if($value->value == 1 ) {
						$xml .= "true";
					} else {
						$xml .= "false";
					}
				    $xml  .= "</c:value>";
					
					break;
				case 'crmoptionsetvalue':
					$xml  .= "<c:value i:type=\"b:OptionSetValue\"><b:Value>".$value->value."</b:Value>";
					$xml  .= "</c:value>";	
					break;
				case 'crmguid':
					$xml  .= "<c:value i:type=\"d:guid\" xmlns:d=\"http://schemas.microsoft.com/2003/10/Serialization/\">";
					$xml  .= utf8_encode($value->value);
					$xml  .= "</c:value>";	
					break;
				case 'crmentityreference':
					$xml  .= "<c:value i:type=\"d:EntityReference\" xmlns:d=\"http://schemas.microsoft.com/2003/10/Serialization/\">";
					$xml  .= "<b:Id>".$value->value."</b:Id>";
					$xml  .= "<b:KeyAttributes xmlns:d=\"http://schemas.microsoft.com/xrm/7.1/Contracts\"/>";
					$xml  .= "<b:LogicalName>".$value->entityName."</b:LogicalName>";
					$xml  .= "<b:Name i:nil=\"true\"/>";
					$xml  .= "<b:RowVersion i:nil=\"true\"/>";
					$xml  .= "</c:value>";	
					break;

				default:
					$xml  .= "<c:value i:type=\"d:string\" xmlns:d=\"http://www.w3.org/2001/XMLSchema\">";
					$xml  .= utf8_encode($value);
					$xml  .= "</c:value>";
					break;
			}

			
			$xml  .= "</b:KeyValuePairOfstringanyType>";
	       
            
				
		}
		// pass back as string. or simple xml object if you want!
		return $xml;
	}
  }

  class CrmAuth {
	
	/**
	 * Gets a CRM SOAP header & expiration.
	 * 
	 * @return CrmAuthenticationHeader An object containing the SOAP header and expiration date/time of the header.
	 * @param String $username
	 *        	Username of a valid CRM user.
	 * @param String $password
	 *        	Password of a valid CRM user.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 * @param String $deploymentType
	 *        	Type of the CRM deployment, either IFDOnPremise or Online.
	 */
	public function GetHeader($username, $password, $url, $deploymentType) {
		switch (strtolower ($deploymentType)) {
			case 'ifdonpremise':
				return $this->GetHeaderOnPremise($username, $password, $url);
				break;
			
			case 'online':
				return $this->GetHeaderOnline ( $username, $password, $url );
				break;
		}
	}
	
	/**
	 * Gets a CRM Online SOAP header & expiration.
	 * 
	 * @return CrmAuthenticationHeader An object containing the SOAP header and expiration date/time of the header.
	 * @param String $username
	 *        	Username of a valid CRM user.
	 * @param String $password
	 *        	Password of a valid CRM user.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 */
	public function GetHeaderOnline($username, $password, $url) {
		$url .= (substr ( $url, - 1 ) == '/' ? '' : '/');
		$urnAddress = $this->GetUrnOnline ( $url );
		$now = $_SERVER ['REQUEST_TIME'];
		
		$xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">";
		$xml .= "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<a:To s:mustUnderstand=\"1\">https://login.microsoftonline.com/RST2.srf</a:To>";
		$xml .= "<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<u:Timestamp u:Id=\"_0\">";
		$xml .= "<u:Created>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', $now ) . "</u:Created>";
		$xml .= "<u:Expires>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '+60 minute', $now ) ) . "</u:Expires>";
		$xml .= "</u:Timestamp>";
		$xml .= "<o:UsernameToken u:Id=\"uuid-" . $this->getGUID () . "-1\">";
		$xml .= "<o:Username>" . $username . "</o:Username>";
		$xml .= "<o:Password>" . $password . "</o:Password>";
		$xml .= "</o:UsernameToken>";
		$xml .= "</o:Security>";
		$xml .= "</s:Header>";
		$xml .= "<s:Body>";
		$xml .= "<trust:RequestSecurityToken xmlns:trust=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">";
		$xml .= "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">";
		$xml .= "<a:EndpointReference>";
		$xml .= "<a:Address>urn:" . $urnAddress . "</a:Address>";
		$xml .= "</a:EndpointReference>";
		$xml .= "</wsp:AppliesTo>";
		$xml .= "<trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>";
		$xml .= "</trust:RequestSecurityToken>";
		$xml .= "</s:Body>";
		$xml .= "</s:Envelope>";
		
		$headers = array (
				"POST " . "/RST2.srf" . " HTTP/1.1",
				"Host: " . "login.microsoftonline.com",
				'Connection: Keep-Alive',
				"Content-type: application/soap+xml; charset=UTF-8",
				"Content-length: " . strlen ( $xml ) 
		);
		
		$ch = curl_init ();
		curl_setopt ( $ch, CURLOPT_URL, "https://login.microsoftonline.com/RST2.srf" );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
		curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headers );
		curl_setopt ( $ch, CURLOPT_POST, 1 );
		curl_setopt ( $ch, CURLOPT_POSTFIELDS, $xml );
		
		$response = curl_exec ( $ch );
		curl_close ( $ch );
		
		$responsedom = new DomDocument ();
		$responsedom->loadXML ( $response );
		
		$cipherValues = $responsedom->getElementsbyTagName ( "CipherValue" );
		$token1 = $cipherValues->item ( 0 )->textContent;
		$token2 = $cipherValues->item ( 1 )->textContent;
		
		$keyIdentiferValues = $responsedom->getElementsbyTagName ( "KeyIdentifier" );
		$keyIdentifer = $keyIdentiferValues->item ( 0 )->textContent;
		
		$tokenExpiresValues = $responsedom->getElementsbyTagName ( "Expires" );
		$tokenExpires = $tokenExpiresValues->item ( 0 )->textContent;
		
		$authHeader = new CrmAuthenticationHeader ();
		$authHeader->Expires = $tokenExpires;
		$authHeader->Header = $this->CreateSoapHeaderOnline ( $url, $keyIdentifer, $token1, $token2 );
		
		return $authHeader;
	}
	
	/**
	 * Gets a CRM Online SOAP header.
	 * 
	 * @return String The XML SOAP header to be used in future requests.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 * @param String $keyIdentifer
	 *        	The KeyIdentifier from the initial request.
	 * @param String $token1
	 *        	The first token from the initial request.
	 * @param String $token2
	 *        	The second token from the initial request.
	 */
	function CreateSoapHeaderOnline($url, $keyIdentifer, $token1, $token2) {
		$xml = "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/Execute</a:Action>";
		$xml .= "<Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<EncryptedData Id=\"Assertion0\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns=\"http://www.w3.org/2001/04/xmlenc#\">";
		$xml .= "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/>";
		$xml .= "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
		$xml .= "<EncryptedKey>";
		$xml .= "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>";
		$xml .= "<ds:KeyInfo Id=\"keyinfo\">";
		$xml .= "<wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<wsse:KeyIdentifier EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\">" . $keyIdentifer . "</wsse:KeyIdentifier>";
		$xml .= "</wsse:SecurityTokenReference>";
		$xml .= "</ds:KeyInfo>";
		$xml .= "<CipherData>";
		$xml .= "<CipherValue>" . $token1 . "</CipherValue>";
		$xml .= "</CipherData>";
		$xml .= "</EncryptedKey>";
		$xml .= "</ds:KeyInfo>";
		$xml .= "<CipherData>";
		$xml .= "<CipherValue>" . $token2 . "</CipherValue>";
		$xml .= "</CipherData>";
		$xml .= "</EncryptedData>";
		$xml .= "</Security>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<a:To s:mustUnderstand=\"1\">" . $url . "XRMServices/2011/Organization.svc</a:To>";
		$xml .= "</s:Header>";
		
		return $xml;
	}
	
	/**
	 * Gets the correct URN Address based on the Online region.
	 * 
	 * @return String URN Address.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 */
	function GetUrnOnline($url) {
		if (strpos ( strtoupper ( $url ), "CRM2.DYNAMICS.COM" )) {
			return "crmsam:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM4.DYNAMICS.COM" )) {
			return "crmemea:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM5.DYNAMICS.COM" )) {
			return "crmapac:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM6.DYNAMICS.COM" )) {
			return "crmoce:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM7.DYNAMICS.COM" )) {
			return "crmjpn:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM9.DYNAMICS.COM" )) {
			return "crmgcc:dynamics.com";
		}
		
		return "crmna:dynamics.com";
	}
	
	/**
	 * Gets a CRM On Premise SOAP header & expiration.
	 * 
	 * @return CrmAuthenticationHeader An object containing the SOAP header and expiration date/time of the header.
	 * @param String $username
	 *        	Username of a valid CRM user.
	 * @param String $password
	 *        	Password of a valid CRM user.
	 * @param String $url
	 *        	The Url of the CRM On Premise (IFD) organization (https://org.domain.com).
	 */
	function GetHeaderOnPremise($username, $password, $url) {
		$url .= (substr ( $url, - 1 ) == '/' ? '' : '/');
		$adfsUrl = $this->GetADFS ( $url );
		$now = $_SERVER ['REQUEST_TIME'];
		$urnAddress = $url . "XRMServices/2011/Organization.svc";
		$usernamemixed = $adfsUrl . "/13/usernamemixed";
		
		$xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\">";
		$xml .= "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<Security s:mustUnderstand=\"1\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<u:Timestamp  u:Id=\"" . $this->getGUID () . "\">";
		$xml .= "<u:Created>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', $now ) . "</u:Created>";
		$xml .= "<u:Expires>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '+60 minute', $now ) ) . "</u:Expires>";
		$xml .= "</u:Timestamp>";
		$xml .= "<UsernameToken u:Id=\"" . $this->getGUID () . "\">";
		$xml .= "<Username>" . $username . "</Username>";
		$xml .= "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">" . $password . "</Password>";
		$xml .= "</UsernameToken>";
		$xml .= "</Security>";
		$xml .= "<a:To s:mustUnderstand=\"1\">" . $usernamemixed . "</a:To>";
		$xml .= "</s:Header>";
		$xml .= "<s:Body>";
		$xml .= "<trust:RequestSecurityToken xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">";
		$xml .= "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">";
		$xml .= "<a:EndpointReference>";
		$xml .= "<a:Address>" . $urnAddress . "</a:Address>";
		$xml .= "</a:EndpointReference>";
		$xml .= "</wsp:AppliesTo>";
		$xml .= "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>";
		$xml .= "</trust:RequestSecurityToken>";
		$xml .= "</s:Body>";
		$xml .= "</s:Envelope>";
		
		$headers = array (
				"POST " . parse_url ( $usernamemixed, PHP_URL_PATH ) . " HTTP/1.1",
				"Host: " . parse_url ( $adfsUrl, PHP_URL_HOST ),
				'Connection: Keep-Alive',
				"Content-type: application/soap+xml; charset=UTF-8",
				"Content-length: " . strlen ( $xml ) 
		);
		
		$ch = curl_init ();
		curl_setopt ( $ch, CURLOPT_URL, $usernamemixed );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
		curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headers );
		curl_setopt ( $ch, CURLOPT_POST, 1 );
		curl_setopt ( $ch, CURLOPT_POSTFIELDS, $xml );
		
		$response = curl_exec ( $ch );
		curl_close ( $ch );
		
		$responsedom = new DomDocument ();
		$responsedom->loadXML ( $response );
		
		$cipherValues = $responsedom->getElementsbyTagName ( "CipherValue" );
		$token1 = $cipherValues->item ( 0 )->textContent;
		$token2 = $cipherValues->item ( 1 )->textContent;
		
		$keyIdentiferValues = $responsedom->getElementsbyTagName ( "KeyIdentifier" );
		$keyIdentifer = $keyIdentiferValues->item ( 0 )->textContent;
		
		$x509IssuerNames = $responsedom->getElementsbyTagName ( "X509IssuerName" );
		$x509IssuerName = $x509IssuerNames->item ( 0 )->textContent;
		
		$x509SerialNumbers = $responsedom->getElementsbyTagName ( "X509SerialNumber" );
		$x509SerialNumber = $x509SerialNumbers->item ( 0 )->textContent;
		
		$binarySecrets = $responsedom->getElementsbyTagName ( "BinarySecret" );
		$binarySecret = $binarySecrets->item ( 0 )->textContent;
		
		$created = gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '-1 minute', $now ) );
		$expires = gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '+5 minute', $now ) );
		$timestamp = "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\"><u:Created>" . $created . "</u:Created><u:Expires>" . $expires . "</u:Expires></u:Timestamp>";
		
		$hashedDataBytes = sha1 ( $timestamp, true );
		$digestValue = base64_encode ( $hashedDataBytes );
		
		$signedInfo = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\"></SignatureMethod><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>" . $digestValue . "</DigestValue></Reference></SignedInfo>";
		$binarySecretBytes = base64_decode ( $binarySecret );
		$hmacHash = hash_hmac ( "sha1", $signedInfo, $binarySecretBytes, true );
		$signatureValue = base64_encode ( $hmacHash );
		
		$tokenExpiresValues = $responsedom->getElementsbyTagName ( "Expires" );
		$tokenExpires = $tokenExpiresValues->item ( 0 )->textContent;
		
		$authHeader = new CrmAuthenticationHeader ();
		$authHeader->Expires = $tokenExpires;
		$authHeader->Header = $this->CreateSoapHeaderOnPremise ( $url, $keyIdentifer, $token1, $token2, $x509IssuerName, $x509SerialNumber, $signatureValue, $digestValue, $created, $expires );
		
		return $authHeader;
	}
	
	/**
	 * Gets a CRM On Premise (IFD) SOAP header.
	 * 
	 * @return String SOAP Header XML.
	 * @param String $url
	 *        	The Url of the CRM On Premise (IFD) organization (https://org.domain.com).
	 * @param String $keyIdentifer
	 *        	The KeyIdentifier from the initial request.
	 * @param String $token1
	 *        	The first token from the initial request.
	 * @param String $token2
	 *        	The second token from the initial request.
	 * @param String $x509IssuerName
	 *        	The certificate issuer.
	 * @param String $x509SerialNumber
	 *        	The certificate serial number.
	 * @param String $signatureValue
	 *        	The hashsed value of the header signature.
	 * @param String $digestValue
	 *        	The hashed value of the header timestamp.
	 * @param String $created
	 *        	The header created date/time.
	 * @param String $expires
	 *        	The header expiration date/tim.
	 */
	function CreateSoapHeaderOnPremise($url, $keyIdentifer, $token1, $token2, $x509IssuerName, $x509SerialNumber, $signatureValue, $digestValue, $created, $expires) {
		$xml = "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/Execute</a:Action>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<a:To s:mustUnderstand=\"1\">" . $url . "XRMServices/2011/Organization.svc</a:To>";
		$xml .= "<o:Security xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\">";
		$xml .= "<u:Created>" . $created . "</u:Created>";
		$xml .= "<u:Expires>" . $expires . "</u:Expires>";
		$xml .= "</u:Timestamp>";
		$xml .= "<xenc:EncryptedData Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">";
		$xml .= "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>";
		$xml .= "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
		$xml .= "<e:EncryptedKey xmlns:e=\"http://www.w3.org/2001/04/xmlenc#\">";
		$xml .= "<e:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">";
		$xml .= "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>";
		$xml .= "</e:EncryptionMethod>";
		$xml .= "<KeyInfo>";
		$xml .= "<o:SecurityTokenReference xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<X509Data>";
		$xml .= "<X509IssuerSerial>";
		$xml .= "<X509IssuerName>" . $x509IssuerName . "</X509IssuerName>";
		$xml .= "<X509SerialNumber>" . $x509SerialNumber . "</X509SerialNumber>";
		$xml .= "</X509IssuerSerial>";
		$xml .= "</X509Data>";
		$xml .= "</o:SecurityTokenReference>";
		$xml .= "</KeyInfo>";
		$xml .= "<e:CipherData>";
		$xml .= "<e:CipherValue>" . $token1 . "</e:CipherValue>";
		$xml .= "</e:CipherData>";
		$xml .= "</e:EncryptedKey>";
		$xml .= "</KeyInfo>";
		$xml .= "<xenc:CipherData>";
		$xml .= "<xenc:CipherValue>" . $token2 . "</xenc:CipherValue>";
		$xml .= "</xenc:CipherData>";
		$xml .= "</xenc:EncryptedData>";
		$xml .= "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
		$xml .= "<SignedInfo>";
		$xml .= "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
		$xml .= "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\"/>";
		$xml .= "<Reference URI=\"#_0\">";
		$xml .= "<Transforms>";
		$xml .= "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
		$xml .= "</Transforms>";
		$xml .= "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>";
		$xml .= "<DigestValue>" . $digestValue . "</DigestValue>";
		$xml .= "</Reference>";
		$xml .= "</SignedInfo>";
		$xml .= "<SignatureValue>" . $signatureValue . "</SignatureValue>";
		$xml .= "<KeyInfo>";
		$xml .= "<o:SecurityTokenReference xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<o:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\">" . $keyIdentifer . "</o:KeyIdentifier>";
		$xml .= "</o:SecurityTokenReference>";
		$xml .= "</KeyInfo>";
		$xml .= "</Signature>";
		$xml .= "</o:Security>";
		$xml .= "</s:Header>";
		
		return $xml;
	}
	
	/**
	 * Gets the name of the AD FS server CRM uses for authentication.
	 * 
	 * @return String The AD FS server url.
	 * @param String $url
	 *        	The Url of the CRM On Premise (IFD) organization (https://org.domain.com).
	 */
	function GetADFS($url) {
		$ch = curl_init ();
		curl_setopt ( $ch, CURLOPT_URL, $url . "XrmServices/2011/Organization.svc?wsdl=wsdl0" );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		
		$response = curl_exec ( $ch );
		curl_close ( $ch );
		
		$responsedom = new DomDocument();
		$responsedom->loadXML ( $response );
		
		$identifiers = $responsedom->getElementsbyTagName ( "MetadataReference" );
		$identifier = $identifiers->item ( 0 )->textContent;
		
		return trim(str_replace("/mex", "", str_replace ( "http://", "https://", $identifier )));
	}
	
	// http://stackoverflow.com/questions/18206851/com-create-guid-function-got-error-on-server-side-but-works-fine-in-local-usin
	function getGUID() {
		if (function_exists ( 'com_create_guid' )) {
			return com_create_guid ();
		} else {
			mt_srand ( ( double ) microtime () * 10000 ); // optional for php 4.2.0 and up.
			$charid = strtoupper ( md5 ( uniqid ( rand (), true ) ) );
			$hyphen = chr ( 45 ); // "-"
			$uuid = chr ( 123 ) . // "{"
substr ( $charid, 0, 8 ) . $hyphen . substr ( $charid, 8, 4 ) . $hyphen . substr ( $charid, 12, 4 ) . $hyphen . substr ( $charid, 16, 4 ) . $hyphen . substr ( $charid, 20, 12 ) . chr ( 125 ); // "}"
			return $uuid;
		}
	}
}

class CrmAuthenticationHeader
{
    public $Header;
    public $Expires;
}

class CrmExecuteSoap {
	/**
	 * Executes the SOAP request.
	 * @return String SOAP response.
	 * @param CrmAuthenticationHeader $authHeader
	 *        	The authenticated CrmAuthenticationHeader.
	 * @param String $request
	 *        	The SOAP request body.
	 * @param String $url
	 *        	The CRM URL.
	 */
	public function ExecuteSOAPRequest($authHeader, $request, $url) {
		$url = rtrim ( $url, "/" );
		$xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\">";
		$xml .= $authHeader->Header;
		$xml .= $request;
		$xml .= "</s:Envelope>";
		
		$headers = array (
				"POST " . "/Organization.svc" . " HTTP/1.1",
				"Host: " . str_replace ( "https://", "", $url ),
				'Connection: Keep-Alive',
				"Content-type: application/soap+xml; charset=UTF-8",
				"Content-length: " . strlen ( $xml ) 
		);
		
		$cURL = curl_init ();
		curl_setopt ( $cURL, CURLOPT_URL, $url . "/XRMServices/2011/Organization.svc" );
		curl_setopt ( $cURL, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $cURL, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $cURL, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $cURL, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
		curl_setopt ( $cURL, CURLOPT_HTTPHEADER, $headers );
		curl_setopt ( $cURL, CURLOPT_POST, 1 );
		curl_setopt ( $cURL, CURLOPT_POSTFIELDS, $xml );
		
        $response = curl_exec ( $cURL );
		curl_close ( $cURL );
		
		return $response;
	}
}

?>

	
     
	