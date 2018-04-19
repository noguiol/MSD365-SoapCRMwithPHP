<?php
include "MSCrmIFD.php";
include "CrmType.php";
include "CrmBoolean.php";
include "CrmOptionSetValue.php";
include "CrmGuid.php";
include "CrmDouble.php";
include "CrmEntityReference.php";

// place your credentials here and keep the contents to yourself
include "connectionDetails.inc.php";

$crmService = new MSCrmIFD();

// place your credentials here
$crmService->usr = $connectionUsername;
$crmService->pwd = $connectionPassword;
$crmService->url = $connectionUrl;


$crmService->getAccess();

//FetchXml Sample
$fetchXml = "
<fetch mapping='logical'> 
   <entity name='account'>
      <attribute name='accountid'/> 
      <attribute name='name'/> 
</entity>
</fetch>
";
$result = $crmService->fetchRequest($fetchXml);

echo $result;
?>