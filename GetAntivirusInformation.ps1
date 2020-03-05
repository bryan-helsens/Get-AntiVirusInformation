function Get-AntiVirusProduct {

<#
.KORTE INHOUD

	Krijg de status van Antivirus Product op uw lokale computer.
	Deze versie werkt op Windows 10
	
	Auther: Bryan Helsens
	Last edited : 05/03/2020
	Versie 1.0
	
#>


$ComputerName = $env:COMPUTERNAME

<# Hier wordt alle antivirus informatie van de lokale computer opgehaald #>
# root\SecurityCenter2 dit is de Windows Security Center, deze functie geeft de algemene beveiligingsstatus van het systeem weer
$AntiVirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $ComputerName -ErrorAction Stop 
$Count = $AntiVirusProduct.displayName | measure-object | select count
echo $Count.count

$array = @()

$i = 0
$j = 0


if ($Count.count -eq 1){


	while ($i -ne $Count.Count){	


	<# Als u de productState naar HEX converteert, dan kunt u het 1st, 2de of 3de block lezen om er achter te komen 
	of het product is ingeschakeld/uitgeschakeld en of de versie up-to-date is of verouderd is. #>
	$productState = $AntiVirusProduct.productState
	
	<# converteren naar hex, voeg een extra '0' toe indien nodig #>
	$hex = [convert]::ToString($productState[0], 16).PadLeft(6,'0')
	
	  # Substring(int startIndex, int length)  
        $WSC_SECURITY_PROVIDER = $hex.Substring(0,2)
        $WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2)
        $WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2)
 
                # Hier wordt er gecontroleerd welke security provider er wordt gebruikt
                $SECURITY_PROVIDER = switch ($WSC_SECURITY_PROVIDER)
                {
                    0  {"NONE"}
                    1  {"FIREWALL"}
                    2  {"AUTOUPDATE_SETTINGS"}
                    4  {"ANTIVIRUS"}
                    8  {"ANTISPYWARE"}
                    16 {"INTERNET_SETTINGS"}
                    32 {"USER_ACCOUNT_CONTROL"}
                    64 {"SERVICE"}
                    default {"UNKNOWN"}
                }
 
				# Hier wordt er gecontroleerd of het antivirus ingeschakeld/uitgeschakeld is
                $RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE)
                {
                    "00" {"OFF"} 
                    "01" {"EXPIRED"}
                    "10" {"ON"}
                    "11" {"SNOOZED"}
                    default {"UNKNOWN"}
                }
 
				# Hier wordt er gecontroleerd of het antivirus up-to-date is of niet
                $DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS)
                {
                    "00" {"UP_TO_DATE"}
                    "10" {"OUT_OF_DATE"}
                    default {"UNKNOWN"}
                }  
				
				
				if ($AntiVirusProduct.displayName -match "virus"){
				
				$HiveInfo = Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Where-Object {$_.Name -like "*" + $AntiVirusProduct.get($i).displayName + "*"}

				$AntivirusName = $HiveInfo.GetValue("DisplayName")
				$AntivirusVersion = $HiveInfo.GetValue("DisplayVersion")
				$AntivirusPublisher = $HiveInfo.GetValue("Publisher")


				$lengthWord = $AntiVirusName.split(" ").length
				
				while ($j -ne $lengthWord){
				
					#$HiveInfo2 = Get-ChildItem -Path "HKLM:\SOFTWARE\" + $AntiVirusName.split(" ")[$j]
					
					
					if (Get-ChildItem -Path "HKLM:\SOFTWARE\" | Where-Object {$_.Name -like "*" + $AntiVirusName.split(" ")[$j] + "*"} ){
							
							echo $AntiVirusName.split(" ")[$j] " exists"
							$GetFullName = Get-ChildItem -Path "HKLM:\SOFTWARE\*$($AntiVirusName.split(' ')[$j])*" -name
					
							$HiveInfo2 = Get-ChildItem -Path "HKLM:\SOFTWARE\$($GetFullName)"
							$HiveInfo2 = $HiveInfo2.get(1)

							$AntivirusLicense = $HiveInfo2.GetValue("LicenseFile")
							$AntivirusLogsLocation = $HiveInfo2.GetValue("SetupLog")
							
					}else{
						echo $AntiVirusName.split(" ")[$j] " doesn't exists"
					}
					
					$j ++
				
				}
				
				$j = 0
				
				
			
				
				
					# Hier wordt alle data verzameld en in een object gestoken
			$obj = [PSCustomObject] @{
			'ComputerName' = $ComputerName;
			'Antivirus' = 'True'
			'AntiVirusName' = $AntiVirusName;
			'Version' = $AntivirusVersion;
			'Publisher' = $AntivirusPublisher;
			'Licenties' = $ANtivirusLicense;
			'Logs location' = $AntivirusLogsLocation;
			'DefinitionStatus' = $DefinitionStatus;
			'RealtimeProtectionStatus' = $RealTimeProtectionStatus;
			'ProductState' = $productState;
			
				}
	
				
					$i ++
					$array += $obj
					$obj = ""	
			}else{
			
			# Hier wordt alle data verzameld en in een object gestoken
			$obj = [PSCustomObject] @{
			'ComputerName' = $ComputerName;
			'Antivirus' = 'False'
			'AntiVirusName' = $AntiVirusProduct.displayName;
			'DefinitionStatus' = $DefinitionStatus;
			'RealtimeProtectionStatus' = $RealTimeProtectionStatus;
			'ProductState' = $productState;
				}
				
					$i ++
					$array += $obj
					$obj = ""	
			
			}
}

}else{

	while ($i -ne $Count.Count){	


	<# Als u de productState naar HEX converteert, dan kunt u het 1st, 2de of 3de block lezen om er achter te komen 
	of het product is ingeschakeld/uitgeschakeld en of de versie up-to-date is of verouderd is. #>
	$productState = $AntiVirusProduct.get($i).productState
	
	<# converteren naar hex, voeg een extra '0' toe indien nodig #>
	$hex = [convert]::ToString($productState[0], 16).PadLeft(6,'0')
	
	  # Substring(int startIndex, int length)  
        $WSC_SECURITY_PROVIDER = $hex.Substring(0,2)
        $WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2)
        $WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2)
 
                # Hier wordt er gecontroleerd welke security provider er wordt gebruikt
                $SECURITY_PROVIDER = switch ($WSC_SECURITY_PROVIDER)
                {
                    0  {"NONE"}
                    1  {"FIREWALL"}
                    2  {"AUTOUPDATE_SETTINGS"}
                    4  {"ANTIVIRUS"}
                    8  {"ANTISPYWARE"}
                    16 {"INTERNET_SETTINGS"}
                    32 {"USER_ACCOUNT_CONTROL"}
                    64 {"SERVICE"}
                    default {"UNKNOWN"}
                }
 
				# Hier wordt er gecontroleerd of het antivirus ingeschakeld/uitgeschakeld is
                $RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE)
                {
                    "00" {"OFF"} 
                    "01" {"EXPIRED"}
                    "10" {"ON"}
                    "11" {"SNOOZED"}
                    default {"UNKNOWN"}
                }
 
				# Hier wordt er gecontroleerd of het antivirus up-to-date is of niet
                $DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS)
                {
                    "00" {"UP_TO_DATE"}
                    "10" {"OUT_OF_DATE"}
                    default {"UNKNOWN"}
                }  
				
				
				if ($AntiVirusProduct.get($i).displayName -match "virus"){
				
				$HiveInfo = Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Where-Object {$_.Name -like "*" + $AntiVirusProduct.get($i).displayName + "*"}

				$AntivirusName = $HiveInfo.GetValue("DisplayName")
				$AntivirusVersion = $HiveInfo.GetValue("DisplayVersion")
				$AntivirusPublisher = $HiveInfo.GetValue("Publisher")


				
				$lengthWord = $AntiVirusName.split(" ").length
				
				while ($j -ne $lengthWord){
				
					#$HiveInfo2 = Get-ChildItem -Path "HKLM:\SOFTWARE\" + $AntiVirusName.split(" ")[$j]
					
					
					if (Get-ChildItem -Path "HKLM:\SOFTWARE\" | Where-Object {$_.Name -like "*" + $AntiVirusName.split(" ")[$j] + "*"} ){
							echo $AntiVirusName.split(" ")[$j] " exists"
							$GetFullName = Get-ChildItem -Path "HKLM:\SOFTWARE\*$($AntiVirusName.split(' ')[$j])*" -name
						
							$HiveInfo2 = Get-ChildItem -Path "HKLM:\SOFTWARE\$($GetFullName)"
							$HiveInfo2 = $HiveInfo2.get(1)

							$AntivirusLicense = $HiveInfo2.GetValue("LicenseFile")
							$AntivirusLogsLocation = $HiveInfo2.GetValue("SetupLog")
							
					}else{
						echo $AntiVirusName.split(" ")[$j] " doesn't exists"
					}
					$j ++
				
				}
				
				$j = 0
				
				
				
					# Hier wordt alle data verzameld en in een object gestoken
			$obj = [PSCustomObject] @{
			'ComputerName' = $ComputerName;
			'Antivirus' = 'True'
			'AntiVirusName' = $AntiVirusName;
			'Version' = $AntivirusVersion;
			'Publisher' = $AntivirusPublisher;
			'Licenties' = $ANtivirusLicense;
			'Logs location' = $AntivirusLogsLocation;
			'DefinitionStatus' = $DefinitionStatus;
			'RealtimeProtectionStatus' = $RealTimeProtectionStatus;
			'ProductState' = $productState;
			
				}
	
				
					$i ++
					$array += $obj
					$obj = ""	
			}else{
			
			# Hier wordt alle data verzameld en in een object gestoken
			$obj = [PSCustomObject] @{
			'ComputerName' = $ComputerName;
			'Antivirus' = 'False'
			'AntiVirusName' = $AntiVirusProduct.get($i).displayName;
			'DefinitionStatus' = $DefinitionStatus;
			'RealtimeProtectionStatus' = $RealTimeProtectionStatus;
			'ProductState' = $productState;
				}
				
					$i ++
					$array += $obj
					$obj = ""	
			
			}
}

}


echo "The function is ready, below you will find the result"

$array

}


get-antivirusproduct -list


