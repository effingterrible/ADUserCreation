#Clear screen and variable declaration
clear
$type = ""
$firstName = ""
$lastName = ""
$studentNumber = ""
$users = ""
$checkedName = ""
$tempName = ""
$userName = ""
$securePassword = ""
$content = ""
$alias = ""
$numUser = 0
$timeStamp = Get-Date -Format FileDateTime
$currentUser = $env:Username
$fileName = $currentUser+$timeStamp+".txt"
$profileDir = "\\cee.carleton.ca\CeeStorage\"
$OU1 = "OU=UnderGrad,OU=UserAccounts,DC=cee,DC=carleton,DC=ca"
$OU2 = "OU=Graduate,OU=UserAccounts,DC=cee,DC=carleton,DC=ca"
$OU3 = "OU=PhD,OU=UserAccounts,DC=cee,DC=carleton,DC=ca"
$OU4 = "OU=Staff,OU=UserAccounts,DC=cee,DC=carleton,DC=ca"
$OU5 = "OU=NoLogin,OU=UserAccounts,DC=cee,DC=carleton,DC=ca"
$domain = "cee.carleton.ca"
$isNew = $true
$Option = "0"

#
# Function Declarations
#

#Add user function, checks for account 'type' (student, staff, grad etc), adds user
#If it exists then updates description to appropriate year
#Creates user file share and provides proper access rights
function Add-User{

	$DisplayName = $firstName + ' ' + $lastName
	$alias=$userName + "@" + $domain

	if ($type -In 1..4){ $OuPath = $OU1	
		$description = "Year $type Student"
	}
	if ($type -eq "g"){	$OuPath = $OU2 
		$description = "Graduate Student"
	}
	if ($type -eq "p"){	$OuPath = $OU3 
		$description = "Post-Grad"
	}
	if ($type -eq "s"){	$OuPath = $OU4 
		$description = "Staff"
	}
	
	try {
		$homeDir = $profileDir+$userName
		New-ADUser -SamAccountName $userName -Givenname $firstName -Surname $lastName -Name $userName -DisplayName $DisplayName -HomeDrive "P:" -HomeDirectory $homeDir -Path $OuPath -Accountpassword $securePassword -Description $description -userprincipalname $alias -enabled $true
		Add-Content $fileName -Value "	Adding user: $userName"
		Set-ADUser -Identity $UserName -ChangePasswordAtLogon:$True
	} catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException]{
		Add-Content $fileName -Value "	Username already exists: $userName updating description if needed and moving to new OU"
		Set-ADUser -Identity $userName -Description $description
		$toMove = dsquery user -samid $userName
		$toMove = $toMove.Replace("`"","")
		Move-ADObject -Identity $toMove -TargetPath $OuPath
	}
	 catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException]{
		Add-Content $fileName -Value "	Password did not meet complexity requirements for user: $userName OR user duplicated in script, attempting to move OUs."
		Set-ADUser -Identity $userName -Description $description
		$toMove = dsquery user -samid $userName
		$toMove = $toMove.Replace("`"","")
		Move-ADObject -Identity $toMove -TargetPath $OuPath
	} 
	catch {
		Add-Content $fileName -Value "	Username already exists: $userName updating description if needed and moving to new OU" 
		Set-ADUser -Identity $userName -Description $description
		$toMove = dsquery user -samid $userName
		$toMove = $toMove.Replace("`"","")
		Move-ADObject -Identity $toMove -TargetPath $OuPath
	}

	try{
		New-Item -Path $profileDir -Name $userName -ItemType "Directory" -ErrorAction SilentlyContinue | Out-Null
		$UsersAm = $domain + "\" + $userName
		$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::"ContainerInherit", "ObjectInherit" 
		$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
		$AccessControl =[System.Security.AccessControl.AccessControlType]::Allow
		$FileSystemAccessRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
		$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($UsersAm, $FileSystemAccessRights, $InheritanceFlags, $PropagationFlags, $AccessControl);

		$currentACL = Get-ACL -path $homeDir
		$currentACL.SetAccessRule($accessRule)
		Set-ACL -path $homeDir -AclObject $currentACL
		$currentACL.SetOwner([System.Security.Principal.NTAccount]$userName)
		$shareName = $userName+'$'
		icacls $homeDir /inheritance:d /remove:g Users | Out-Null
		icacls $homeDir /inheritance:d /remove:g Users | Out-Null
	} catch {Add-Content $fileName -Value "$userName  $($error[0])"}
	Clear-Variable "type"
	Clear-Variable "firstName"
	Clear-Variable "lastName"
	Clear-Variable "studentNumber"
	Clear-Variable "tempName"
	Clear-Variable "userName"
	Clear-Variable "securePassword"

}

#Function to load user(s) from specified file
function Load-FromFile{
	$progress = 0
	Write-Host "Loading users from file." 
	$content | ForEach-Object {
		
		$type = $_.Level
		$firstName = $_.FirstName
		$lastName = $_.LastName
		$studentNumber = $_.StudentNumber
		$tempName = $_.LoginName 
		$tempName = $tempName -replace '\s',''
		$userName = $tempName
		$securePassword = ConvertTo-Securestring -AsPlainText "C!v!l$studentNumber!" -Force
		Add-User
		$progress++
		Write-Progress -Activity "Adding Users" -Status "Progress:" -PercentComplete ($progress/$content.count*100)
	}
}

#Moves users to Archive OU if they exist in AD but not in the list, skips staff.
function Move-ToArchive{
	$progress = 0
	Add-Content $fileName -Value "========= Checking for non returning users ========="
	foreach ($user in $users){
	
		$exist = $user.SamAccountName
		
		$content | ForEach-Object { 
			if ($_.LoginName -eq $exist) {
				$account = "fluff data"
				continue
			}else { $account = "" } 

		}
		if ($account -eq "fluff data"){ Add-Content $fileName -Value "	No users to move" } 
		else { 
			if ($user.DistinguishedName -like "*Staff*"){
				#Do Nothing
			} else {
				Move-ADObject -Identity $user.ObjectGUID -TargetPath $OU5
				Disable-ADAccount $user.ObjectGUID
				$temp = $user.SamAccountName
				Add-Content $fileName -Value "	User:	$temp moved to NoLogin OU"
			}
		}
		$progress++
		Write-Progress -Activity "Archiving" -Status "Progress:" -PercentComplete ($progress/$users.count*100)
	}
}

#
#'Main' code
#

#Import AD module to allow script to process Active Directory, limit user search to specific OUs
Import-Module ActiveDirectory
$ous = $OU1,$OU2,$OU3,$OU4
$users = $ous | ForEach { Get-ADUser -Filter * -SearchBase $_ }

#Create log file
Out-File -FilePath $fileName

#Menu and action code block, will keep this menu up after any processing until the user hits '5'
while ($Option -ne "5"){
	Write-Host "Please enter one of the following options:"
	Write-Host "	1 - Add Users From File Without Archiving"
	Write-Host "	2 - Add Regular User"
	Write-Host "	3 - Add Users From File"
	Write-Host "	4 - Remove old users (Archived over one year)"
	Write-Host "	5 - Exit"

	$Option = Read-Host "	Choice"

	if ($Option){
		#Load users from file without Archiving, used to handle students who have registered late
		#Looks at the directory for any CSV files and adds them to a list for the user, user can also specifiy a file location.
		if ($Option -eq "1"){
			
			Add-Content $fileName -Value "========= Loading users from file without Archiving ========="
			
			$numFiles = 0
			$files = Get-ChildItem -Path *.csv
					
			Write-Host "Please choose a file, or enter the full path of the file you would like to load."
			Write-Host "If there are any spaces in the path please use quotation marks around the entire path."
					
			if ($files){
				foreach ($file in $files){
					Write-Host "["$numFiles"] - "$file
					$numFiles++
				}
			}
					
			$opt = Read-Host
					
			if ($opt -In 0..$numFiles){ $content = Import-CSV $files[$opt] }
			else { if (Test-Path -Path $opt){ $content = Import-CSV $opt } }
			#If the file exists then run the Load-FromFile function
			if ($content){ Load-FromFile }
			else { Write-Host "Invalid file name" }
					
		}
		#Creates individual user
		if ($Option -eq "2"){

			Add-Content $fileName -Value "========= Creating individual user ========="

			$type = Read-Host "Type (Staff (s), Year (#), Grad (g) etc " 
			$firstName = Read-Host "First Name "
			$lastName = Read-Host "Last Name "
			$studentNumber = Read-Host "Student Number "
			$tempName = Read-Host "User Name "
			$securePassword = ConvertTo-Securestring -AsPlainText "C!v!l$studentNumber!" -Force
			$userName = $tempName	
			Add-User
		}
		#Creates users from file, will archive if they don't exist in the list but exist in AD
		if ($Option -eq "3"){

			Add-Content $fileName -Value "========= Loading users from file ========="

			$numFiles = 0
			$files = Get-ChildItem -Path *.csv
			
			Write-Host "Please choose a file, or enter the full path of the file you would like to load."
			Write-Host "If there are any spaces in the path please use quotation marks around the entire path."
			
			if ($files){
				foreach ($file in $files){
					Write-Host "["$numFiles"] - "$file
					$numFiles++
				}
			}
			
			$opt = Read-Host
			
			if ($opt -In 0..$numFiles){ $content = Import-CSV $files[$opt] -Encoding UTF8}
			else { if (Test-Path -Path $opt){ $content = Import-CSV $opt -Encoding UTF8 } }

			if ($content){ Load-FromFile }
			else { Write-Host "Invalid file name" }
			Write-Host "Users added to Active Directory...Moving unlisted users to archive."
			Move-ToArchive
			Write-Host "Archiving completed."
		}
		#Remove archived user accounts older than 1.5 years
		if ($Option -eq "4"){

			Add-Content $fileName -Value "========= Removing Archived users over 1 year old ========="

			$inactives = Get-ADUser -SearchBase $OU5 -Filter * -Properties "LastLogonDate"  
			$Date = Get-Date
			Foreach ($inactive in $inactives){
			If ($inactive.Enabled -eq $False){
				If ($inactive.LastLogonDate -ne $Null){
					If ((($inactive.LastLogonDate).Subtract($date) | Select -ExpandProperty Days) -le "-540"){
						Set-ADUser -Identity $inactive -Description "Disabled on $Date for inactivity."
						Remove-ADObject -Identity $inactive -Confirm:$False
						Add-Content $fileName -Value "	User $inactive removed"
					}
					}
				}
			} 
		}
		#Exit the application
		if ($Option -eq "5"){
			Add-Content $fileName -Value "========= No Action Taken ========="
			Write-Host "Good-Bye"
		}
	} else {
		Write-Host "Good-Bye"
	}
}
