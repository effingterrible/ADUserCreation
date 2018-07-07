#clear
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

#function Check-AddRegUsers {
#param($toCheck)
	
#	foreach ($user in $users){

#		if ($user -eq $toCheck){
#			Add-Content -Path $fileName -Value "WARNING: USERNAME ALREADY EXISTS IN ACTIVE DIRECTORY"
#			$numUser++
#			$inc = $numUser.ToString()
#			$checkedName = $firstName + $lastName + $inc
#			Check-AddRegUsers -toCheck $checkedName
#		} 
#	}	 
#}

function Add-User{

	$DisplayName = $firstName + ' ' + $lastName
	$alias=$tempName + "@TheHeart.local"

	if ($type -In 1..4){ $OuPath = "OU=UnderGrad,OU=UserAccounts,DC=TheHeart,DC=local"	}
	if ($type -eq "g"){	$OuPath = "OU=Graduate,OU=UserAccounts,DC=TheHeart,DC=local" }
	if ($type -eq "s"){	$OuPath = "OU=Staff,OU=UserAccounts,DC=TheHeart,DC=local" }
	try {
		
		New-ADUser -SamAccountName $tempName -Givenname $firstName -Surname $lastName -Name $DisplayName -DisplayName $DisplayName -Path $OuPath -Accountpassword $securePassword -userprincipalname $alias -PasswordNeverExpires 1 -enabled $true
		Add-Content $fileName -Value "	Adding user: $tempName"
	} catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException]{
		Add-Content $fileName -Value "	Username already exists: $tempName"
		Write-Host "$($error[0])"
	}
	 catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException]{
		Add-Content $fileName -Value "	Password did not meet complexity requirements for user: $tempName"
		Write-Host "$($error[0])"
	}
}

function Load-FromFile{

	$content | ForEach-Object { 
		$type = $_.Level
		$firstName = $_.FirstName
		$lastName = $_.LastName
		$studentNumber = $_.StudentNumber
		$tempName = $_.LoginName 
		$securePassword = $studentNumber | ConvertTo-Securestring -AsPlainText -Force
		Add-User
	}


#	foreach ($item in $content){
		
#		$type = $item.Level
#		$firstName = $item.FirstName
#		$lastName = $item.LastName
#		$studentNumber = $item.StudentNumber
#		$tempName = $item.LoginName
#		Check-AddRegUsers -toCheck $tempName
#		if (!$checkedName){
#			$userName = $tempName
#		}
#		$securePassword = $studentNumber | ConvertTo-Securestring -AsPlainText -Force

#		Add-User
#	}
}

function Move-ToArchive{
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
			Move-ADObject -Identity $user.ObjectGUID -TargetPath "OU=NoLogin,OU=UserAccounts,DC=TheHeart,DC=local"
			Disable-ADAccount $user.ObjectGUID
			$temp = $user.SamAccountName
			Add-Content $fileName -Value "	User:	$temp moved to NoLogin OU"
		}
	}
}

Import-Module ActiveDirectory

$users = Get-ADUser -SearchBase "OU=UnderGrad,OU=UserAccounts,DC=TheHeart,DC=local" -Filter *
$users += Get-ADUser -SearchBase "OU=Graduate,OU=UserAccounts,DC=TheHeart,DC=local" -Filter *
$users += Get-ADUser -SearchBase "OU=Staff,OU=UserAccounts,DC=TheHeart,DC=local" -Filter *
Write-Host "Please enter one of the following options:"
Write-Host "	1 - Add Regular User"
Write-Host "	2 - Add Users From File"
Write-Host "	3 - Remove old users (Archived over one year)"
Write-Host "	4 - Exit"

$Option = Read-Host "	Choice"

if ($Option){
	Out-File -FilePath $fileName
	if ($Option -eq "1"){

		Add-Content $fileName -Value "========= Creating individual user ========="

		$type = Read-Host "Type (Staff (s), Year (#), Grad (g) etc " 
		$firstName = Read-Host "First Name "
		$lastName = Read-Host "Last Name "
		$studentNumber = Read-Host "Student Number "
		$tempName = Read-Host "User Name "
		$securePassword = $studentNumber | ConvertTo-Securestring -AsPlainText -Force
		
#		Check-AddRegUsers -toCheck $tempName
#		if (!$checkedName){
#			$userName = $tempName
#		}
		
#		if ($userName -ne $tempName){ Write-Host $tempName" is now "$userName }
		
		Add-User
	}
	if ($Option -eq "2"){

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
		
		if ($opt -In 0..$numFiles){ $content = Import-CSV $files[$opt] }
		else { if (Test-Path -Path $opt){ $content = Import-CSV $opt } }

		if ($content){ Load-FromFile }
		else { Write-Host "Invalid file name" }
		
		Move-ToArchive
	}
	
	if ($Option -eq "3"){

		Add-Content $fileName -Value "========= Removing Archived users over 1 year old ========="

		$inactives = Get-ADUser -SearchBase "OU=NoLogin,OU=UserAccounts,DC=TheHeart,DC=local" -Filter * -Properties "LastLogonDate"  
		$Date = Get-Date
		Foreach ($inactive in $inactives){
		If ($inactive.Enabled -eq $False){
			If ($inactive.LastLogonDate -ne $Null){
				If ((($inactive.LastLogonDate).Subtract($date) | Select -ExpandProperty Days) -le "0"){
					Set-ADUser -Identity $inactive -Description "Disabled on $Date for inactivity."
					Remove-ADObject -Identity $inactive -Confirm:$False
					Add-Content $fileName -Value "	User $inactive removed"
				}
				}
			}
		} 
	}
	if ($Option -eq "4"){
		Add-Content $fileName -Value "========= No Action Taken ========="
	}
} else {
	Write-Host "Good-Bye"
}
