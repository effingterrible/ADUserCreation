clear
$type = ""
$firstName = ""
$lastName = ""
$studentNumber = ""
$users = ""
$numUser = 0
$checkedName = ""
$tempName = ""
$userName = ""
$securePassword = ""
$content = ""
$alias = ""

function Check-AddRegUsers {
param($toCheck)
	
	foreach ($user in $users){
		#Write-Host "Checking"$toCheck" against" $user
		if ($user -eq $toCheck){
			$numUser++
			$inc = $numUser.ToString()
			$checkedName = $firstName + $lastName + $inc
			Check-AddRegUsers -toCheck $checkedName
		} 
	} 
}

function Add-User{

	$DisplayName = $firstName + ' ' + $lastName
	$alias=$userName + "@TheHeart.local"

	if ($type -In 1..4){ $OuPath = "OU=UnderGrad,OU=UserAccounts,DC=TheHeart,DC=local"	}
	if ($type -eq "g"){	$OuPath = "OU=Graduate,OU=UserAccounts,DC=TheHeart,DC=local" }
	if ($type -eq "s"){	$OuPath = "OU=Staff,OU=UserAccounts,DC=TheHeart,DC=local" }
	
	New-ADUser -SamAccountName $tempName -Givenname $firstName -Surname $lastName -Name $DisplayName -DisplayName $DisplayName -Path $OuPath -Accountpassword $securePassword -userprincipalname $alias -PasswordNeverExpires 1 -enabled $true
}

function Load-FromFile{

	foreach ($item in $content){
		
		$type = $item.Level
		$firstName = $item.FirstName
		$lastName = $item.LastName
		$studentNumber = $item.StudentNumber
		$tempName = $item.LoginName
		Check-AddRegUsers -toCheck $tempName
		if (!$checkedName){
			$userName = $tempName
		}
		$securePassword = $studentNumber | ConvertTo-Securestring -AsPlainText -Force

		Add-User
	}
}

function Move-ToArchive{

	foreach ($user in $users){
	
		$exist = $user.SamAccountName
		
		foreach ($person in $content){
		
			if ($exist -eq $person.LoginName){ $account = "fluff data" }
		}
		
		if ($account){ Write-Host $exist" account found" } 
		else { 
			Write-Host $exist" account not found, moving to archive OU"
			#move to NoLogin OU
		}
	}
}

Import-Module ActiveDirectory
#$users = Get-ADUser -Filter *
$users = Get-ADUser -SearchBase "OU=UserAccounts,DC=TheHeart,DC=local" -Filter * | Select-Object SamAccountName

Write-Host "Please enter one of the following options:"
Write-Host "	1 - Add Regular User"
Write-Host "	2 - Add Users From File"
Write-Host "	3 - Remove old users (Archived over one year)"

$Option = Read-Host "	Choice"

if ($Option){
	if ($Option -eq "1"){
		
		$type = Read-Host "Type (Staff (s), Year (#), Grad (g) etc " 
		$firstName = Read-Host "First Name "
		$lastName = Read-Host "Last Name "
		$studentNumber = Read-Host "Student Number "
		$tempName = $firstName + $lastName
		
		Check-AddRegUsers -toCheck $tempName
		if (!$checkedName){
			$userName = $tempName
		}
		
		if ($userName -ne $tempName){ Write-Host $tempName" is now "$userName }
		
		Add-User
	}
	if ($Option -eq "2"){
		
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
		
		Move-ToArchive
	}
	
	if ($Option -eq "3"){
		$type = Read-Host ""
		$firstName = Read-Host ""
		$lastName = Read-Host ""
		$studentNumber = Read-Host ""
	}
}
