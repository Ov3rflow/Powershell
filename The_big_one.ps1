


############# Set up the variables to be used for the rest of the script #############

$user = "godwilly"  ###CHANGE THIS #####
$pw = Read-Host "Please enter your password" -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$pw
#$complist = (Get-Content c:\put there path to a text file with computernames here.txt) ######CHANGE THIS####



##### Find Processes across the entire network #####
function Find-Process {
    param($cred, $complist)
    Clear-Host
    $process = Read-Host "`n`nWhich process do you want to search for? "
    foreach($comp in $complist) {
        Invoke-Command -ComputerName $comp -Credential $cred -ArgumentList $process, $comp -ScriptBlock {
            param($process,$comp)
            Write-Host "Checking $comp"
            ps | Where-Object {$_.ProcessName -eq $process}
        }
    }
    pause
}

##### Check-Eventlogs #####

function Check-EventLogs {
    param($cred)
    Clear-Host
    $hostname = Read-Host "What host would you like to check? "
    $continue = 'y'
    $logtype = read-host 'Which Event Log would you like to check? [security or system] '

    function check-event {
        param($eventid, $hostname, $cred,$logtype)
        Write-Host "`n`t`t`t`t`t$logtype LOGS"
        Write-Host "`n`n`t`t`t  Checking last 1000 logs for EventID $eventid"
        Invoke-Command -ComputerName $hostname -Credential $cred -ScriptBlock {

            Get-EventLog -LogName $logtype -Newest 1000 | ? {$_.EventID -eq $eventid} | Format-list EventID, MachineName, Message | more
        }
        Read-Host "`n`n`t`t`t`tFinished searching for logs!`n`t`t`tPress enter to continue to the next search!"
        Clear-Host
    }


    while ($continue -eq 'y') {

        if ($logtype -eq 'system') {
    
           $systemid = Read-Host '`n`nThe following is a list of interesting Event IDs.`n`nYou can choose your own or one of the following to search for`n`n
            7045. `tA new service was installed
            7030. `tInteractive service
            104. `tLogon failure
            517. `tThe audit log was cleared (created if the SECURITY log is cleared)
            1102. `tThe audit log was cleared (SECURITY log again)'
    
           check-event $systemid $hostname $cred $logtype
        }

        elseif ($logtype -eq 'security') {
    
           $securityid ='`n`nThe following is a list of interesting Event IDs.`n`nYou can choose your own or one of the following to search for `n`n
            4663. `tAn attempt was made to access an object
            4740. `tA user account was locked out
            4728. `tA member was added to a security enabled global group
            4732. `tA member was added to a security enabled local group
            4756. `tA member was added to a security enabled universal group
            4735. `tA security enabled local goup was changed
            4634. `tAn account was logged off
            4724. `tAn attempt was made to reset an accounts passwords
            4625. `tAn account failed to log on
            4648. `tA logon was attempted using explicit credentials (alternate creds e.g. RunAs)
            4741. `tA computer account was created
            4624. `tAn account was successfully logged on
            4720. `tA user account was created
            4688. `tA new process has been created
            4657. `tA registry value was modified
            4698. `tA scheduled task was created'
      
            check-event $securityid $hostname $cred $logtype 
    
        }

        $continue = Read-Host "Would you like to check another Event ID? [y/n]"
    }
}


##### List the process tree for a remote host #####

function List-ProcessTree {
    param($cred)
    $processById = @{}
    $hostname = Read-Host "Enter the host you would like to check? "
    Invoke-Command -ComputerName $hostname -Credential $cred -ArgumentList $hostname, $processById -ScriptBlock {
        param($hostname, $processById)
        foreach ($process in (Get-WmiObject -Class win32_process -ComputerName $hostname)) {
            $processById[$process.processid] = $process
        }
        $processesWithoutParents = @()
        $ProcessesByParent = @()
        foreach($Pair in $processById.GetEnumerator()) {
            $Process = $pair.value
            if(($Process.ParentProcessId -eq 0) -or !$processById.ContainsKey($process.ParentProcessId)) {
                $processesWithoutParents += $process 
                continue
            }
            if(!$ProcessesByParent.Contains($process.ParentProcessId)){
                $processesByparent[$process.parentProcessId] = @()
            }
            $siblings = $ProcessesByParent[$process.parentProcessid]
            $siblings += $process 
            $processesByParent[$process.parentProcessId] = $siblings
        }
        function Show-ProcessTree([uint32]$processid, $indentlevel) {
            $process = $processById[$processid]
            $indent = " " * $indentlevel
            if ($process.CommandLine) {
                $description = $process.CommandLine
            }
            else {
                $description = $process.caption
            }
            Write-Output ("{0,6} {1} {2}" -f $process.ProcessId, $indent, $description)
            foreach($child in $ProcessesByParent[$processId] | Sort-Object creationDate) {
                Show-ProcessTree $child.processId ($indentlevel+4)
            }
        }
        Write-Output ("{0,6} {1}" -f "PID", "Command Line")
        Write-Output ("{0,6} {1}" -f "---", "------------")

        foreach ($process in ($processesWithoutParents | Sort-Object creationdate)) {
            Show-ProcessTree $process.ProcessId 0
        }
    }
    pause
}


#### PsEmpire SSP check ####

function Find-PsEmpireSSP {
    param($cred, $complist)
    Clear-Host
    foreach($comp in $complist) {
        Invoke-Command -ComputerName $comp -Credential $cred -ArgumentList $comp -ScriptBlock {
            param($comp)
            Clear-Host
            $c = cmd /c reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa | findstr "Security"
            Write-Host "$comp has the following Security Packages...`n`n$c`n`nLook for any dll's that dont match the following white list:
                `tKerberos
                `tmsv1_0
                `tschannel
                `twdigest
                `ttspkg
                `tpku2u
                `nIf you find any that don't match, the are probably bad and should be investigated.`nLook for them in the system32 folder."
            pause
        }
    }
    Pause
}



#### PsEmpire userland persistence locator #####

function Find-PsEmpireUserlandPersist {
    parm($cred, $complist)
    Clear-Host
    foreach ($comp in $complist ) {
        Invoke-Command -ComputerName $comp -Credential $cred -ErrorAction SilentlyContinue -ArgumentList $comp -ScriptBlock {
            param($comp)
            $c = cmd /c reg query HKCU\software\microsoft\windows\currentversion\run | findstr "powershell"
            Write-Host "$comp .... $c"
        }
    }
    Pause
}



#### PsEmpire Elevated persistence locator #####

function Find-PsEmpireElevatedPersist {
    param($cred, $complist)
    Clear-Host
    foreach($comp in $complist) {
        Invoke-Command -ComputerName $comp -Credential $cred -ArgumentList $comp -ScriptBlock {
            param($comp)
            $c = cmd /c reg query HKLM\software\microsoft\windows\currentversion\run | findstr "powershell"
            Write-Host "$comp .... $c"
        }
    }
    Pause
}



##### PsEmpire debugger persistence locator ######

function Find-PsEmpireDebuggerPersist {
    param($cred, $complist)
    Clear-Host
    foreach($comp in $complist) {
        Invoke-Command -ComputerName $Comp -Credential $cred -ArgumentList $comp -ScriptBlock {
            param($comp)
            $sethc = cmd /c reg query 'HKLM\software\microsoft\windows NT\currentversion\image file execution options' | findstr "sethc.exe"
            $utilman = cmd /c reg query 'HKLM\software\microsoft\windows NT\currentversion\image file execution options' | findstr "utilman.exe"
            $magnify = cmd /c reg query 'HKLM\software\microsoft\windows NT\currentversion\image file execution options' | findstr "magnify.exe"
            $narrator = cmd /c reg query 'HKLM\software\microsoft\windows NT\currentversion\image file execution options' | findstr "narrator.exe"
            $osk = cmd /c reg query 'HKLM\software\microsoft\windows NT\currentversion\image file execution options' | findstr "osk.exe"
            Write-Host "------------------------------`n$comp .....
            `nSETHC:$sethc`nUTILMAN:$utilman`nMAGNIFY:$magnify`nNARRATOR:$narrator`nOSK:$osk`n-----------------------------`n`n"
            
        }
    }
    Pause
}




##### PsEmpire scheduled task persistence locator #####

function Find-PsEmpireSchtaskPersist {
    param($cred, $complist)
    Clear-Host
    foreach($comp in $complist) {
        Invoke-Command -ComputerName $comp -Credential $cred -ArgumentList $comp -ScriptBlock {
            param($cred)
            $c = schtasks /query /FO csv /v | findstr "powershell.exe"
            Write-Host "$comp .....`n$c`n`n"
        }
    }
    Pause
}


####  PsEmpire WMI persistence locator #####

function Find-PsEmpireWMIPersist {
    param($cred, $complist)
    Clear-Host
    foreach($comp in $complist) {
        Invoke-Command -ComputerName $comp -Credential $cred -ArgumentList $comp -ScriptBlock {
            param($comp)
            $c = Get-WmiObject -Namespace root\subscription -Class __Eventconsumer | findstr 'powershell.exe'
            Write-Host "$comp .....`n$c`n`n"
        }
    }
    Pause
}



#### Netstat listing for remote host ####

function Check-Connections {
    param($cred)
    Clear-Host
    $hostname = Read-Host "Which host would you like to check? "
    Invoke-Command -ComputerName $hostname -Credential $cred -ScriptBlock {
        cmd /c netstat -noab
    }
    Pause
}



#### find any file across the domain ####

function Find-Files {
    param($cred, $complist)
    Clear-Host
    $num = Read-Host "How many days back would you like to check? "
    $file = Read-Host "While file would you like to search for? (e.g. .exe .py evilfile)"
    Write-Host "`n`t`tStarting jobs on remote hosts.....`n" -ForegroundColor Green
    foreach ($comp in $complist) {
        $s = Invoke-Command -ComputerName $comp -Credential $cred -AsJob -JobName $comp -ErrorAction SilentlyContinue -ScriptBlock {
            Get-ChildItem -Path c:\ -Recurse | Where {$_.LastWriteTime -gt (Get-Date).AddDays(-$num) -and $_.Name -like "*$file*"}
        }
    }
    Write-Host "`n`t`tWaiting for remote jobs to finish...`n`n" -ForegroundColor Green
    $j = Wait-Job *
    $j = Get-Job

    Write-Host "`n`n`t`tHere are the results for c:\ an all subirectories...`n`n" -ForegroundColor Green
    foreach($comp in $complist) {
        $result = $j | Receive-Job -ComputerName $comp
        if ($result -like "*.*" -and $result -notlike "*does not exist*") {
            Write-Host "------------------`n$comp"
            Write-Host "`n`t`t$result"
        }
    }
    Write-Host "`n`n"
    Remove-Job *
    Pause
}



##### main() i guess #####
while ($true) {
    Clear-Host
    $choice = Read-Host "`n`nWhat would you like to do?`n
        Function Name`t`t`t`t`t`t`tDescription
        -------------`t`t`t`t`t`t`t-----------

        1.  Find-Process`t`t`t`t`t`tFind a single process across the entire network
        2.  Check-EventLogs`t`t`t`t`t`tCheck a single host for any EventID
        3.  List-ProcessTree`t`t`t`t`tList the full process tree (including cmdline) for a single host
        4.  Find-PsEmpireSSP`t`t`t`t`tList the registry location PsEmpire uses to install bad dlls for persistence
        5.  Find-PsEmpireUserlandPersist`t`tLooks for Powershell persistence in the low priv location PsEmpire uses
        6.  Find-PsEmpireElevatedPersist`t`tLooks for Powershell persistence in the high priv location PsEmpire uses
        7.  Find-PsEmpireDebuggerPersist`t`tLooks for debugger persistence used by PsEmpire
        8.  Find-PsEmpireSchtaskPersist`t`t`tLooks for scheduled task persistence used by PsEmpire
        9.  Find-PsEmpireWMIPersist`t`t`t`tLooks for advanced WMI persistence used by PsEmpire
        10. Check-Connections`t`t`t`t`tRun netstat on a remote host including the associated binaries for connections
        11. Find-Files`t`t`t`t`t`t`tSearch for any file or file extension across the network created within the last X days

        Choice"

    if ($choice -eq '1' -or $choice -eq 'Find-Process') {
        Find-Process $cred $complist 
    }
    elseif ($choice -eq '2' -or $choice -eq 'Check-EventLogs') {
        Check-EventLogs $cred 
    }
    elseif ($choice -eq '3' -or $choice -eq 'List-ProcessTree') {
        List-ProcessTree $cred 
    }
    elseif ($choice -eq '4' -or $choice -eq 'Find-PsEmpireSSP') {
        Find-PsEmpireSSP $cred $complist 
    }
    elseif ($choice -eq '5' -or $choice -eq 'Find-PsEmpireUserlandPersist') {
        Find-PsEmpireUserlandPersist $cred $complist 
    }
    elseif ($choice -eq '6' -or $choice -eq 'Find-PsEmpireElevatedPersist') {
        Find-PsEmpireElevatedPersist $cred $complist 
    }
    elseif ($choice -eq '7' -or $choice -eq 'Find-PsEmpireDebuggerPersist') {
        Find-PsEmpireDebuggerPersist $cred $complist 
    }
    elseif ($choice -eq '8' -or $choice -eq 'Find-PsEmpireSchtaskPersist') {
        Find-PsEmpireSchtaskPersist $cred $complist 
    }
    elseif ($choice -eq '9' -or $choice -eq 'Find-PsEmpireWMIPersist') {
        Find-PsEmpireWMIPersist $cred $complist 
    }
    elseif ($choice -eq '10' -or $choice -eq 'Check-Connections') {
        Check-Connections $cred $complist 
    }
    elseif ($choice -eq '11' -or $choice -eq 'Find-Files') {
        Find-Files $cred $complist 
    }
}







































