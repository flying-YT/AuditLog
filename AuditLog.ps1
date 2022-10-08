#version 1.0

$logonSuccessId = 4624
$logonFailId = 4625
$logoffCompId = 4634

$logonId = 7001
$logoutId = 7002

#Initialize variable for date
$date = ""

#There are arguments when calling from a bat file, no arguments when calling from the task scheduler
if($Args[0] -eq $null){
    $date = (Get-Date).AddDays(-1).ToString("yyyy/MM/dd") #Startup is the day after the target date, so reduce by 1 day
}else{
    $date = $Args[0].ToString().Substring(0,4) + "/" + $Args[0].ToString().Substring(4,2) + "/" + $Args[0].ToString().Substring(6,2)
}

#Set start time and end time
$startDate = $date + " 00:00:00"
$datetime = [DateTime]::ParseExact($date, "yyyy/MM/dd", $null)
$endDate = $datetime.AddDays(1).ToString("yyyy/MM/dd ") + " 00:00:00"

#Output Path
$fileNameDate = [DateTime]::ParseExact($date, "yyyy/MM/dd", $null)
$logfile = "D:\AuditLog/AuditLog_" + $fileNamedate.ToString("yyyyMMdd") + ".txt";

#Create file
New-Item $logfile -Force;
cls

#Coverage confirmation
$now = (Get-Date);
$duration = New-TimeSpan $now $datetime;

if(-31 -lt $duration.Days -and $duration.Days -lt 1){

    #Log extraction
    $LogonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startDate; EndTime=$endDate} | Where-Object {($_.Id -eq $logonSuccessId) -or ($_.Id -eq $logonFailId) -or ($_.Id -eq $logoffCompId)}
    $systemEventsLogon = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startDate; EndTime=$endDate} | Where-Object{$_.ID -eq $logonId -or $_.ID -eq $logoutId}

    #message creation
    $textMsg = @();
    $textMsg += "Period  " + $startDate + " - " + $endDate;
    $textMsg += "--------------------------------------------------------";
    $textMsg += "Login Logout Report";
    $textMsg += "--------------------------------------------------------";

    #File output
    Write-Output $textMsg | Add-Content $logfile;

    $Status = @()
    foreach($systemEvent in $systemEventsLogon){
        if($systemEvent.ID -eq 7001){ #Logon

            foreach($LogonEvent in $LogonEvents){
                $xml = [XML]$LogonEvent.ToXml()
                $logonType = ($Xml.Event.EventData.Data | ? {$_.Name -eq "LogonType"}).'#text'
                $targetDomainName = ($Xml.Event.EventData.Data | ? {$_.Name -eq "TargetDomainName"}).'#text'
                $account = ($Xml.Event.EventData.Data | ? {$_.Name -eq "TargetUserName"}).'#text'

                if($targetDomainName -ne "Window Manager" -and $targetDomainName -ne "Font Driver Host"){
                    if(($logonType -eq 2) -or ($logonType -eq 3) -or ($logonType -eq 11) -or ($logonType -eq 10)){
                        $timeSpan = $systemEvent.TimeCreated - $LogonEvent.TimeCreated;
                        #Less than 1500 millisecond difference
                        if(-1500 -lt $timeSpan.TotalMilliseconds -and $timeSpan.TotalMilliseconds -lt 1500){
                            if($LogonEvent.Id -eq $logonSuccessId){
                                $Status += New-Object PSObject -Property @{Account=$account; Time=$systemEvent.TimeCreated; event="logon";}
                                break
                            }
                        }
                    }
                }
            }

        }elseif($systemEvent.ID -eq 7002){ #Logoff
            foreach($LogonEvent in $LogonEvents){
                $xml = [XML]$LogonEvent.ToXml()
                $logonType = ($Xml.Event.EventData.Data | ? {$_.Name -eq "LogonType"}).'#text'
                $targetDomainName = ($Xml.Event.EventData.Data | ? {$_.Name -eq "TargetDomainName"}).'#text'
                $account = ($Xml.Event.EventData.Data | ? {$_.Name -eq "TargetUserName"}).'#text'

                if($targetDomainName -ne "Window Manager" -and $targetDomainName -ne "Font Driver Host"){
                    if(($logonType -eq 2) -or ($logonType -eq 3) -or ($logonType -eq 10) -or ($logonType -eq 11)){
                        $timeSpan = $systemEvent.TimeCreated - $LogonEvent.TimeCreated;
                        #Less than 1500 millisecond difference
                        if(-1500 -lt $timeSpan.TotalMilliseconds -and $timeSpan.TotalMilliseconds -lt 1500){
                            if($LogonEvent.Id -eq $logoffCompId){
                                $Status += New-Object PSObject -Property @{Account=$account; Time=$systemEvent.TimeCreated; event="logoff";}
                                break
                            }
                        }
                    }
                }
            }
        }
    }
    [array]::Reverse($Status);
    Write-Output $Status | Format-Table -Property Account, Time, event >> $logfile;

    #message creation
    $textMsg = @();
    $textMsg += "`r`n";
    $textMsg += "--------------------------------------------------------";
    $textMsg += "Login Failure Report";
    $textMsg += "--------------------------------------------------------";

    #File output
    Write-Output $textMsg | Add-Content $logfile;

    $Status = @();
    foreach($LogonEvent in $LogonEvents){
        if($LogonEvent.Id -eq $logonFailId){
            $Xml = [xml]$LogonEvent.ToXml();
            $account = ($Xml.Event.EventData.Data | ? {$_.Name -eq "TargetUserName"}).'#text'
            $Ip = ($Xml.Event.EventData.data | ? {$_.Name -eq "IpAddress"}).'#text'

            $Status += New-Object PSObject -Property @{Account=$account; Time=$LogonEvent.TimeCreate; Ip=$Ip};
        }
    }
    [array]::Reverse($Status);
    Write-Output $Status | Format-Table -Property Account, Time, Ip >> $logfile;

    foreach($text in Get-Content $logfile){
        Write-Host $text;
    }

}else{
    echo out of term
    $print = Read-Host "Please Enter";
}
