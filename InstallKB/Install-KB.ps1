$updates = "remote path to updates"
$localpath = "Local path to patches"
$hotfixes = (Get-Hotfix).HotFixID

$updatelist = get-childitem $updates -recurse | where {$_.extension -eq ".msu"}
foreach($update in $updatelist){
    if(!(test-path -Path "$($localpath)\$($update.Name)")){
        Write-Host "Copying file to local directory"
        Copy-Item -Path $update.FullName -Destination $localpath
    }
}

$KBArrayList = New-Object -TypeName System.Collections.ArrayList #KBs list
$KBs = Get-ChildItem -Recurse -Filter *x64*msu* "$localpath" | Select-Object Directory, Name #We only get the files with "x64" and "msu"

foreach ($KB in $($KBs | select -ExpandProperty "Name")) { #In order to have PowerShell 2 compatibility
    $splitUp = $KB -split "kb" #Cut the name file with "kb" as separator
    $KB = "KB" + $splitUp[1].ToUpper() #We get the element n°1 (KB name). The element 0 is the path. ToUpper() convert the name in uppercase.
    $splitUp = $KB -split "-" #Cut the name file with "-" as separator
    $KB = $splitUp[0].ToUpper() #We get the element n°1 (KB name). The element 0 is the path. ToUpper() convert the name in uppercase.
    $KBArrayList.AddRange(@("$KB")) #We add the KN name to our KBArrayList list
}
write-host $hotfixes "--- KB Already Installed"
Write-Host $KBArrayList "--- KB Waiting" #show all the KBs

 
  foreach ($KB in $($KBArrayList | Where-Object { $_ -match ".*KB.*" } | select -Unique)) { #we remove duplicate KBs from the list and we only get elements where the word KB is present.
    
    if (!(Get-Hotfix -Id $KB -ErrorAction SilentlyContinue)) {
        Write-Host "$KB update is going to be installed"
        $KB_dir = $KBs | Where-Object { $_.Name -match ".*$($KB.ToLower()).*" } | select -First 1 -expand Directory #get the directory where the KB is. First 1 allows to only get the first occurence. Expand allows to convert current objet in string format.
        $KB_name = $KBs | Where-Object { $_.Name -match ".*$($KB.ToLower()).*" } | select -First 1 -expand Name #get the KB name. First 1 allows to only get the first occurence. Expand allows to convert current objet in string format.
        Write-Host "Start-Process -FilePath wusa.exe -ArgumentList `"$KB_dir\$KB_name`" /quiet /norestart -Wait" #Show the command
        Start-Process -FilePath wusa.exe -ArgumentList "`"$KB_dir\$KB_name`"" -Wait #KB installation

    } else {
        Write-Host "$KB is already installed"
    }
}
