Function Copy-FileFast
{
<#
.DESCRIPTION
Uses Robocopy to quickly copy folders.

.PARAMETER FSrc
Source folder

.PARAMETER FDst
Destination folder

#>
    param( 
        [string]$FSrc,
        [string]$FDst
    )
    $ExitCode = 0
    if (-not (test-path $FSrc)) { Write-Error "Source path does not exist"; $ExitCode = -1 }

    if (test-path $FDst) { Write-Error "Target path already exists"; $ExitCode = -2 }

    if ( -not $ExitCode ) {

        $roboargs  = ""
        $roboargs += "/E "  ;# /E :: copy subdirectories, including Empty ones.
                    ;# keep the folder structure

        $roboargs += "/MT:128 " ;# /MT[:n] :: Do multi-threaded copies with n threads (default 8).
                    ;# pump up the thread count!

        $roboargs += "/XJ "     ;# /XJ :: eXclude symbolic links (for both files and directories) and Junction points.
                    ;# don't bother with links

        $roboargs += "/R:8 "    ;# /R:n :: number of Retries on failed copies: default 1 million.
                    ;# don't want to wait for 1,000,000 tries on a locked file

        $roboargs += "/W:5 "     ;# /W:n :: Wait time between retries: default is 30 seconds.
        $roboargs += "/NS "      ;# /NS :: No Size - don't log file sizes.
        $roboargs += "/NC "      ;# /NC :: No Class - don't log file classes.
        $roboargs += "/NFL "     ;# /NFL :: No File List - don't log file names.
        $roboargs += "/NDL "     ;# /NDL :: No Directory List - don't log directory names.
        $roboargs += "/NP "      ;# /NP :: No Progress - don't display percentage copied.
                     ;# log as little as possible to focus on the copy

        $roboargs += "/LOG:" + "$env:Appdata\RoboLog-" + (get-date  -Format MMdd-hhmm) + ".txt"
                    ;# /LOG:file :: output status to LOG file (overwrite existing log).
                    ;# change this to simply "Robolog.txt" if you don't want to keep a record

        $roboout = robocopy $FSrc $FDst $roboargs
                    ;# look into try {} catch {} for this
    }

    return $ExitCode
}
