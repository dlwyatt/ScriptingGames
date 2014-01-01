cls

del *.html

#.\AnalyzePermissions.ps1 -RootFolder C:\Users\Dave\Desktop\Finance -CsvPath .\Permissions.csv -OutputDirectory .
.\AnalyzePermissions.ps1 -RootFolder C:\Users\Dave\Desktop\Finance -CsvPath .\Permissions.csv -FixPermissions -Verbose

#dir .\*.html | Invoke-Item
