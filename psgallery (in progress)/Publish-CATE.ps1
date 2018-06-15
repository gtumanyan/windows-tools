$ReleaseNotes = @(
	"CATE - Clean All Temp Etc",
	"Cleans temporary files and folders from all standard user temp folders,",
	"system profile temp folders, and system temp folders (they are not the same!);",
	"also clears logs, IE caches, Firefox caches, Chrome caches, Ask Partner Network data,",
	"Adobe Flash caches, Java deployment caches, and Microsoft CryptnetURL caches."
	)

Update-ScriptFileInfo -Path .\CATE.ps1 -Version 3.54 `
	-Author "Jonathan E. Brickman" `
	-Description "Clean All Temp Etc - cleans temporary files and folders from all standard user and system temp folders, clears logs, and more" `
	-ReleaseNotes $ReleaseNotes `
	-CompanyName "Ponderworthy Music" `
	-Copyright "(c) 2018 Jonathan E. Brickman" `
	-Force

Publish-Script -Path .\CATE.ps1 -NuGetApiKey 6f05b805-b551-403f-9b05-b45fb420c69b