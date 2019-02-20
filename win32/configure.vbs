' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' Nharu Library
' Copyleft (C) 2015 by The Crypthing Initiative
' Environment for Windows Development
'
' Nharu Library is free software: you can redistribute it and/or
' modify it under the terms of the GNU Lesser General Public License
'    as published by the Free Software Foundation; either version 3
'    of the License, or (at your option) any later version.
'
' Nharu Library is distributed in the hope that it will be useful,
'    but WITHOUT ANY WARRANTY; without even the implied warranty of
'    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
'    General Public License for more details.
'
' You should have received copies of the GNU General Public License and
'    the GNU Lesser General Public License along with this program.  If
'    not, see <https://www.gnu.org/licenses/lgpl.txt>. */
'
' -----------------------------
' Run with cscript
' -----------------------------
' Possible arguments
'	/proxy:[ip:port]: Proxy server for Internet connection, if needed
'	/user:[proxy user]: Proxy server user for authentication, if necessary
'	/pwd:[password]: Proxy server password
'
' Required software
' -----------------------------
' MS Visual Studio Community	Required to to build native library		https://visualstudio.microsoft.com/pt-br/downloads/
' Git							Software configuration management		https://git-scm.com/
' Dr. Memory Debugger			Required to look for memory leaks		https://drmemory.org/
' Netwide Assembler				Required to compile OpenSSL				https://www.nasm.us/
' Active Perl					Required to compile OpenSSL 			http://www.activestate.com/activeperl
' Java Development Kit 32 bits	Required to build						http://www.oracle.com/technetwork/java/javase/downloads/
' Apache Ant					Required to build						https://ant.apache.org/
' Ant Contrib Tasks				Required to build						http://ant-contrib.sourceforge.net/
' Open SSL						Nharu dependency						https://github.com/openssl/openssl
' GNU Libidn					Nharu dependency						https://git.savannah.gnu.org/git/libidn.git
'
' -----------------------------
' Authors:
' 		diego.sohsten@gmail.com
' 		yorick.flannagan@gmail.com
' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *


Const VS_INSTALL_PATH		= 0
Const GIT_INSTALL_PATH		= 1
Const DRMEM_INSTALL_PATH	= 2
Const NASM_INSTALL_PATH		= 3
Const PERL_INSTALL_PATH		= 4
Const JAVA_INSTALL_PATH		= 5
Const ANT_INSTALL_PATH		= 6
Const ANTC_INSTALL_PATH		= 7
Const SSL_INSTALL_PATH		= 8
Const IDN_INSTALL_PATH		= 9


Const HKEY_LOCAL_MACHINE	= &H80000002
Const INSTALLER_REGKEY		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders"
Const GIT_REGKEY			= "HKEY_LOCAL_MACHINE\SOFTWARE\GitForWindows\InstallPath"
Const NASM_REGKEY			= "HKEY_CURRENT_USER\Software\nasm\"
Const PERL_REGKEY			= "HKEY_LOCAL_MACHINE\SOFTWARE\Perl\"

Dim ARG_PROXY
Dim ARG_USER
Dim ARG_PWD

Main
Sub Main

	Dim args : Set args = Nothing
	Dim argProxy, argUser, argPwd
	Dim products
	On Error Resume Next

	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library                                    "
	WScript.Echo " Environment for Windows development configuration"
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo ""

	Set args = WScript.Arguments.Named
	If args.Exists("proxy") Then
		ARG_PROXY = args.Item("proxy")
	End If
	If args.Exists("user") Then
		ARG_USER = args.Item("user")
	End If
	If args.Exists("pwd") Then
		ARG_PWD = args.Item("pwd")
	End If
	Set args = Nothing

	products = GetInstalledProducts()

	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Environment for Windows development configured   "
	WScript.Echo " Use dev-env.bat file to all operations           "
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"

End Sub

' Search for installed software requirements
Function GetInstalledProducts()

	Dim fs : Set fs = Nothing
	Dim ret(10), msiFiles
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	msiFiles = fs.GetParentFolderName(WScript.ScriptFullName) & "\temp"
	If Not fs.FolderExists(msiFiles) Then
		fs.CreateFolder(msiFiles) : CheckError
	End If

	ret(VS_INSTALL_PATH)	= EnsureInstallVS()
	ret(GIT_INSTALL_PATH)	= EnsureInstallGit(msiFiles, True)
	ret(DRMEM_INSTALL_PATH)	= EnsureInstallDrMem(msiFiles, True)
	ret(NASM_INSTALL_PATH)	= EnsureInstallNASM(msiFiles, True)
	ret(PERL_INSTALL_PATH)	= EnsureInstallPerl(msiFiles, True)
	ret(JAVA_INSTALL_PATH)	= EnsureInstallJava()
	ret(ANT_INSTALL_PATH)	= EnsureInstallAnt(msiFiles & "\ant.zip", True)
	ret(ANTC_INSTALL_PATH)	= EnsureInstallAntContrib(msiFiles & "\antc.zip", True)
	ret(SSL_INSTALL_PATH)	= EnsureInstallOpenSSL(ret(GIT_INSTALL_PATH), True)
	ret(IDN_INSTALL_PATH)	= EnsureInstallLibidn(ret(GIT_INSTALL_PATH), True)

	If fs.FolderExists(msiFiles) Then
		Dim folder
		Set folder = fs.GetFolder(msiFiles)
		If folder.Files.Count = 0 Then
			fs.DeleteFolder(msiFiles)
		End If
		Set folder = Nothing
	End If
	Set fs = Nothing
	GetInstalledProducts = ret

End Function

' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' Ensures that softaware requirements have been met
' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' Check Microsoft Visual Studio
Function EnsureInstallVS()

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError

	stdout.Write("Searching for Visual Studio... ")
	ret = GetVSInstallPath() : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallVS = ret
	Else
		stdout.WriteLine("Visual Studio 2017 must be previously installed.")
		stdout.WriteLine("Please, download it from https://visualstudio.microsoft.com/pt-br/downloads/,")
		stdout.WriteLine("install it and run this configure.vbs again.")
		stdout.WriteBlankLines(1)
		WScript.Quit 2
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function
Function GetVSInstallPath()

	Const VSWHERE = "\Microsoft Visual Studio\Installer\vswhere.exe"
	Const PATH_STRING = "installationPath:"
	Dim exe, vs32, vs64
	Dim fs : Set fs = Nothing
	Dim shell : Set shell = Nothing
	Dim ret : Set ret = Nothing
	On Error Resume Next

	Set fs = CreateObject("Scripting.FileSystemObject") : CheckError
	Set shell = CreateObject("WScript.Shell") : CheckError
	vs32 = shell.ExpandEnvironmentStrings("%ProgramFiles(x86)%") & VSWHERE
	vs64 = shell.ExpandEnvironmentStrings("%ProgramFiles%") & VSWHERE
	If fs.FileExists(vs32) Then
		exe = vs32
	ElseIf fs.FileExists(vs64) Then
		exe = vs64
	Else
		Set fs = Nothing
		Set shell = Nothing
		Exit Function
	End If
	Set ret = shell.Exec(exe)
	If ret.ExitCode() = 0 Then
		Dim line
		Do While Not ret.StdOut.AtEndOfStream
			line = ret.StdOut.ReadLine()
			If InStr(1, line, PATH_STRING, vbTextCompare) <> 0 Then
				GetVSInstallPath = Trim(Mid(line, Len(PATH_STRING) + 1)) & "\"
				Exit Do
			End If
		Loop
	End If
	Set fs = Nothing
	Set shell = Nothing

End Function

' Gets Git SCM installation path
' Arguments:
'	target: temporary directory files should be downloaded, if necessary
'	try: True if it should be downloaded and executed
Function EnsureInstallGit(target, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError

	stdout.Write("Searching for Git SCM... ")
	ret = GetRegistryValue(GIT_REGKEY) : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallGit = ret & "\"
	Else
		If try Then
			TryInstallProduct "Git SM", "https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe", target & "\git.exe"
			EnsureInstallGit = EnsureInstallGit(target, False)
		Else
			stdout.WriteLine("Could not download and/or install  Git SCM")
			stdout.WriteLine("Please, download it from https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Dr. Memory installation path
' Arguments:
'	target: temporary directory files should be downloaded, if necessary
'	try: True if it should be downloaded and executed
Function EnsureInstallDrMem(target, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError

	stdout.Write("Searching for Dr. Memory Debugger... ")
	ret = GetInstallPathFromInstaller("Dr. Memory") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallDrMem = ret
	Else
		If try Then
			TryInstallProduct "Dr. Memory Debugger", "https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Windows-1.11.0-2.msi", target & "\drmem.msi"
			EnsureInstallDrMem = EnsureInstallDrMem(target, False)
		Else
			stdout.WriteLine("Could not download and/or install Dr. Memory Debugger")
			stdout.WriteLine("Please, download it from https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Windows-1.11.0-2.msi,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Netwide Assembler installation path
' Arguments:
'	target: temporary directory files should be downloaded, if necessary
'	try: True if it should be downloaded and executed
Function EnsureInstallNASM(target, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError

	stdout.Write("Searching for Netwide Assembler... ")
	ret = GetRegistryValue(NASM_REGKEY) : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallNASM = ret & "\"
	Else
		If try Then
			TryInstallProduct "Netwide Assembler", "https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/nasm-2.14.02-installer-x86.exe", target & "\nasm.exe"
			EnsureInstallNASM = EnsureInstallNASM(target, False) & "\"
		Else
			stdout.WriteLine("Could not download and/or install Netwide Assembler")
			stdout.WriteLine("Please, download it from https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/nasm-2.14.02-installer-x86.exe,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Active Perl installation path
' Arguments:
'	target: temporary directory files should be downloaded, if necessary
'	try: True if it  should be downloaded and executed
Function EnsureInstallPerl(target, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError

	stdout.Write("Searching for Active Perl... ")
	ret = GetRegistryValue(PERL_REGKEY) : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallPerl = ret
	Else
		If try Then
			TryInstallProduct "Active Perl", "https://downloads.activestate.com/ActivePerl/releases/5.26.3.2603/ActivePerl-5.26.3.2603-MSWin32-x64-a95bce075.exe", target & "\perl.exe"
			EnsureInstallPerl = EnsureInstallPerl(target, False) & "\"
		Else
			stdout.WriteLine("Could not download and/or install Active Perl")
			stdout.WriteLine("Please, download it from https://downloads.activestate.com/ActivePerl/releases/5.26.3.2603/ActivePerl-5.26.3.2603-MSWin32-x64-a95bce075.exe,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Java SE Development Kit installation path
Function EnsureInstallJava()

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError

	stdout.Write("Searching for Java SE Development Kit... ")
	ret = GetInstallPathFromInstaller("Java SE Development Kit") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallJava = ret
	Else
		stdout.WriteLine("Java SE Development Kit must be previously installed.")
		stdout.WriteLine("Please, download it from http://www.oracle.com/technetwork/java/javase/downloads/,")
		stdout.WriteLine("install it and run this configure.vbs again.")
		stdout.WriteBlankLines(1)
		WScript.Quit 2
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Apache Ant installation path
' Arguments:
'	temp: temporary path (with file name) to download, if necessary
'	try: True if it should be downloaded and unzipped
Function EnsureInstallAnt(temp, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim location, ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	location = fs.GetParentFolderName(fs.GetParentFolderName(fs.GetParentFolderName(WScript.ScriptFullName)))
	stdout.Write("Searching for Apache Ant... ")
	ret = FindFile(fs, location, "ant.jar") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallAnt = fs.GetParentFolderName(ret) & "\"
	Else
		If try Then
			TryUnzipDocument "Apache Ant", "http://mirror.nbtelecom.com.br/apache//ant/binaries/apache-ant-1.10.5-bin.zip", temp, location
			EnsureInstallAnt = EnsureInstallAnt(temp, False)
		Else
			stdout.WriteLine("Could not download and/or install Apache Ant")
			stdout.WriteLine("Please, download it from http://mirror.nbtelecom.com.br/apache//ant/binaries/apache-ant-1.10.5-bin.zip,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Ant Contrib Tasks installation path
' Arguments:
'	temp: temporary path (with file name) to download, if necessary
'	try: True if it should be downloaded and unzipped
Function EnsureInstallAntContrib(temp, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim location, ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	location = fs.GetParentFolderName(fs.GetParentFolderName(fs.GetParentFolderName(WScript.ScriptFullName)))
	stdout.Write("Searching for Ant Contrib Tasks... ")
	ret = FindFile(fs, location, "ant-contrib-1.0b3.jar") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallAntContrib = fs.GetParentFolderName(ret) & "\"
	Else
		If try Then
			TryUnzipDocument "Ant Contrib Tasks", "https://ufpr.dl.sourceforge.net/project/ant-contrib/ant-contrib/1.0b3/ant-contrib-1.0b3-bin.zip", temp, location
			EnsureInstallAntContrib = EnsureInstallAntContrib(temp, False)
		Else
			stdout.WriteLine("Could not download and/or install Ant Contrib Tasks")
			stdout.WriteLine("Please, download it from https://ufpr.dl.sourceforge.net/project/ant-contrib/ant-contrib/1.0b3/ant-contrib-1.0b3-bin.zip,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets OpenSSL installation path
' Arguments:
'	gitInstallPath: Git location to download OpenSSL, if necessary
'	try: True if it should be downloaded
Function EnsureInstallOpenSSL(gitInstallPath, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim location, ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	location = fs.GetParentFolderName(fs.GetParentFolderName(fs.GetParentFolderName(WScript.ScriptFullName)))
	stdout.Write("Searching for OpenSSL... ")
	ret = FindFile(fs, location, "libcrypto.lib") : Feedback stdout, ret
	If Not Empty(ret) Then
		EnsureInstallOpenSSL = fs.GetParentFolderName(ret) & "\"
	Else
		If try Then
			Dim shell : Set shell = Nothing
			Dim git, cmd, rv
			Set shell = CreateObject("Wscript.Shell") : CheckError
			SetGitEnv ret(GIT_INSTALL_PATH)
			git = """" & gitInstallPath & "git-cmd.exe"""
			cmd = git & " git clone https://github.com/openssl/openssl " & location & "\openssl"
			rv = shell.Run(cmd, 1, True)
			If rv <> 0 Then
				stdout.WriteLine("Could not clone OpenSSL Library to build it.")
				stdout.WriteLine("You must do it by yourself and run this configure.vbs again.")
				WScript.Quit 3
			End If
			' TODO: Configure and build OpenSSL
			Set shell = Nothing
			EnsureInstallOpenSSL = EnsureInstallOpenSSL(gitInstallPath, False)
		Else
			stdout.WriteLine("Could not clone and/or install OpenSSL")
			stdout.WriteLine("Please, download it from https://github.com/openssl/openssl,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Libidn installation path
' Arguments:
'	gitInstallPath: Git location to download OpenSSL, if necessary
'	try: True if it should be downloaded
Function EnsureInstallLibidn(gitInstallPath, try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim location, ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	location = fs.GetParentFolderName(fs.GetParentFolderName(fs.GetParentFolderName(WScript.ScriptFullName)))
	stdout.Write("Searching for Libidn... ")
	ret = FindFile(fs, location, "libidn.lib") : Feedback stdout, ret
	If Not Empty(ret) Then
		EnsureInstallLibidn = fs.GetParentFolderName(ret) & "\"
	Else
		If try Then
			Dim shell : Set shell = Nothing
			Dim git, cmd, rv
			Set shell = CreateObject("Wscript.Shell") : CheckError
			SetGitEnv ret(GIT_INSTALL_PATH)
			git = """" & gitInstallPath & "git-cmd.exe"""
			cmd = git & " git clone https://git.savannah.gnu.org/git/libidn.git " & location & "\libidn"
			rv = shell.Run(cmd, 1, True)
			If rv <> 0 Then
				stdout.WriteLine("Could not clone Libidn Library to build it.")
				stdout.WriteLine("You must do it by yourself and run this configure.vbs again.")
				WScript.Quit 3
			End If
			' TODO: Configure and build Libidn
			Set shell = Nothing
			EnsureInstallLibidn = EnsureInstallLibidn(gitInstallPath, False)
		Else
			stdout.WriteLine("Could not clone and/or install OpenSSL")
			stdout.WriteLine("Please, download it from https://git.savannah.gnu.org/git/libidn.git,")
			stdout.WriteLine("install it and run this configure.vbs again.")
			stdout.WriteBlankLines(1)
			WScript.Quit 2
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function


' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' General utilities
' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Sub Feedback(stdout, value)

	If Not IsEmpty(value) Then
		stdout.WriteLine("Found!")
	Else
		stdout.WriteLine("Not found!")
	End If	

End Sub

' Set http.proxy variable to Git use
' Arguments:
'	gitInstallPath: Git install folder
Sub SetGitEnv(gitInstallPath)

	Dim shell : Set shell = Nothing
	Dim git, cmd, rv
	On Error Resume Next

	Set shell = CreateObject("Wscript.Shell") : CheckError
	git = """" & gitInstallPath & "git-cmd.exe"""
	If Not Empty(ARG_PROXY) Then
		cmd = git & " git config --global --get http.proxy"
		rv = shell.Run(cmd, 0, True)
		If rv <> 0 Then
			cmd = git & " git config --global http.proxy http://" & ARG_PROXY
			rv = shell.Run(cmd, 0, True)
			If rv <> 0 Then
				WScript.Echo "Could not set Git environment to clone Nharu Library."
				WScript.Echo "You must do it by yourself and run this configure.vbs again."
				WScript.Quit 3
			End If
		End If
	End If
	Set shell = Nothing

End sub

' Gets value of specified registry key
' Arguments:
'	Key: complete path to registry key
Function GetRegistryValue(key)

	Dim shell : Set shell = Nothing
	Dim value
	On Error Resume Next

	Set shell = WScript.CreateObject("WScript.Shell") : CheckError
	value = shell.RegRead(key)
	If Err.number = 0 Then GetRegistryValue = value
	Set shell = Nothing

End Function

' Gets install location using Windows Installer
Function GetInstallPathFromInstaller(productName)

	Dim product, value
	Dim installer : Set installer = Nothing
	Dim products : Set products = Nothing
	On Error Resume Next

	Set installer = Wscript.CreateObject("WindowsInstaller.Installer") : CheckError
	Set products = installer.Products : CheckError
	For Each product In products
		value = installer.ProductInfo(product, "ProductName") : CheckError
		If InStrRev(value, productName, -1, vbTextCompare) <> 0 Then 
			value = installer.ProductInfo(product, "InstallLocation") : CheckError
			If value <> Empty Then GetInstallPathFromInstaller = value
			Exit For
		End If 
	Next
	Set products = Nothing
	Set installer = Nothing

End Function

' Finds specified file name and returns its location, if found
' Arguments
'	fs: an instance of Scripting.FileSystemObject
'	folderName: the folder where the current search begins
'	fileName: the file to find
Function FindFile(fs, folderName, fileName)

	Dim file, folder
	Dim current : Set current = Nothing
	On Error Resume Next

	Set current = fs.GetFolder(folderName) : CheckError
	For Each file In current.Files
		If StrComp(file.Name, fileName, vbTextCompare) = 0 Then
			FindFile = current.Path & "\"
			Set current = Nothing
			Exit Function
		End If
	Next
	For Each folder In current.SubFolders
		file = FindFile(fs, folder.Path, fileName)
		If Not IsEmpty(file) Then
			FindFile = file
			Set current = Nothing
			Exit Function
		End If
	Next
	Set current = Nothing

End Function

' Downloads specified Windows Installer and run it t install
' Arguments:
'	productName: Label for executions
'	uri: URI of Windows installer of product
'	target: MSI file name and path. It is removed if all succeeds
Sub TryInstallProduct(productName, uri, target)

	If Not DownloadFile(productName, uri, target) Then Exit Sub
	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim shell : Set shell = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1)
	Set shell = CreateObject("Wscript.Shell") : CheckError
	stdout.WriteLine("Running installer at " & target & "...")
	ret = shell.Run(target, 0, True)
	If ret = 0 Then
		fs.DeleteFile(target)
	Else
		stdout.WriteLine("Installer returned error level " & ret)
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing
	Set shell = Nothing

End Sub

' Downloads specified Zip file and uncompress it
' Arguments:
'	document: Label for executions
'	uri: URI of zip file
'	temp: temporary folder to download document
'	target: folder where document should be unzipped
Sub TryUnzipDocument(document, uri, temp, target)

	If Not DownloadFile(document, uri, temp) Then Exit Sub
	Dim fs : Set fs = Nothing
	Dim shell : Set shell = Nothing
	Dim oSource : Set oSource = Nothing
	Dim oTarget : Set oTarget = Nothing
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	If Not fs.FolderExists(target) Then
		fs.CreateFolder(target) : CheckError
	End If
	Set shell = CreateObject("Shell.Application") : CheckError
	Set oSource = shell.NameSpace(temp).Items()
	Set oTarget = shell.NameSpace(target)
	oTarget.CopyHere oSource, 256
	fs.DeleteFile(temp)
	Set oSource = Nothing
	Set oTarget = Nothing
	Set fs = Nothing
	Set shell = Nothing

End Sub

' Downloads a product
' Arguments:
'	productName: Label for executions
'	uri: URI of file to download
'	target: file name to be created when download ends
Function DownloadFile(productName, uri, target)

	Dim cmd
	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim shell : Set shell = Nothing
	Dim ret
	On Error Resume Next

	cmd = "wget.exe "
	If Not IsEmpty(ARG_PROXY) Then
		If InStr(uri, "https") = 1 Then
			cmd = cmd & "-e https_proxy=" & ARG_PROXY & " --no-check-certificate"
		Else
			cmd = cmd & "-e http_proxy=" & ARG_PROXY
		End If
		If Not IsEmpty(ARG_USER) Then
			cmd = cmd & " --proxy-user=" & ARG_USER
		End If
		If Not IsEmpty(ARG_PWD) Then
			cmd = cmd & " --proxy-password=" & ARG_PWD
		End If
	End If
	cmd = cmd & " --output-document=" & target & " " & uri

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1)
	Set shell = CreateObject("Wscript.Shell") : CheckError
	stdout.WriteLine("Downloading " & productName & " to " & target & "...")
	ret = shell.Run(cmd, 1, True)
	If ret = 0 Then
		DownloadFile = True
	Else
		stdout.WriteLine("WGET failed to download installer with error level " & ret)
		If fs.FileExists(target) Then
			fs.DeleteFile(target)
		End If
		DownloadFile = False
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing
	Set shell = Nothing

End Function

' Error check
Sub CheckError

	Dim message
	If Err.number <> 0 Then
		WScript.Echo "An error number " & Err.number & " of type " & Err.Source & "has occurred: " & Err.Description
		Wscript.Quit 1
	End If

End Sub
