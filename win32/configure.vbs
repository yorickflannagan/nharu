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
' -----------------------------
' Authors:
' 		diego.sohsten@gmail.com
' 		yorick.flannagan@gmail.com
' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *


' Encapsultes a proxy definition
Class Proxy

	Public Server, User, Pwd

	' Sets Proxy object from command line arguments
	Public Sub FromArguments

		Dim args : Set args = Nothing
		Set args = WScript.Arguments.Named

		If args.Exists("proxy") Then
			Server = args.Item("proxy")
		End If
		If args.Exists("user") Then
			User = args.Item("user")
		End If
		If args.Exists("pwd") Then
			Pwd = args.Item("pwd")
		End If
		Set args = Nothing

	End Sub

End Class

' Encapsulates GNU WGet operation
Class WGet

	Private m_location, m_proxy

	' Configures object to download
	' Arguments:
	'	wgetLocation: folder where wget.exe lies
	'	oProxy: instance of Proxy class
	Public Sub Configure(wgetLocation, oProxy)

		If Not FolderExists(wgetLocation) Or Not FileExists(wgetLocation & "\wget.exe") Then Err.Raise 1, "WGet.Configure", "Argument must point to an existing wget.exe"
		mm_location = """" & wgetLocation & "\wget.exe"""
		Set m_proxy = oProxy

	End Sub

	' Downloads a file
	' Arguments:
	'	name: label for feedeback
	'	uri: resource location
	'	target: complete path to downloaded resource
	Public Function Download(name, uri, target)

		If IsEmpty(mm_location) Or IsEmpty(m_proxy) Then Err.Raise 2, "WGet.Download", "Object improperly initialized"
		Dim cmd
		Dim shell : Set shell = Nothing
		Dim ret

		cmd = mm_location
		If Not IsEmpty(m_proxy.Server) Then
			If InStr(uri, "https") = 1 Then
				cmd = cmd & " -e httpsm_proxy=" & m_proxy.Server & " --no-check-certificate"
			Else
				cmd = cmd & " -e httpm_proxy=" & m_proxy.Server
			End If
			If Not IsEmpty(m_proxy.User) Then
				cmd = cmd & " --proxy-user=" & m_proxy.User
			End If
			If Not IsEmpty(m_proxy.Pwd) Then
					cmd = cmd & " --proxy-password=" & m_proxy.Pwd
			End If
		End If
		cmd = cmd & " --output-document=" & target & " " & uri

		Set shell = CreateObject("Wscript.Shell")
		ret = shell.Run(cmd, 1, True)
		If ret <> 0 Then
			Dim fs : Set fs = Nothing
			Set fs = CreateObject ("Scripting.FileSystemObject")
			If fs.FileExists(target) Then
				fs.DeleteFile(target)
			End If
			Set fs = Nothing
		End If
		Download = ret
		
		Set shell = Nothing

	End Function

End Class

' Install facility
Class Installer

	' WGet instance
	Public Getter

	' Dowloads and executes specified installer
	' Arguments:
	'	name: execution label
	'	source: URI where installer lies
	Public Sub Install(name, source)

		Dim target, rv
		Dim shell : Set shell = Nothing

		CheckGetter
		target = GetTempName()
		rv = Getter.Download(name, source, target)
		If rv <> 0 Then Err.Raise rv, "Installer.Install", "WGet facility failed to download resource"

		Set shell = CreateObject("Wscript.Shell")
		rv = shell.Run(target, 0, True)
		DeleteFile target
		Set shell = Nothing
		If rv <> 0 Then Err.Raise rv, "Installer.Install", "Installer failed"

	End Sub

	' Dowloads and unzips specified resource
	' Arguments:
	'	name: resource name. The files are copied to name
	'	source: URI where resource lies
	'	target: destination folder
	Public Sub Unzip(name, source, target)

		Dim temp, rv
		Dim fs : Set fs = Nothing
		Dim shell : Set shell = Nothing
		Dim oSource : Set oSource = Nothing
		Dim oTarget : Set oTarget = Nothing

		CheckGetter
		temp = GetTempName()
		rv = Getter.Download(name, source, temp)
		If rv <> 0 Then Err.Raise rv, "Installer.Unzip", "WGet facility failed to download resource"

		Set fs = CreateObject ("Scripting.FileSystemObject")
		If Not fs.FolderExists(name) Then
			fs.CreateFolder(name)
		End If
		Set shell = CreateObject("Shell.Application")
		Set oSource = shell.NameSpace(temp).Items()
		Set oTarget = shell.NameSpace(target)
		oTarget.CopyHere oSource, 256
		fs.DeleteFile(target)
		Set oSource = Nothing
		Set oTarget = Nothing
		Set fs = Nothing
		Set shell = Nothing

	End Sub
	
	Private Sub CheckGetter

		Dim oProxy : Set oProxy = Nothing
		Dim fs : Set fs = Nothing
		Dim location

		If IsEmpty(Getter) Then
			Set oProxy = New Proxy
			oProxy.FromArguments
			Set Getter = New WGet
			Set fs = CreateObject ("Scripting.FileSystemObject")
			Getter.Configure fs.GetParentFolderName(WScript.ScriptFullName), oProxy
			Set fs = Nothing
		End If 

	End Sub

End Class

' Encapsulates Git SCM
Class GitSCM

	Private mm_location, m_proxy


	' Configures object to download
	' Arguments:
	'	gitLocation: folder where git-cmd.exe lies
	'	oProxy: instance of Proxy class
	Public Sub Configure(gitLocation, oProxy)

		If Not FolderExists(gitLocation) Or Not FileExists(gitLocation & "\git-cmd.exe") Then Err.Raise 1, "GitSCM.Configure", "Argument must point to an existing git-cmd.exe"
		mm_location = """" & gitLocation & "\git-cmd.exe"""
		Set m_proxy = oProxy

	End Sub

	' Sets Git SCM proxy global environment, if necessary
	Public Sub SetEnv

		If IsEmpty(m_location) Or IsEmpty(m_proxy) Then Err.Raise 2, "GitSCM.SetEnv", "Object improperly initialized"
		If IsEmpty(m_proxy.Server) Then Exit Sub
		Dim shell : Set shell = Nothing
		Dim cmd, rv

		Set shell = CreateObject("Wscript.Shell")
		cmd = m_location & " git config --global http.proxy http://"
		If Not IsEmpty(m_proxy.User) And Not IsEmpty(m_proxy.Pwd) Then
			cmd = cmd & m_proxy.User & ":" & m_proxy.Pwd & "@"
		End If
		cmd = cmd & m_proxy.Server
		rv = shell.Run(m_location & " git config --global --get http.proxy", 0, True)
		If rv <> 0 Then
			rv = shell.Run(cmd, 0, True)
			If rv <> 0 Then Err.Raise 2, "GitSCM.SetEnv", "Failed to set Git global http.proxy"
			rv = shell.Run(m_location & " git config --global --get https.proxy", 0, True)
			If rv <> 0 Then
				cmd = Replace(cmd, "http.proxy", "https.proxy")
				rv = shell.Run(cmd, 0, True)
				If rv <> 0 Then Err.Raise 2, "GitSCM.SetEnv", "Failed to set Git global https.proxy"
			End If
		End If
		Set shell = Nothing
		
	End Sub

	' Clones specified Git repository
	' Arguments:
	'	uri: Git repository identifier
	'	target: folder where to clone. Must no exists
	Public Function Clone(uri, target)

		If IsEmpty(m_location) Or IsEmpty(m_proxy) Then Err.Raise 2, "GitSCM.Clone", "Object improperly initialized"
		If FolderExists(target) Then err.Raise 3, "GitSCM.Clone", "Target directory must not exists"
		Dim shell : Set shell = Nothing

		Set shell = CreateObject("Wscript.Shell")
		Clone = shell.Run(m_location & " git clone " & uri & " " & target, 1, True)
		Set shell = Nothing

	End Function

End Class

' Implements a file finder
Class Finder

	' Folder where the search must start
	Public StartFolder

	' Finds specified file name and returns its location, if found
	' Arguments
	'	fileName: the file to find
	Public Function Find(fileName)
	
		Dim fs : Set fs = Nothing
		
		Set fs = CreateObject ("Scripting.FileSystemObject")
		If IsEmpty(StartFolder) Then StartFolder = fs.GetParentFolderName(WScript.ScriptFullName)
		Find = FindFile(fs, StartFolder, fileName)
		Set fs = Nothing

	End Function

	' Finds specified file name and returns its location, if found
	' Arguments
	'	fs: an instance of Scripting.FileSystemObject
	'	folderName: the folder where the current search begins
	'	fileName: the file to find
	Private Function FindFile(fs, folderName, fileName)
	
		Dim file, folder, found
		Dim current : Set current = Nothing

		Set current = fs.GetFolder(folderName)
		For Each file In current.Files
			If StrComp(file.Name, fileName, vbTextCompare) = 0 Then
				found = current.Path
				Exit For
			End If
		Next
		If IsEmpty(found) Then
			For Each folder In current.SubFolders
				file = FindFile(fs, folder.Path, fileName)
				If Not IsEmpty(file) Then
					found = file
					Exit For
				End If
			Next
		End If 
		Set current = Nothing
		If Not IsEmpty(found) Then FindFile = found
	
	End Function


End Class

' Shortcut for Scripting.FileSystemObject.FolderExists
Function FolderExists(name)

	Dim fs : Set fs = Nothing
	Set fs = CreateObject("Scripting.FileSystemObject")
	FolderExists = fs.FolderExists(name)
	Set fs = Nothing

End Function

' Shortcut for Scripting.FileSystemObject.FileExists
Function FileExists(name)

	Dim fs : Set fs = Nothing
	Set fs = CreateObject ("Scripting.FileSystemObject")
	FileExists = fs.FileExists(name)
	Set fs = Nothing

End Function

' Shortcut for Scripting.FileSystemObject.DeleteFile
Sub DeleteFile(target)

	Dim fs : Set fs = Nothing
	Set fs = CreateObject ("Scripting.FileSystemObject")
	fs.DeleteFile(target)
	Set fs = Nothing

End Sub

' Shortcut for Scripting.FileSystemObject.GetTempName
Function GetTempName()

	Dim fs : Set fs = Nothing
	Set fs = CreateObject ("Scripting.FileSystemObject")
	GetTempName = fs.GetTempName()
	Set fs = Nothing

End Function

' Gets value of specified registry key
' Arguments:
'	Key: complete path to registry key
Function GetRegistryValue(key)

	Dim shell : Set shell = Nothing
	Dim value

	Set shell = WScript.CreateObject("WScript.Shell")
	value = shell.RegRead(key)
	If Err.number = 0 Then GetRegistryValue = value
	Set shell = Nothing

End Function

' Gets install location using Windows Installer
Function GetInstallPathFromInstaller(productName)

	Dim product, value
	Dim installer : Set installer = Nothing
	Dim products : Set products = Nothing

	Set installer = Wscript.CreateObject("WindowsInstaller.Installer")
	Set products = installer.Products
	For Each product In products
		value = installer.ProductInfo(product, "ProductName")
		If InStrRev(value, productName, -1, vbTextCompare) <> 0 Then 
			value = installer.ProductInfo(product, "InstallLocation")
			If value <> Empty Then GetInstallPathFromInstaller = value
			Exit For
		End If 
	Next
	Set products = Nothing
	Set installer = Nothing

End Function

' Set variable in current user environment
' Arguments:
'	name: variable name
'	value: variable value
Sub SetEnvironment(name, value)

	Dim shell : Set shell = Nothing
	Dim var : Set var = Nothing
	On Error Resume Next

	Set shell = CreateObject("WScript.Shell")
	Set var = GetObject( "winmgmts://./root/cimv2:Win32_Environment").SpawnInstance_
	var.Name = name
	var.VariableValue = value
	var.UserName = shell.ExpandEnvironmentStrings("%USERNAME%")
	var.Put_
	Set var = Nothing
	Set shell = Nothing

End Sub




' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' Main program
' -----------------------------
' Required software
' -----------------------------
' MS Visual Studio Community	Required to to build native library	https://visualstudio.microsoft.com/pt-br/downloads/
' Git							Software configuration management	https://git-scm.com/
' Dr. Memory Debugger			Required to look for memory leaks	https://drmemory.org/
' Netwide Assembler				Required to compile OpenSSL			https://www.nasm.us/
' Active Perl					Required to compile OpenSSL 		http://www.activestate.com/activeperl
' Java Development Kit 32 bits	Required to build					http://www.oracle.com/technetwork/java/javase/downloads/
' Apache Ant					Required to build					https://ant.apache.org/
' Ant Contrib Tasks				Required to build					http://ant-contrib.sourceforge.net/
' Open SSL						Nharu dependency					https://github.com/openssl/openssl
' GNU Libidn					Nharu dependency					https://git.savannah.gnu.org/git/libidn.git
' -----------------------------
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

Dim oInstaller : Set oInstaller = New Installer
Dim oFinder : Set oFinder = New Finder
Dim fs : Set fs = Nothing
Set fs = CreateObject ("Scripting.FileSystemObject")
oFinder.StartFolder = fs.GetParentFolderName(fs.GetParentFolderName(fs.GetParentFolderName(WScript.ScriptFullName)))
Set fs = Nothing


' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' Error messages
' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Dim msgs(9, 6)
msgs(VS_INSTALL_PATH, 0)	= "Searching for Visual Studio... "
msgs(VS_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(VS_INSTALL_PATH, 2)	= "Visual Studio 2017 must be previously installed."
msgs(VS_INSTALL_PATH, 3)	= "Please, download it from https://visualstudio.microsoft.com/pt-br/downloads/,"
msgs(VS_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(VS_INSTALL_PATH, 5)	= 1

msgs(GIT_INSTALL_PATH, 0)	= "Searching for Git SCM... "
msgs(GIT_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(GIT_INSTALL_PATH, 2)	= "Could not download and/or install  Git SCM"
msgs(GIT_INSTALL_PATH, 3)	= "Please, download it from https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe,"
msgs(GIT_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(GIT_INSTALL_PATH, 5)	= 2

msgs(DRMEM_INSTALL_PATH, 0)	= "Searching for Dr. Memory Debugger... "
msgs(DRMEM_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(DRMEM_INSTALL_PATH, 2)	= "Could not download and/or install Dr. Memory Debugger"
msgs(DRMEM_INSTALL_PATH, 3)	= "Please, download it from https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Windows-1.11.0-2.msi,"
msgs(DRMEM_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(DRMEM_INSTALL_PATH, 5)	= 3

msgs(NASM_INSTALL_PATH, 0)	= "Searching for Netwide Assembler... "
msgs(NASM_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(NASM_INSTALL_PATH, 2)	= "Could not download and/or install Netwide Assembler"
msgs(NASM_INSTALL_PATH, 3)	= "Please, download it from https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/nasm-2.14.02-installer-x86.exe,"
msgs(NASM_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(NASM_INSTALL_PATH, 5)	= 4

msgs(PERL_INSTALL_PATH, 0)	= "Searching for Active Perl... "
msgs(PERL_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(PERL_INSTALL_PATH, 2)	= "Could not download and/or install Active Perl"
msgs(PERL_INSTALL_PATH, 3)	= "Please, download it from https://downloads.activestate.com/ActivePerl/releases/5.26.3.2603/ActivePerl-5.26.3.2603-MSWin32-x64-a95bce075.exe,"
msgs(PERL_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(PERL_INSTALL_PATH, 5)	= 5

msgs(JAVA_INSTALL_PATH, 0)	= "Searching for Java SE Development Kit... "
msgs(JAVA_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(JAVA_INSTALL_PATH, 2)	= "Java SE Development Kit must be previously installed."
msgs(JAVA_INSTALL_PATH, 3)	= "Please, download it from http://www.oracle.com/technetwork/java/javase/downloads/,"
msgs(JAVA_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(JAVA_INSTALL_PATH, 5)	= 6

msgs(ANT_INSTALL_PATH, 0)	= "Searching for Apache Ant... "
msgs(ANT_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(ANT_INSTALL_PATH, 2)	= "Could not download and/or install Apache Ant"
msgs(ANT_INSTALL_PATH, 3)	= "Please, download it from http://mirror.nbtelecom.com.br/apache//ant/binaries/apache-ant-1.10.5-bin.zip,"
msgs(ANT_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(ANT_INSTALL_PATH, 5)	= 7

msgs(ANTC_INSTALL_PATH, 0)	= "Searching for Ant Contrib Tasks... "
msgs(ANTC_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(ANTC_INSTALL_PATH, 2)	= "Could not download and/or install Ant Contrib Tasks"
msgs(ANTC_INSTALL_PATH, 3)	= "Please, download it from https://ufpr.dl.sourceforge.net/project/ant-contrib/ant-contrib/1.0b3/ant-contrib-1.0b3-bin.zip,"
msgs(ANTC_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(ANTC_INSTALL_PATH, 5)	= 8

msgs(SSL_INSTALL_PATH, 0)	= "Searching for OpenSSL... "
msgs(SSL_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(SSL_INSTALL_PATH, 2)	= "Could not clone and/or install OpenSSL"
msgs(SSL_INSTALL_PATH, 3)	= "Please, download it from https://github.com/openssl/openssl,"
msgs(SSL_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(SSL_INSTALL_PATH, 5)	= 9

msgs(IDN_INSTALL_PATH, 0)	= "Searching for GNU Libidn... "
msgs(IDN_INSTALL_PATH, 1)	= "FATAL ERROR:"
msgs(IDN_INSTALL_PATH, 2)	= "Could not clone and/or install GNU Libidn"
msgs(IDN_INSTALL_PATH, 3)	= "Please, download it from https://git.savannah.gnu.org/git/libidn.git,"
msgs(IDN_INSTALL_PATH, 4)	= "install it and run this configure.vbs again."
msgs(IDN_INSTALL_PATH, 5)	= 10


Set oInstaller = Nothing
Set oFinder = Nothing

Sub Main

	Dim products

	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library                                    "
	WScript.Echo " Environment for Windows development configuration"
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo ""

	products = GetInstalledProducts()

	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Environment for Windows development configured   "
	WScript.Echo " Use dev-env.bat file to all operations           "
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"

End Sub

' Search for installed software requirements
Function GetInstalledProducts()

	Dim ret(10)
	ret(VS_INSTALL_PATH)	= EnsureInstallVS()
	ret(GIT_INSTALL_PATH)	= EnsureInstallGit(True)
	ret(DRMEM_INSTALL_PATH)	= EnsureInstallDrMem(True)
	ret(NASM_INSTALL_PATH)	= EnsureInstallNASM(True)
	ret(PERL_INSTALL_PATH)	= EnsureInstallPerl(True)
	ret(JAVA_INSTALL_PATH)	= EnsureInstallJava()
	ret(ANT_INSTALL_PATH)	= EnsureInstallAnt(True)
	ret(ANTC_INSTALL_PATH)	= EnsureInstallAntContrib(True)
	ret(SSL_INSTALL_PATH)	= EnsureInstallOpenSSL(ret(GIT_INSTALL_PATH), True)
	ret(IDN_INSTALL_PATH)	= EnsureInstallLibidn(ret(GIT_INSTALL_PATH), True)
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
	stdout.Write(msgs(VS_INSTALL_PATH, 0))
	ret = GetVSInstallPath() : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallVS = AddSlash(ret)
	Else
		ByeBye VS_INSTALL_PATH
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function
Function GetVSInstallPath()

	Const VSWHERE = "\Microsoft Visual Studio\Installer\vswhere.exe"
	Const PATH_STRING = "installationPath:"
	Dim exe, vs32, vs64
	Dim shell : Set shell = Nothing
	Dim ret : Set ret = Nothing
	On Error Resume Next

	Set shell = CreateObject("WScript.Shell") : CheckError
	vs32 = shell.ExpandEnvironmentStrings("%ProgramFiles(x86)%") & VSWHERE
	vs64 = shell.ExpandEnvironmentStrings("%ProgramFiles%") & VSWHERE
	If FileExists(vs32) Then
		exe = vs32
	ElseIf FileExists(vs64) Then
		exe = vs64
	End If
	If Not IsEmpty(exe) Then
		Set ret = shell.Exec(exe)
		If ret.ExitCode() = 0 Then
			Dim line
			Do While Not ret.StdOut.AtEndOfStream
				line = ret.StdOut.ReadLine()
				If InStr(1, line, PATH_STRING, vbTextCompare) <> 0 Then
					GetVSInstallPath = Trim(Mid(line, Len(PATH_STRING) + 1))
					Exit Do
				End If
			Loop
		End If
	End If 
	Set shell = Nothing

End Function

' Gets Git SCM installation path
' Arguments:
'	try: True if it should be downloaded and executed
Function EnsureInstallGit(try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(GIT_INSTALL_PATH, 0))
	ret = GetRegistryValue(GIT_REGKEY) : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallGit = AddSlash(ret)
	Else
		If try Then
			oInstaller.Install "Git SM", "https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe" : CheckError
			EnsureInstallGit = EnsureInstallGit(False)
		Else
			ByeBye GIT_INSTALL_PATH
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Dr. Memory installation path
' Arguments:
'	try: True if it should be downloaded and executed
Function EnsureInstallDrMem(try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(DRMEM_INSTALL_PATH, 0))
	ret = GetInstallPathFromInstaller("Dr. Memory") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallDrMem = AddSlash(ret)
	Else
		If try Then
			oInstaller.Install "Dr. Memory Debugger", "https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Windows-1.11.0-2.msi" : CheckError
			EnsureInstallDrMem = EnsureInstallDrMem(False)
		Else
			ByeBye DRMEM_INSTALL_PATH
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Netwide Assembler installation path
' Arguments:
'	try: True if it should be downloaded and executed
Function EnsureInstallNASM(try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(NASM_INSTALL_PATH, 0))
	ret = GetRegistryValue(NASM_REGKEY) : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallNASM = AddSlash(ret)
	Else
		If try Then
			oInstaller.Install "Netwide Assembler", "https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/nasm-2.14.02-installer-x86.exe" : CheckError
			EnsureInstallNASM = EnsureInstallNASM(False)
		Else
			ByeBye NASM_INSTALL_PATH
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Active Perl installation path
' Arguments:
'	try: True if it  should be downloaded and executed
Function EnsureInstallPerl(try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(PERL_INSTALL_PATH, 0))
	ret = GetRegistryValue(PERL_REGKEY) : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallPerl = AddSlash(ret)
	Else
		If try Then
			oInstaller.Install "Active Perl", "https://downloads.activestate.com/ActivePerl/releases/5.26.3.2603/ActivePerl-5.26.3.2603-MSWin32-x64-a95bce075.exe" : CheckError
			EnsureInstallPerl = EnsureInstallPerl(False)
		Else
			ByeBye PERL_INSTALL_PATH
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
	stdout.Write(msgs(JAVA_INSTALL_PATH, 0))
	ret = GetInstallPathFromInstaller("Java SE Development Kit") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallJava = AddSlash(ret)
	Else
		ByeBye JAVA_INSTALL_PATH
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Apache Ant installation path
' Arguments:
'	try: True if it should be downloaded and unzipped
Function EnsureInstallAnt(try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(ANT_INSTALL_PATH, 0))
	ret = oFinder.Find("ant.jar") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallAnt = AddSlash(fs.GetParentFolderName(ret))
	Else
		If try Then
			oInstaller.Unzip "Apache Ant", "http://mirror.nbtelecom.com.br/apache//ant/binaries/apache-ant-1.10.5-bin.zip", oFinder.StartFolder : CheckError
			EnsureInstallAnt = EnsureInstallAnt(False)
		Else
			ByeBye ANT_INSTALL_PATH
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

' Gets Ant Contrib Tasks installation path
' Arguments:
'	try: True if it should be downloaded and unzipped
Function EnsureInstallAntContrib(try)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(ANTC_INSTALL_PATH, 0))
	ret = oFinder.Find("ant-contrib-1.0b3.jar") : Feedback stdout, ret
	If Not IsEmpty(ret) Then
		EnsureInstallAntContrib = AddSlash(ret)
	Else
		If try Then
			oInstaller.Unzip "Ant Contrib Tasks", "https://ufpr.dl.sourceforge.net/project/ant-contrib/ant-contrib/1.0b3/ant-contrib-1.0b3-bin.zip", oFinder.StartFolder : CheckError
			EnsureInstallAntContrib = EnsureInstallAntContrib(False)
		Else
			ByeBye ANTC_INSTALL_PATH
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
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(SSL_INSTALL_PATH, 0))
	ret = oFinder.Find("libcrypto.lib") : Feedback stdout, ret
	If Not Empty(ret) Then
		EnsureInstallOpenSSL = AddSlash(fs.GetParentFolderName(ret))
	Else
		If try Then
			ret = Clone(gitInstallPath, "https://github.com/openssl/openssl") : CheckError
			If ret <> 0 Then ByeBye SSL_INSTALL_PATH
			' TODO: Configure and build OpenSSL
			EnsureInstallOpenSSL = EnsureInstallOpenSSL(gitInstallPath, False)
		Else
			ByeBye SSL_INSTALL_PATH
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
	Dim ret
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	stdout.Write(msgs(IDN_INSTALL_PATH, 0))
	ret = oFinder.Find("libidn.lib") : Feedback stdout, ret
	If Not Empty(ret) Then
		EnsureInstallLibidn = AddSlash(fs.GetParentFolderName(ret))
	Else
		If try Then
			ret = Clone(gitInstallPath, "https://git.savannah.gnu.org/git/libidn.git") : CheckError
			If ret <> 0 Then ByeBye IDN_INSTALL_PATH
			' TODO: Configure and build Libidn
			EnsureInstallLibidn = EnsureInstallLibidn(gitInstallPath, False)
		Else
			ByeBye IDN_INSTALL_PATH
		End If
	End If
	stdout.Close
	Set stdout = Nothing
	Set fs = Nothing

End Function

Function Clone(gitInstallPath, uri)

	Dim git : Set git = New GitSCM
	Dim oProxy : Set oProxy = New Proxy
	oProxy.FromArguments
	git.Configure gitInstallPath, oProxy
	git.SetEnv
	Clone = git.Clone(uri, oFinder.StartFolder) : CheckError
	Set oProxy = Nothing
	Set git = Nothing

End Function
Sub Feedback(stdout, value)

	If Not IsEmpty(value) Then
		stdout.WriteLine("Found!")
	Else
		stdout.WriteLine("Not found!")
	End If	

End Sub
Sub CheckError

	If Err.number <> 0 Then
		WScript.Echo "An error number " & Err.number & " has occurred: " & Err.Description
		Wscript.Quit 1
	End If

End Sub
Sub ByeBye(product)

	Dim i
	
	For i = 1 To 4
		WScript.Echo msgs(product, i)
	Next
	WScript.Quit msgs(5)

End Sub
Function AddSlash(path)

	If InStrRev(path, "\") <> Len(path) Then
		AddSlash = path & "\"
	Else
		AddSlash = path
	End If

End Function

