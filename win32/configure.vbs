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


' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
' General utilities
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

	Private _location, _proxy

	' Configures object to download
	' Arguments:
	'	wgetLocation: folder where wget.exe lies
	'	oProxy: instance of Proxy class
	Public Sub Configure(wgetLocation, oProxy)

		If Not FolderExists(wgetLocation) Or Not FileExists(wgetLocation & "\wget.exe") Then Err.Raise 1, "WGet.Configure", "Argument must point to an existing wget.exe"
		_location = """" & wgetLocation & "\wget.exe"""
		Set _proxy = oProxy

	End Sub

	' Downloads a file
	' Arguments:
	'	name: label for feedeback
	'	uri: resource location
	'	target: complete path to downloaded resource
	Public Function Download(name, uri, target)

		If IsEmpty(_location) Or IsEmpty(_proxy) Then Err.Raise 2, "WGet.Download", "Object improperly initialized"
		Dim cmd
		Dim shell : Set shell = Nothing
		Dim ret

		cmd = _location
		If Not IsEmpty(_proxy.Server) Then
			If InStr(uri, "https") = 1 Then
				cmd = cmd & " -e https_proxy=" & _proxy.Server & " --no-check-certificate"
			Else
				cmd = cmd & " -e http_proxy=" & _proxy.Server
			End If
			If Not IsEmpty(_proxy.User) Then
				cmd = cmd & " --proxy-user=" & _proxy.User
			End If
			If Not IsEmpty(_proxy.Pwd) Then
					cmd = cmd & " --proxy-password=" & _proxy.Pwd
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

	Public Sub Install(source, target)


	End Sub
	
	Private Sub CheckGetter

		If IsEmpty(Getter) Then
			Dim oProxy : Set oProxy = Nothing
			Dim fs : Set fs = Nothing
			Dim location

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

	Private _location, _proxy


	' Configures object to download
	' Arguments:
	'	gitLocation: folder where git-cmd.exe lies
	'	oProxy: instance of Proxy class
	Public Sub Configure(gitLocation, oProxy)

		If Not FolderExists(gitLocation) Or Not FileExists(gitLocation & "\git-cmd.exe") Then Err.Raise 1, "GitSCM.Configure", "Argument must point to an existing git-cmd.exe"
		_location = """" & gitLocation & "\git-cmd.exe"""
		Set _proxy = oProxy

	End Sub

	' Sets Git SCM proxy global environment, if necessary
	Public Sub SetEnv

		If IsEmpty(_location) Or IsEmpty(_proxy) Then Err.Raise 2, "GitSCM.SetEnv", "Object improperly initialized"
		If IsEmpty(_proxy.Server) Then Exit Sub
		Dim shell : Set shell = Nothing
		Dim cmd, rv

		Set shell = CreateObject("Wscript.Shell")
		cmd = _location & " git config --global http.proxy http://"
		If Not IsEmpty(_proxy.User) And Not IsEmpty(_proxy.Pwd) Then
			cmd = cmd & _proxy.User & ":" & _proxy.Pwd & "@"
		End If
		cmd = cmd & _proxy.Server
		rv = shell.Run(_location & " git config --global --get http.proxy", 0, True)
		If rv <> 0 Then
			rv = shell.Run(cmd, 0, True)
			If rv <> 0 Then Err.Raise 2, "GitSCM.SetEnv", "Failed to set Git global http.proxy"
			rv = shell.Run(_location & " git config --global --get https.proxy", 0, True)
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

		If IsEmpty(_location) Or IsEmpty(_proxy) Then Err.Raise 2, "GitSCM.Clone", "Object improperly initialized"
		If FolderExists(target) Then err.Raise 3, "GitSCM.Clone", "Target directory must not exists"
		Dim shell : Set shell = Nothing

		Set shell = CreateObject("Wscript.Shell")
		Clone = shell.Run(_location & " git clone " & uri & " " & target, 1, True)
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
