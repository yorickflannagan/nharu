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

		Dim fs : Set fs = CreateObject("Scripting.FileSystemObject")
		If Not fs.FolderExists(wgetLocation) Or Not fs.FileExists(wgetLocation & "\wget.exe") Then Err.Raise 1, "WGet.Configure", "Argument must point to an existing wget.exe"
		m_location = """" & wgetLocation & "\wget.exe"""
		Set m_proxy = oProxy
		Set fs = Nothing

	End Sub

	' Downloads a file
	' Arguments:
	'	name: label for feedeback
	'	uri: resource location
	'	target: complete path to downloaded resource
	Public Function Download(name, uri, target)

		If IsEmpty(m_location) Or IsEmpty(m_proxy) Then Err.Raise 2, "WGet.Download", "Object improperly initialized"
		Dim cmd
		Dim shell : Set shell = Nothing
		Dim ret

		cmd = m_location
		If Not IsEmpty(m_proxy.Server) Then
			cmd = cmd & " -e http_proxy=" & m_proxy.Server & " -e https_proxy=" & m_proxy.Server & " --no-check-certificate"
			If Not IsEmpty(m_proxy.User) Then
				cmd = cmd & " --proxy-user=" & m_proxy.User
			End If
			If Not IsEmpty(m_proxy.Pwd) Then
					cmd = cmd & " --proxy-password=" & m_proxy.Pwd
			End If
		End If
		cmd = cmd & " --output-document=" & target & " " & uri

		Set shell = CreateObject("Wscript.Shell")
		WScript.Echo cmd
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

Sub Include(fspec)

	Dim fs : Set fs = CreateObject("Scripting.FileSystemObject")
	Dim file : Set file = fs.OpenTextFile(fspec, 1)
	Dim lib : lib = file.ReadAll
	file.Close
	Set file = Nothing : Set fs = Nothing
	ExecuteGlobal lib

End Sub

Sub DownloadLib(wGetLocation, lib, uri)

	Dim oProxy : Set oProxy = New Proxy
	Dim iwr : Set iwr = New WGet
	Dim ret
	oProxy.FromArguments
	iwr.Configure wGetLocation, oProxy
	ret = iwr.Download(lib, uri, lib)
	Set iwr = Nothing : Set oProxy = Nothing
	If ret <> 0 Then Err.Raise ret, "DownloadLib", "Could not dowload library " & lib & " from URI " & uri

End sub


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

Dim fs : Set fs = CreateObject ("Scripting.FileSystemObject")
Dim start : start = fs.GetParentFolderName(fs.GetParentFolderName(fs.GetParentFolderName(WScript.ScriptFullName)))
DownloadLib fs.GetParentFolderName(WScript.ScriptFullName), "library.vbs", """https://docs.google.com/uc?export=download&id=1kQVYeQiqOg50mVbeP3J9bnswBaoD0aNW"""
Set fs = Nothing
Include "library.vbs"
Main


Sub Main

	Dim products
	Dim oInstaller : Set oInstaller = New Installer
	Dim oFinder : Set oFinder = New Finder
	oFinder.StartFolder = start
	SetFacilities oInstaller, oFinder

	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library                                    "
	WScript.Echo " Environment for Windows development configuration"
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo ""

	products = GetInstalledProducts()
	GenerateMakefile products

	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Environment for Windows development configured   "
	WScript.Echo " Use dev-env.bat file to all operations           "
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"

	Set oInstaller = Nothing
	Set oFinder = Nothing

End Sub

' Search for installed software requirements
Function GetInstalledProducts()

	Dim ret(16)
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

Sub GenerateMakefile(productsPath)


End Sub