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
'	/version:[ver]: Version string. Optional. Default: 1.1.10
'	/prefix:[path]: Folder where Nharu should be installed. Optional. Default [parent of nharu_home]
'	/debug If present, compilation is set for debug
'
' -----------------------------
' Authors:
' 		diego.sohsten@gmail.com
' 		yorick.flannagan@gmail.com
' * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *


' Encapsultes a proxy definition
Class ProxyParams

	Public Server, User, Pwd

End Class

' Encapsulates GNU WGet operation
Class WGet

	Private m_location, m_proxy

	' Configures object to download
	' Arguments:
	'	wgetLocation: folder where wget.exe lies
	'	prx: instance of Proxy class
	Public Sub Configure(wgetLocation, prx)

		Dim fs : Set fs = CreateObject("Scripting.FileSystemObject")
		If Not fs.FolderExists(wgetLocation) Or Not fs.FileExists(wgetLocation & "\wget.exe") Then Err.Raise 1, "WGet.Configure", "Argument must point to an existing wget.exe"
		m_location = """" & wgetLocation & "\wget.exe"""
		Set m_proxy = prx
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
		cmd = cmd & " --output-document=" & target & "\" & name & " " & uri

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

Sub Include(fspec)

	Dim fs : Set fs = CreateObject("Scripting.FileSystemObject")
	Dim file : Set file = fs.OpenTextFile(fspec, 1)
	Dim lib : lib = file.ReadAll
	file.Close
	Set file = Nothing : Set fs = Nothing
	ExecuteGlobal lib

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

'
' Globals
' -----------------------------
Dim PROXY : Set PROXY = Nothing
Dim CONFIG : Set CONFIG = Nothing
Dim IWR : Set IWR = Nothing
Dim START, CURRENT
Dim INSTALL : Set INSTALL = Nothing
Dim FFINDER : Set FFINDER = Nothing

Sub Initialize

	Dim args : Set args = WScript.Arguments.Named
	Dim fs : Set fs = CreateObject ("Scripting.FileSystemObject")
	CURRENT = fs.GetParentFolderName(WScript.ScriptFullName)
	START = fs.GetParentFolderName(fs.GetParentFolderName(CURRENT))

	Set PROXY = New ProxyParams
	If args.Exists("proxy") Then
		PROXY.Server = args.Item("proxy")
	End If
	If args.Exists("user") Then
		PROXY.User = args.Item("user")
	End If
	If args.Exists("pwd") Then
		PROXY.Pwd = args.Item("pwd")
	End If

	Set CONFIG = CreateObject("Scripting.Dictionary")
	If args.Exists("prefix") Then
		CONFIG.Add "prefix", """" & args.Item("prefix") & """"
	Else
		CONFIG.Add "prefix", """" & START & "\3rdparty\nharu"""
	End If
	If args.Exists("version") Then
		CONFIG.Add "version", args.Item("version")
	Else
		CONFIG.Add "version", "1.1.10"
	End If
	If args.Exists("debug") Then
		CONFIG.Add "debug", """DEBUG=1"""
	Else
		CONFIG.Add "debug", """"""
	End If
	Set args = Nothing
	Set fs = Nothing

	Set IWR = New WGet
	IWR.Configure CURRENT, PROXY

End Sub

Sub InitLibrary

	Dim ret : ret = IWR.Download("library.vbs", """https://docs.google.com/uc?export=download&id=1kQVYeQiqOg50mVbeP3J9bnswBaoD0aNW""", CURRENT)
	If ret <> 0 Then Err.Raise ret, "InitLibrary", "Failed to include library"
	Include "library.vbs"
	Set INSTALL = New Installer
	Set INSTALL.Getter = IWR
	Set FFINDER = New Finder
	FFINDER.StartFolder = START
	SetFacilities INSTALL, FFINDER, PROXY

End Sub

Sub ShowConfig

	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library                                    "
	WScript.Echo " Environment for Windows development configuration"
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo ""

	WScript.Echo " Startup configuration:"
	WScript.Echo " Proxy server: " & PROXY.Server
	WScript.Echo " Proxy user: " & PROXY.User
	WScript.Echo " Prefix directory: " & CONFIG.Item("prefix")
	WScript.Echo " Version number: " & CONFIG.Item("version")
	WScript.Echo " DEbug flag: " & CONFIG.Item("debug")
	WScript.Echo " Search folder: " & FFINDER.StartFolder
	WScript.Echo ""
	
End Sub

Sub Main

	products = GetInstalledProducts()
	GenerateDevEnv products
	GenerateBuild CONFIG.Item("prefix"), CONFIG.Item("version"), CONFIG.Item("debug")

	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Environment for Windows development configured   "
	WScript.Echo " Use build.bat file to build                      "
	WScript.Echo " Use dev-env.bat file to all other operations     "
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * *"

End Sub

' Search for installed software requirements
Function GetInstalledProducts()

	Dim ret(17)
	ret(VS_INSTALL_PATH)	= EnsureInstallVS()
	ret(JDK8_INSTALL_PATH)	= EnsureInstallJava(JDK8_INSTALL_PATH, "8")
	ret(JDK7_INSTALL_PATH)	= EnsureInstallJava(JDK7_INSTALL_PATH, "7")
	ret(GIT_INSTALL_PATH)	= EnsureInstallGit(True)
	ret(DRMEM_INSTALL_PATH)	= EnsureInstallDrMem(True)
	ret(NASM_INSTALL_PATH)	= EnsureInstallNASM(True)
	ret(PERL_INSTALL_PATH)	= EnsureInstallPerl(True)
	ret(SSL_INSTALL_PATH)	= EnsureInstallOpenSSL(ret(GIT_INSTALL_PATH), ret(NASM_INSTALL_PATH), ret(PERL_INSTALL_PATH), ret(VS_INSTALL_PATH), True)
	ret(IDN_INSTALL_PATH)	= EnsureInstallLibidn(ret(GIT_INSTALL_PATH), ret(PERL_INSTALL_PATH), ret(VS_INSTALL_PATH), True)
	ret(ANT_INSTALL_PATH)	= EnsureInstallAnt(True)
	ret(ANTC_INSTALL_PATH)	= EnsureInstallAntContrib(True)
	GetInstalledProducts = ret

End Function

Sub GenerateDevEnv(productsPath)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim template : Set template = Nothing
	Dim out : Set out = Nothing
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	Set template = fs.OpenTextFile("dev-env.template", 1) : CheckError
	Set out = fs.CreateTextFile("dev-env.bat", True) : CheckError
	stdout.Write(" Generating configuration batch file... ")
	While Not template.AtEndOfStream
		Dim line, newLine
		line = template.ReadLine()
		newLine = Replace(line,    "__OPENSSL__",         productsPath(SSL_INSTALL_PATH))
		newLine = Replace(newLine, "__LIBIDN__",          productsPath(IDN_INSTALL_PATH))
		newLine = Replace(newLine, "__JAVA_HOME__",       productsPath(JDK8_INSTALL_PATH))
		newLine = Replace(newLine, "__ANT_HOME__",        productsPath(ANT_INSTALL_PATH))
		newLine = Replace(newLine, "__ANT_CONTRIB__",     productsPath(ANTC_INSTALL_PATH) & "ant-contrib-1.0b3.jar")
		newLine = Replace(newLine, "__JRE_7RT__",         productsPath(JDK7_INSTALL_PATH) & "jre\lib\rt.jar")
		newLine = Replace(newLine, "__VS_INSTALL_PATH__", productsPath(VS_INSTALL_PATH))
		out.WriteLine(newLine)
	Wend
	stdout.WriteLine("Done!")
	out.Close
	template.Close
	stdout.Close
	Set fs = Nothing
	Set stdout = Nothing
	Set template = Nothing
	Set out = Nothing

End Sub

Sub GenerateBuild(prefix, ver, debug)

	Dim fs : Set fs = Nothing
	Dim stdout : Set stdout = Nothing
	Dim template : Set template = Nothing
	Dim out : Set out = Nothing
	On Error Resume Next

	Set fs = CreateObject ("Scripting.FileSystemObject") : CheckError
	Set stdout = fs.GetStandardStream(1) : CheckError
	Set template = fs.OpenTextFile("build.template", 1) : CheckError
	Set out = fs.CreateTextFile("build.bat", True) : CheckError
	stdout.Write(" Generating build batch file... ")
	While Not template.AtEndOfStream
		Dim line, newLine
		line = template.ReadLine()
		newLine = Replace(line,    "__PREFIX__",  prefix)
		newLine = Replace(newLine, "__VERSION__", ver)
		newLine = Replace(newLine, "__DEBUG__",   debug)
		out.WriteLine(newLine)
	Wend
	stdout.WriteLine("Done!")
	out.Close
	template.Close
	stdout.Close
	Set fs = Nothing
	Set stdout = Nothing
	Set template = Nothing
	Set out = Nothing

End Sub

Initialize
InitLibrary
ShowConfig
Main
