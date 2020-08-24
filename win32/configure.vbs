' Visual Studio installation check facility
Class VisualStudio
	Private m_shell, m_vswhere, m_location, m_fs
	Private Sub Class_Initialize()
		Const VSWHERE = "\Microsoft Visual Studio\Installer\vswhere.exe"
		Set m_shell = CreateObject("WScript.Shell")
		Set m_fs = CreateObject ("Scripting.FileSystemObject")
		Dim vs32 : vs32 = m_shell.ExpandEnvironmentStrings("%ProgramFiles(x86)%") & VSWHERE
		Dim vs64 : vs64 = m_shell.ExpandEnvironmentStrings("%ProgramFiles%") & VSWHERE
		If m_fs.FileExists(vs32) Then
			m_vswhere = vs32
		ElseIf m_fs.FileExists(vs64) Then
			m_vswhere = vs64
		End If
	End Sub
	Private Sub Class_Terminate()
		Set m_shell = Nothing
	End Sub

	' Retrives install location
	Private Function GetInstallLocation()
		Const PATH_STRING = "installationPath:"
		If IsEmpty(m_location) And Not IsEmpty(m_vswhere) Then
			Dim ret : Set ret = m_shell.Exec(m_vswhere)
			Do While ret.Status = 0
	     		WScript.Sleep 100
			Loop
			If ret.ExitCode = 0 Then
				Dim line
				Do While Not ret.StdOut.AtEndOfStream
					line = ret.StdOut.ReadLine()
					If InStr(1, line, PATH_STRING, vbTextCompare) <> 0 Then
						m_location = AddSlash(Trim(Mid(line, Len(PATH_STRING) + 1)))
						Exit Do
					End If
				Loop
			End If
		End If
		GetInstallLocation = m_location
	End Function

	' Retrieve Visual Studio installation folder. If does not exists, Raise an exception
	Public Function EnsureInstall()
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) Then Err.Raise 1, "VisualStudio.EnsureInstall", "MS Visual Studio version 16.0 must be installed from https://visualstudio.microsoft.com/pt-br/downloads/"
		EnsureInstall = value
	End Function 
End Class

' Java installation check facility
Class Java
	Private m_installer, m_location, m_fs
	Private Sub Class_Initialize()
		Set m_installer = New Installer
		Set m_fs = CreateObject("Scripting.FileSystemObject")
	End Sub
	Private Sub Class_Terminate()
		Set m_installer = Nothing
		Set m_fs = Nothing
	End Sub

	' Retrives install location
	' Arguments:
	' 	string version: JDK version number
	Public Function GetInstallLocation(version)
		Const ENTRY = "Java SE Development Kit "
		If IsEmpty(m_location) Then
			Dim ret : ret = m_installer.GetInstallLocation(ENTRY & version)
			If Not IsEmpty(ret) Then
				m_location = AddSlash(ret)
			End If
		End If
		GetInstallLocation = m_location
	End Function

	' Retrieve Java JDK installation folder. If does not exists, Raise an exception
	' Arguments:
	' 	string version: JDK version number
	Public Function EnsureInstall(version)
		Dim value : value = GetInstallLocation(version)
		If IsEmpty(value) Then Err.Raise 1, "Java.EnsureInstall", "Java JDK version " & version & " must be installed from https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html"
		EnsureInstall = value
	End Function 
End Class

' Installation facility
Class Installer
	Private m_installer, m_products, m_shell
	Private Sub Class_Initialize()
		Set m_installer = Wscript.CreateObject("WindowsInstaller.Installer")
		Set m_products = m_installer.Products
		Set m_shell = CreateObject("Wscript.Shell")
	End Sub
	Private Sub Class_Terminate()
		Set m_products = Nothing
		Set m_installer = Nothing
		Set m_shell = Nothing
	End Sub

	' Retrieves install location of a product from Windows Installer database
	' string productName: product name to Windows Installer
	Public Function GetInstallLocation(productName)
		Dim product, value
		For Each product In m_products
			value = m_installer.ProductInfo(product, "ProductName")
			If StrComp(value, productName, 1) = 0 Then 
				value = m_installer.ProductInfo(product, "InstallLocation")
				If Not IsEmpty(value) Then GetInstallLocation = AddSlash(value)
				Exit For
			End If 
		Next
	End Function

	' Check if specified application is in PATH environment variable
	' Arguments:
	'	string app: executable name
	Public Function IsInPath(app)
		Const CMD = "WHERE /Q "
		Dim ret : ret = m_shell.Run(CMD & app, 0, True)
		If ret = 0 Then
			IsInPath = True
		Else
			IsInPath = False
		End If
	End Function
End Class

' Find file facility
Class Finder
	Private m_start, m_fs
	Private Sub Class_Initialize()
		Dim shell : Set shell = CreateObject("WScript.Shell")
		m_start = shell.ExpandEnvironmentStrings("%USERPROFILE%")
		Set m_fs = CreateObject("Scripting.FileSystemObject")
		Set shell = Nothing
	End Sub
	Private Sub Class_Terminate()
		Set m_fs = Nothing
	End Sub

	' Find specified file from %USERPROFILE% folder
	' Arguments:
	'	string fileName: file to find
	Public Function Find(fileName)
		Find = FindFile(m_start, fileName)
	End Function

	' Find specified file from specified folder
	' Arguments:
	'	string folderName: start folder
	'	string fileName: file to find
	Public Function FindFile(folderName, fileName)
		Dim file, folder, found
		Dim current : Set current = m_fs.GetFolder(folderName)
		If InStr(1, current.Name, ".", 1) <> 0 Then Exit Function
		If (current.Attributes And 2) = 2 Then Exit Function
		If (current.Attributes And 1024) = 1024 Then Exit Function
		If (current.Attributes And 2048) = 2048 Then Exit Function
	
		For Each file In current.Files
			If StrComp(file.Name, fileName, vbTextCompare) = 0 Then
				found = current.Path
				Exit For
			End If
		Next
		If IsEmpty(found) Then
			For Each folder In current.SubFolders
				file = FindFile(folder.Path, fileName)
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

Function AddSlash(path)
	If InStrRev(path, "\") <> Len(path) Then
		AddSlash = path & "\"
	Else
		AddSlash = path
	End If
End Function
Function RemoveSlash(path)
	If InStrRev(path, "\") = Len(path) Then
		RemoveSlash = Mid(path, 1, Len(path) - 1)
	Else
		RemoveSlash = path
	End If
End Function 


' Command line arguments
'	/prefix: Library installation folder. Optional. Default: UserProfile & \development\build
'	/openssl: OpenSSL libraty source code folder. Optional. Must be found at UserProfile
'	/libidn: Libidn libraty source code folder. Optional. Must be found at UserProfile
Sub Main
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library"
	WScript.Echo " Environment for Windows Development"
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo ""
	Dim shell : Set shell = CreateObject("WScript.Shell")
	Dim args : Set args = WScript.Arguments.Named
	Dim fd : Set fd = new Finder
	Dim fs : Set fs = CreateObject("Scripting.FileSystemObject")
	Dim prefix, openssl, libidn
	Dim vs : Set vs = new VisualStudio
	Dim jdk : Set jdk = new Java
	Dim installer : Set installer = new Installer
	Dim jdk32, jdk64

	' Ensures that dependent libraries are downloaded
	If args.Exists("prefix") Then
		prefix = args.Item("prefix")
	Else
		prefix = shell.ExpandEnvironmentStrings("%USERPROFILE%") & "\development\build"
	End If
	If args.Exists("openssl") Then
		openssl = args.Item("openssl")
	Else
		WScript.Echo " Checking OpenSSL. Please, wait..."
		
		openssl = fd.Find("opensslconf.h.in")
		If Not IsEmpty(openssl) Then openssl = fs.GetParentFolderName(fs.GetParentFolderName(openssl))
	End If
	If IsEmpty(openssl) Then Err.Raise 1, "Main", "OpenSSL must be cloned from https://github.com/openssl/openssl and checked out on version OpenSSL_1_1_0f"
	If args.Exists("libidn") Then
		libidn = args.Item("libidn")
	Else
		WScript.Echo " Checking Libidn. Please, wait..."
		libidn = fd.Find("libidn.pc.in")
	End If
	If IsEmpty(libidn) Then Err.Raise 1, "Main", "Libidn must be cloned from https://git.savannah.gnu.org/git/libidn.git and checked out on version libidn-1-32"

	' Ensures that support software are installed
	vs.EnsureInstall()
	jdk.EnsureInstall("7 Update 80")
	jdk32 = jdk.GetInstallLocation("7 Update 80")
	Set jdk = Nothing
	Set jdk = new Java
	jdk.EnsureInstall("7 Update 80 (64-bit)")
	jdk64 = jdk.GetInstallLocation("7 Update 80 (64-bit)")
	If Not installer.IsInPath("drmemory.exe") Then Err.Raise 1, "Main", "Dr. Memory must be installed in path from https://drmemory.org/"
	If Not installer.IsInPath("mvn.cmd")  Then Err.Raise 1, "Main", " Apache Maven must be installed in path from https://maven.apache.org/download.cgi"
	If Not installer.IsInPath("perl.exe") Then Err.Raise 1, "Main", " Active Perl must be installed in path from https://downloads.activestate.com/ActivePerl/"
	If Not installer.IsInPath("nasm.exe") Then Err.Raise 1, "Main", " Netwide Assembler must be installed in path from https://www.nasm.us/pub/nasm/releasebuilds/2.15.04/"
	WScript.Echo ""
	WScript.Echo " JDK 7 Update 80:          " & jdk32
	WScript.Echo " JDK 7 Update 80 (64-bit): " & jdk64
	WScript.Echo " Install directory:        " & prefix
	WScript.Echo " OpenSSL source code:      " & openssl
	WScript.Echo " Libidn source code:       " & libidn
	WScript.Echo ""
	WScript.Echo " MSBuild utility found"
	WScript.Echo " Dr Memory utility found"
	WScript.Echo " Apache Maven utility found"
	WScript.Echo " Active Perl utility found"
	WScript.Echo " NetWide Assembler utility found"

	' Create MSBuild project file
	Dim curDir: curDir = fs.GetParentFolderName(WScript.ScriptFullName)
	Dim template : Set template = fs.OpenTextFile(curDir & "\nharu-build.proj.in", 1)
	Dim out : Set out = fs.CreateTextFile(curDir & "\nharu-build.proj")
	While Not template.AtEndOfStream
		Dim line : line = template.ReadLine()
		line = Replace(line, ">__PREFIX__<",    ">" & prefix               & "<")
		line = Replace(line, ">__JDK32HOME__<", ">" & RemoveSlash(jdk32)   & "<")
		line = Replace(line, ">__JDK64HOME__<", ">" & RemoveSlash(jdk64)   & "<")
		line = Replace(line, ">__OPENSSL__<",   ">" & RemoveSlash(openssl) & "<")
		line = Replace(line, ">__LIBIDN__<",    ">" & RemoveSlash(libidn)  & "<")
		out.WriteLine(line)
	Wend

	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library"
	WScript.Echo " Environment for Windows Development"
	WScript.Echo " --------------------------------------------------"
	WScript.Echo " Copyleft (C) 2015/2020 by The Crypthing Initiative"
	WScript.Echo " Authors:"
	WScript.Echo "   diego.sohsten@caixa.gov.br"
	WScript.Echo "   yorick.flannagan@gmail.com"
	WScript.Echo " --------------------------------------------------"
	WScript.Echo " Run MSBuild under Visual Studio vcvarsamd64_x86.bat"
	WScript.Echo " or vcvars64.bat as your command line environment"
	WScript.Echo " to build nharu-build.proj"
	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
End Sub

Main
