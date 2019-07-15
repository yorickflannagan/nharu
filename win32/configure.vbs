Const HKEY_CURRENT_USER  = &H80000001
Const HKEY_LOCAL_MACHINE = &H80000002

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
	Public Function GetInstallLocation()
		Const PATH_STRING = "installationPath:"
		If IsEmpty(m_location) And Not IsEmpty(m_vswhere) Then
			Dim stdout : Set stdout = m_fs.GetStandardStream(1)
			stdout.Write "Looking for Microsoft Visual Studio... "
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
						stdout.WriteLine "Found!"
						Exit Do
					End If
				Loop
			End If
			stdout.Close
			Set stdout = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Retrieve Visual Studio installation folder. If does not exists, Raise an exception
	Public Function EnsureInstall()
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) Then Err.Raise 1, "VisualStudio.EnsureInstall", "MS Visual Studio is required. Please, download and install it from https://visualstudio.microsoft.com/pt-br/downloads/, then re-run this configure"
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
			Dim stdout : Set stdout = m_fs.GetStandardStream(1)
			stdout.Write "Looking for " & ENTRY & version & "... "
			Dim ret : ret = m_installer.GetInstallLocation(ENTRY & version)
			If Not IsEmpty(ret) Then
				m_location = AddSlash(ret)
				stdout.WriteLine "Found!"
			Else
				stdout.WriteLine "Not found!"
			End If
			stdout.Close
			Set stdout = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Retrieve Java JDK installation folder. If does not exists, Raise an exception
	' Arguments:
	' 	string version: JDK version number
	Public Function EnsureInstall(version)
		Dim value : value = GetInstallLocation(version)
		If IsEmpty(value) Then Err.Raise 1, "Java.EnsureInstall", "Java JDK version " & version & " is required. Please, download and install it from https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html, then re-run this configure"
		EnsureInstall = value
	End Function 
End Class

' Git installation facility
Class GitSCM
	Private m_registry, m_location, m_installer, m_shell, m_fs
	Private Sub Class_Initialize()
		Set m_registry = New Registry
		Set m_installer = New Installer
		Set m_shell = CreateObject("Wscript.Shell")
		Set m_fs = CreateObject("Scripting.FileSystemObject")
	End Sub
	Private Sub Class_Terminate()
		Set m_registry = Nothing
		Set m_installer = Nothing
		Set m_shell = Nothing
		Set m_fs = Nothing
	End Sub

	' Retrieves install location
	Public Function GetInstallLocation()
		Const REGKEY = "SOFTWARE\GitForWindows"
		Const REGVALUE = "InstallPath"
		If IsEmpty(m_location) Then
			Dim stdout : Set stdout = m_fs.GetStandardStream(1)
			stdout.Write "Looking for Git SCM... "
			Dim value : value = m_registry.GetValue(HKEY_LOCAL_MACHINE, REGKEY, REGVALUE)
			If Not IsEmpty(value) Then
				m_location = AddSlash(value)
				stdout.WriteLine "Found!"
			Else
				stdout.WriteLine "Not found!"
			End If
			stdout.Close
			Set stdout = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Ensures software is installed 
	' Arguments:
	'	boolean retry: if true, tries to download and install it, if it does not exist
	public Function EnsureInstall(retry)
		Const GIT_SOURCE = "https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe"
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) And retry Then
			m_installer.Install GIT_SOURCE, ".exe"
			WScript.Sleep 3000
			value = EnsureInstall(False)
			If IsEmpty(value) Then Err.Raise 1, "GitSCM.EnsureInstall", "GitSCM is required. Please, download and install it from " & GIT_SOURCE & ", then re-run this configure"
		End If
		EnsureInstall = value
	End Function

	' Use Git to clone source into target. Must be installed
	' Arguments:
	'	string source: source URI
	'	string target: target directory
	Public Sub Clone(source, target)
		If IsEmpty(m_location) Then If ret <> 0 Then Err.Raise 1, "GitSCM.Clone", "Git not installed"
		Dim cmd : cmd = """" & m_location & "cmd\git.exe"" clone __URI__ ""__TARGET__"""
		Dim rv : rv = m_shell.Run(Replace(Replace(cmd, "__URI__", source), "__TARGET__", target), 1, True)
		If rv <> 0 Then Err.Raise rv, "GitSCM.Clone", "Git clone failed"
	End Sub

	' Use Git to checkout a soufrce. Must be installed
	' Arguments:
	'	string source: source code folder
	'	string tag: tag name
	'	string branch: branch to be created
	Public Sub Checkout(source, tag, branch)
		If IsEmpty(m_location) Then If ret <> 0 Then Err.Raise 1, "GitSCM.Checkout", "Git not installed"
		Dim cmd : cmd = """" & m_location & "cmd\git.exe"" checkout __TAG__ -b __BRANCH__"
		Dim cur : cur = m_shell.CurrentDirectory
		m_shell.CurrentDirectory = source
		m_shell.Run Replace(Replace(cmd, "__TAG__", tag), "__BRANCH__", branch), 1, True
		m_shell.CurrentDirectory = cur
	End Sub
End Class

' Dr. Memory installation facility
Class DrMemory
	Private m_location, m_installer, m_fs
	Private Sub Class_Initialize()
		Set m_installer = New Installer
		Set m_fs = CreateObject("Scripting.FileSystemObject")
	End Sub
	Private Sub Class_Terminate()
		Set m_installer = Nothing
		Set m_fs = Nothing
	End Sub

	' Retrieves install location
	Public Function GetInstallLocation()
		Const ENTRY = "Dr. Memory"
		If IsEmpty(m_location) Then
			Dim stdout : Set stdout = m_fs.GetStandardStream(1)
			stdout.Write "Looking for Dr. Memory... "
			Dim ret : ret = m_installer.GetInstallLocation(ENTRY)
			If Not IsEmpty(ret) Then
				m_location = AddSlash(ret)
				stdout.WriteLine "Found!"
			Else
				stdout.WriteLine "Not found!"
			End If
			stdout.Close
			Set stdout = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Ensures software is installed 
	' Arguments:
	'	boolean retry: if true, tries to download and install it, if it does not exist
	public Function EnsureInstall(retry)
		Const DRM_SOURCE = "https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Windows-1.11.0-2.msi"
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) And retry Then
			m_installer.Install DRM_SOURCE, ".msi"
			WScript.Sleep 3000
			value = EnsureInstall(False)
			If IsEmpty(value) Then Err.Raise 1, "DrMemory.EnsureInstall", "Dr. Memory is required. Please, download and install it from " & DRM_SOURCE & ", then re-run this configure"
		End If
		EnsureInstall = value
	End Function
End Class

' NASM installation facility
Class NetwideASM
	Private m_registry, m_location, m_installer, m_fs
	Private Sub Class_Initialize()
		Set m_registry = New Registry
		Set m_installer = New Installer
		Set m_fs = CreateObject("Scripting.FileSystemObject")
	End Sub
	Private Sub Class_Terminate()
		Set m_registry = Nothing
		Set m_installer = Nothing
		Set m_fs = Nothing
	End Sub

	' Retrieves install location
	Public Function GetInstallLocation()
		Const HKLM_KEY = "SOFTWARE\nasm"
		Const HKCU_KEY = "Software\nasm"
		Const REGVALUE = ""
		If IsEmpty(m_location) Then
			Dim stdout : Set stdout = m_fs.GetStandardStream(1)
			stdout.Write "Looking for Netwide Assembler... "
			Dim value : value = m_registry.GetValue(HKEY_CURRENT_USER, HKCU_KEY, REGVALUE)
			If IsEmpty(value) Then
				value = m_registry.GetValue(HKEY_LOCAL_MACHINE, HKLM_KEY, REGVALUE)
			End If
			If Not IsEmpty(value) Then
				m_location = AddSlash(value)
				stdout.WriteLine "Found!"
			Else
				stdout.WriteLine "Not found!"
			End If
			stdout.Close
			Set stdout = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Ensures software is installed 
	' Arguments:
	'	boolean retry: if true, tries to download and install it, if it does not exist
	public Function EnsureInstall(retry)
		Const NASM_SOURCE = "https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/nasm-2.14.02-installer-x86.exe"
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) And retry Then
			m_installer.Install NASM_SOURCE, ".exe"
			WScript.Sleep 3000
			value = EnsureInstall(False)
			If IsEmpty(value) Then Err.Raise 1, "NetwideASM.EnsureInstall", "Netwide Assembler is required. Please, download and install it from " & NASM_SOURCE & ", then re-run this configure"
		End If
		EnsureInstall = value
	End Function
End Class

' Active Perl installation facility
Class ActivePerl
	Private m_registry, m_location, m_installer, m_fs
	Private Sub Class_Initialize()
		Set m_registry = New Registry
		Set m_installer = New Installer
		Set m_fs = CreateObject("Scripting.FileSystemObject")
	End Sub
	Private Sub Class_Terminate()
		Set m_registry = Nothing
		Set m_installer = Nothing
		Set m_fs = Nothing
	End Sub

	' Retrieves install location
	Public Function GetInstallLocation()
		Const REGKEY = "SOFTWARE\Perl"
		Const REGVALUE = ""
		If IsEmpty(m_location) Then
			Dim stdout : Set stdout = m_fs.GetStandardStream(1)
			stdout.Write "Looking for Active Perl... "
			Dim value : value = m_registry.GetValue(HKEY_LOCAL_MACHINE, REGKEY, REGVALUE)
			If Not IsEmpty(value) Then
				m_location = AddSlash(value)
				stdout.WriteLine "Found!"
			Else
				stdout.WriteLine "Not found!"
			End If
			stdout.Close
			Set stdout = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Ensures software is installed
	' Arguments:
	'	boolean retry: if true, tries to download and install it, if it does not exist
	public Function EnsureInstall(retry)
		Const PERL_SOURCE = "https://downloads.activestate.com/ActivePerl/releases/5.26.3.2603/ActivePerl-5.26.3.2603-MSWin32-x64-a95bce075.exe"
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) And retry Then
			m_installer.Install PERL_SOURCE, ".exe"
			WScript.Sleep 3000
			value = EnsureInstall(False)
			If IsEmpty(value) Then Err.Raise 1, "ActivePerl.EnsureInstall", "Active Perl is required. Please, download and install it from " & PERL_SOURCE & ", then re-run this configure"
		End If
		EnsureInstall = value
	End Function
End Class


' Apache Maven installation facility
Class Maven
	Private m_location, m_finder, m_installer
	Private Sub Class_Initialize()
		Set m_finder = New Finder
		Set m_installer = New Installer
	End Sub
	Private Sub Class_Terminate()
		Set m_finder = Nothing
		Set m_installer = Nothing
	End Sub

	' Retrieves install location
	Public Function GetInstallLocation()
		Const CMD = "mvn.cmd"
		If IsEmpty(m_location) Then
			Set fs = CreateObject("Scripting.FileSystemObject")
			Dim stdout : Set stdout = fs.GetStandardStream(1)
			stdout.Write "Looking for Apache Maven... "
			Dim value : value = m_finder.Find(CMD)
			If Not IsEmpty(value) Then
				m_location = AddSlash(fs.GetParentFolderName(value))
				stdout.WriteLine "Found!"
			Else
				stdout.WriteLine "Not found!"
			End If
			stdout.Close
			Set stdout = Nothing
			Set fs = Nothing
		End If
		GetInstallLocation = m_location
	End Function

	' Ensures software is installed
	' Arguments:
	'	boolean retry: if true, tries to download and install it, if it does not exist
	Public Function EnsureInstall(retry)
		Const MAVEN_URI = "http://ftp.unicamp.br/pub/apache/maven/maven-3/3.6.1/binaries/apache-maven-3.6.1-bin.zip"
		Dim value : value = GetInstallLocation()
		If IsEmpty(value) And retry Then
			Set shell = CreateObject("WScript.Shell")
			Dim target : target = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs"
			Set shell = Nothing
			m_installer.Unzip MAVEN_URI, target
			value = EnsureInstall(False)
		End If
		EnsureInstall = value
	End Function

End Class

' Nharu Library installation facility
Class Nharu
	Private REG_KEY, REG_VALUE
	Private m_location, m_current, m_vsis, m_jdkil, m_jdk64il, m_gitil, m_drmil, m_vnil, m_nasm, m_perl
	Private m_fs, m_vs, m_jdk, m_jdk64, m_git, m_drm, m_vn, m_installer, m_shell, m_nasmil, m_perlil
	Private Sub Class_Initialize()
		REG_KEY = "Software\Microsoft\Command Processor"
		REG_VALUE = "AutoRun"
		Set m_fs = CreateObject("Scripting.FileSystemObject")
		Set m_vs = New VisualStudio
		Set m_jdk = New Java
		Set m_jdk64 = New Java
		Set m_git = New GitSCM
		Set m_drm = New DrMemory
		Set m_vn = New Maven
		Set m_installer = New Installer
		Set m_nasm = New NetwideASM
		Set m_perl = New ActivePerl
		Set m_shell = CreateObject("Wscript.Shell")
		m_current = m_fs.GetParentFolderName(WScript.ScriptFullName)
	End Sub
	Private Sub Class_Terminate()
		Set m_fs = Nothing
		Set m_vs = Nothing
		Set m_jdk = Nothing
		Set m_jdk64 = Nothing
		Set m_git = Nothing
		Set m_drm = Nothing
		Set m_vn = Nothing
		Set m_nasm = Nothing
		Set m_perl = Nothing
		Set m_installer = Nothing
		Set m_shell = Nothing
	End Sub

	' Create configuration file
	' Arguments:
	'	string prefix: installation directory. Optional. Default: [nharu path]\dist
	Public Sub Configure(prefix)
		EnsurePreRequisites
		Dim stdout : Set stdout = m_fs.GetStandardStream(1)
		stdout.Write "Creating build script... "
		Dim template : Set template = m_fs.OpenTextFile(m_current & "\nharu-build.proj.in", 1)
		Dim out : Set out = m_fs.CreateTextFile(m_current & "\nharu-build.proj")
		If IsNull(prefix) Then prefix = m_fs.GetParentFolderName(m_current)
		While Not template.AtEndOfStream
			Dim line : line = template.ReadLine()
			line = Replace(line, "__TARGETDIR__", m_fs.GetParentFolderName(m_current))
			line = Replace(line, "__PREFIX__",    prefix)
			line = Replace(line, "__JDK32HOME__", RemoveSlash(m_jdkil))
			line = Replace(line, "__JDK64HOME__", RemoveSlash(m_jdk64il))
			out.WriteLine(line)
		Wend
		m_installer.AddToPath RequiredPath()
		stdout.WriteLine "Done!"
		template.Close
		Set template = Nothing
		out.Close
		Set out = Nothing
		stdout.Close
		Set stdout = Nothing
	End Sub

	Private Sub EnsurePreRequisites()
		If IsEmpty(m_vsis) Then
			m_vsis = m_vs.EnsureInstall()
			m_jdkil = m_jdk.EnsureInstall("7 Update 80")
			m_jdk64il = m_jdk64.EnsureInstall("7 Update 80 (64-bit)")
			m_gitil = m_git.EnsureInstall(True)
			m_drmil = m_drm.EnsureInstall(True)
			m_vnil = m_vn.EnsureInstall(True)
			m_nasmil = m_nasm.EnsureInstall(True)
			m_perlil = m_perl.EnsureInstall(True)
		End If
	End Sub
	Private Function RequiredPath()
		Dim ret : ret = ""
		If Not m_installer.IsInPath("git.exe") Then
			ret = ret & m_gitil & "cmd;"
		End if
		If Not m_installer.IsInPath("drmemory.exe") Then
			ret = ret & m_drmil & "bin;"
		End if
		If Not m_installer.IsInPath("mvn.cmd") Then
			ret = ret & m_vnil & "bin;"
		End If
		If Not m_installer.IsInPath("perl.exe") Then
			ret = ret & m_perlil & "bin;" & m_perlil & "site\bin;"
		End If
		If Not m_installer.IsInPath("nasm.exe") Then
			ret = ret & m_nasmil
		End If
		RequiredPath = ret
	End Function
End Class



' Installation facility
Class Installer
	Private m_installer, m_products, m_fs, m_current, m_shell, m_app
	Private Sub Class_Initialize()
		Set m_installer = Wscript.CreateObject("WindowsInstaller.Installer")
		Set m_products = m_installer.Products
		Set m_fs = CreateObject ("Scripting.FileSystemObject")
		m_current = m_fs.GetParentFolderName(WScript.ScriptFullName)
		Set m_shell = CreateObject("Wscript.Shell")
		Set m_app = CreateObject("Shell.Application")
	End Sub
	Private Sub Class_Terminate()
		Set m_products = Nothing
		Set m_installer = Nothing
		Set m_fs = Nothing
		Set m_shell = Nothing
		Set m_app = Nothing
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

	' Downloads and run installation application
	' Arguments:
	' 	URI source: installer location
	' 	string extension: install application extension (.exe or .msi)
	Public Sub Install(source, extension)
		Dim temp : temp = Download(source, extension)
		Dim ret : ret = m_shell.Run(temp, 0, True)
		m_fs.DeleteFile temp
		If ret <> 0 Then Err.Raise ret, "Installer.Install", "Installation aborted"
	End Sub

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

	Public Sub AddToPath(folder)

		If IsEmpty(folder) Or IsNull(folder) Or Len(folder) = 0 Then Exit Sub
		Dim old : old = m_shell.ExpandEnvironmentStrings("%Path%")
		Dim env : Set env = m_shell.Environment("User")
		env("Path") = old & ";" & folder
		Set env = Nothing

	End Sub

	' Dowloads and unzips specified resource
	' Arguments:
	'	URI source: URI where resource lies
	'	string target: destination folder
	Public Sub Unzip(source, target)
		Dim temp : temp = Download(source, ".zip")
		If Not m_fs.FolderExists(target) Then
			m_fs.CreateFolder target
		End If
		Dim oSource : Set oSource = m_app.NameSpace(temp).Items()
		Dim oTarget : Set oTarget = m_app.NameSpace(target)
		oTarget.CopyHere oSource, 256
		m_fs.DeleteFile temp
		Set oSource = Nothing
		Set oTarget = Nothing
	End Sub

	' Downloads specified resource
	' Arguments:
	'	URI source: resource location
	'	string extension: extension resource when created on disk (.exe, .msi, .zip)
	Private Function Download(source, extension)
		Const PCMD = "powershell -Command ""[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Method 'GET' -Uri '__URI__' -OutFile '__TARGET__'"""
		Dim ret : ret = m_current & "\" & Replace(m_fs.GetTempName(), ".tmp", extension)
		Dim cmd : cmd = Replace(Replace(PCMD, "__URI__", source), "__TARGET__", ret)
		Dim rv : rv = m_shell.Run(cmd, 1, True)
		If rv <> 0 Then Err.Raise rv, "Installer.Install", "Invoke-WebRequest commandlet failed to download resource"
		Download = ret
	End Function
End Class

' Windows Registry facility
Class Registry
	Private m_shell
	Private Sub Class_Initialize()
		Set m_shell = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
	End Sub
	Private Sub Class_Terminate()
		Set m_shell = Nothing
	End Sub

	' Reads a registry entry
	' Arguments:
	'   number root: root entry (HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE)
	'	string path: complete registry key
	'	string key: registry value name
	Public Function GetValue(root, path, key)
		Dim value, shit
		m_shell.GetStringValue root, path, key, shit
		If Not IsNull(shit) Then
			value = shit
		End If
		GetValue = value
	End Function

	' Reads a registru entru from HKEY_LOCAL_MACHINE
	' Arguments:
	'	string path: complete registry key
	'	string key: registry value name
	Public Function GetMachineValue(path, key)
		GetMachineValue = GetValue(HKEY_LOCAL_MACHINE, path, key)
	End Function

	' Reads a registru entru from HKEY_CURRENT_USER
	' Arguments:
	'	string path: complete registry key
	'	string key: registry value name
	Public Function GetLocalValue(path, key)
		GetLocalValue = GetValue(HKEY_CURRENT_USER, path, key)
	End Function

	Public Function SetStringValue(root, path, key, value)
		SetStringValue = m_shell.SetStringValue(root, path, key, value)
	End Function

	Public Function DeleteValue(root, path, key)
		DeleteValue = m_shell.DeleteValue(root, path, key)
	End Function

	Public Function CreateKey(root, path)
		CreateKey = m_shell.CreateKey(root, path)
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
		Dim alias, compressed
		If current.Attributes And 1024 Then
			alias = True
		Else
			alias = False
		End If
		If current.Attributes And 2048 Then
			compressed = true
		Else
			compressed = false
		End If
		If Not alias And Not compressed Then
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
		End If
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
'	/prefix: Library installation folder. Optional. Default: [path to Nharu]\dist
Sub Main
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library"
	WScript.Echo " Environment for Windows Development"
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo ""
	Dim args : Set args = WScript.Arguments.Named
	Dim prefix
	If args.Exists("prefix") Then
		prefix = args.Item("prefix")
	Else
		prefix = Null
	End If
	Set args = Nothing
	Dim cfg : Set cfg = New Nharu
	cfg.Configure prefix
	Set cfg = Nothing
	WScript.Echo ""
	WScript.Echo " * * * * * * * * * * * * * * * * * * * * * * * * * *"
	WScript.Echo " Nharu Library"
	WScript.Echo " Environment for Windows Development"
	WScript.Echo " --------------------------------------------------"
	WScript.Echo " Copyleft (C) 2015/2019 by The Crypthing Initiative"
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
