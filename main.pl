use XML::LibXML;
use XML::LibXML::NodeList;

use File::Path;
 
use strict;
use warnings;
use Switch; 

# Templates
my %templates  = ( 
					'native', "\t\t<attributes>\n\t\t\t<attribute name=\"org.eclipse.jdt.launching.CLASSPATH_ATTR_LIBRARY_PATH_ENTRY\" value=\"_____NATIVE_LYBRARY_____\"/>\n\t\t</attributes>\n",
					'classpathentry', "\t<classpathentry ___COMBINE___ kind=\"___KIND___\" path=\"___PATH___\" ___SOURCES___ >\n___NATIVE___\t</classpathentry>",
					'classpath', "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<classpath>___CP_ENTRIES___\n</classpath>",
					'jdk_cp_entry', "org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/___JDK___",
					'linked_resources', "\t\t<link>\n\t\t\t<name>___SRC___</name>\n\t\t\t<type>___LINK_TYPE___</type>\n\t\t\t<locationURI>___LOCATION___</locationURI>\n\t\t</link>",
					'preferences', "eclipse.preferences.version=___VERSION___\norg.eclipse.jdt.core.compiler.codegen.inlineJsrBytecode=___ILJBC___\norg.eclipse.jdt.core.compiler.codegen.targetPlatform=___TARGET_PLATAFORM___\norg.eclipse.jdt.core.compiler.codegen.unusedLocal=___UNUSED_LOCAL___\norg.eclipse.jdt.core.compiler.compliance=___COMPLIANCE___\norg.eclipse.jdt.core.compiler.debug.lineNumber=___LINE_NUMBER___\norg.eclipse.jdt.core.compiler.debug.localVariable=___LOCAL_VARIABLE___\norg.eclipse.jdt.core.compiler.debug.sourceFile=___SOURCE_FILE___\norg.eclipse.jdt.core.compiler.problem.assertIdentifier=___ASSERT_IDENTIFIER___\norg.eclipse.jdt.core.compiler.problem.enumIdentifier=___ENUM_IDENTIFIER___\norg.eclipse.jdt.core.compiler.source=___SOURCE___",
					'project', "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<projectDescription>\n\t<name>_____PROJECT_NAME_____</name>\n\t<comment></comment>\n\t<projects>\n\t</projects>\n\t<buildSpec>\n\t\t<buildCommand>\n\t\t\t<name>org.eclipse.jdt.core.javabuilder</name>\n\t\t\t<arguments>\n\t\t\t</arguments>\n\t\t</buildCommand>\n\t</buildSpec>\n\t<natures>\n\t\t<nature>org.eclipse.jdt.core.javanature</nature>\n\t</natures>\n\t<linkedResources>\n_____LINKED_RESOURCES_____\n\t</linkedResources>\n</projectDescription>"
					);

my $RED   = "\e[0;31m";
my $GREEN = "\e[0;32m";
my $WHITE = "\e[0m";

my %JAVA;
$JAVA{"1.7"}{"acquire"} = "wget --no-check-certificate --no-cookies --output-document ___OUTPUT___ --header \"Cookie: oraclelicense=accept-securebackup-cookie\" http://download.oracle.com/otn-pub/java/jdk/7u55-b13/jdk-7u55-linux-i586.tar.gz";
$JAVA{"1.7"}{"version_string"} = "java version \"1.7.0_55\"\nJava(TM) SE Runtime Environment (build 1.7.0_55-b13)\nJava HotSpot(TM) Client VM (build 24.55-b03, mixed mode)";
$JAVA{"1.7"}{"root_dir"} = "jdk1.7.0_55";
$JAVA{"1.7"}{"jdk_string"} = "JavaSE-1.7";


my $LOG = "";

main ($ARGV[0]);

sub main
{

	my $srcfile   = shift;
	my XML::LibXML $parser = XML::LibXML->new();
	
	my $docstr = replace_env(read_file($srcfile));
	my $doc = $parser->parse_string($docstr);
	environment($doc);
	
	#Refresh now with new environment variables resolved. 
	$docstr = replace_env(read_file($srcfile));
	$doc = $parser->parse_string($docstr);


	resources($doc);
	eclipse($doc);
	tests($doc);
	
	print $LOG;
}

sub morre
{
	my $msg = shift;
	
	$LOG .= "$RED\n------------------------------------------------------------------------------------\n";
    $LOG .= " ERRO FATAL : $msg\n";
	$LOG .= "------------------------------------------------------------------------------------$WHITE\n";
	print $LOG;
	die
}

sub	environment
{
	my $doc = shift;
	my $result = $doc->find( "/configure/environment/env" );
	my XML::LibXML::Element $node;
	my $exporting = "#!/bin/bash\n";
	my $scriptfile = ($doc->find("/configure/environment" )->get_nodelist())[0]->getAttribute('scriptfile');
	
	
	if ( $result->isa( 'XML::LibXML::NodeList' ) ) {
	        foreach $node ( @$result) {
	        	my $name = $node->getAttribute('name');
	        	my $value = $node->getAttribute('cmd');
	        	if(defined($value) && $value ne "")
	        	{
	        		$value = command_output($value);
	        	} 
	        	else
	        	{
	        		$value = replace_env($node->getAttribute('value'));
	        	}
	        	$ENV{$name} = $value;
	        	my $export = $node->getAttribute('export');
	        	if(!(defined $export && $export =~ /false/i))
	        	{
	        		$exporting .= "export $name=\"$value\"\n";
	        		 
	        	}
	        }
			$LOG .= "\n------------------------------------------------------------------------------------\n";
	        $LOG .= "Exported variables : \n";
			$LOG .= "------------------------------------------------------------------------------------\n";
			$LOG .= "$exporting\n\n";	        
	        write_file($scriptfile, $exporting);
	}
	return 0;	
	
	
}

sub resources
{
	my $doc = shift;
	my $result = $doc->find( "/configure/resources/*" );
	my XML::LibXML::Element $node;
	$LOG .= "\n------------------------------------------------------------------------------------\n";
	$LOG .= "Resources:\n";
	$LOG .= "------------------------------------------------------------------------------------\n";
	
	if ( $result->isa( 'XML::LibXML::NodeList' ) ) {
	        foreach $node ( @$result) {
	        	my $nodename = $node->nodeName();
	        	switch ($nodename)
	        	{
	        		case "dir" {
						my $name = $node->getAttribute('name');
						unless(create_dir ($name))
						{
							morre("Could not create dir: $name");
						} 
						$LOG .= "Created dir: $name\n";
	        		}
				case "cmd" {
						my $value = $node->getAttribute('value');
						$LOG .= command_output($value);

				}
	        		else {
						morre("Resource $nodename not supported.");
						#todo: add more resources
	        		}
	        	}
	        }
	}
	$LOG .= "\n\n";
	
}

sub tests
{
	my $doc = shift;
	my $result = $doc->find( "/configure/tests/test" );
	my XML::LibXML::Element $node;
	
	$LOG .= "\n------------------------------------------------------------------------------------\n";
	$LOG .= "Test Environment : \n";
	$LOG .= "------------------------------------------------------------------------------------\n";
	
	if ( $result->isa( 'XML::LibXML::NodeList' ) ) {
	        foreach $node ( @$result) {
	        	my $command = $node->getAttribute("eval") . "(\"" . $node->getAttribute("value") . "\", \$node)";
	        	my $retorno = eval($command);
	        	unless(defined $retorno)
	        	{
	        		morre("Não foi possível executar o commando: $command");
	        	}
	        	$LOG .=$retorno;
	        	$LOG .="\n";
	        }
	}
}


sub install_openssl
{
	my $destination = shift;
	my $dirname = "openssl-1.0.1h";
	my $tddir = $ENV{"TD_DIR"};
	my $output = "wget --no-check-certificate --no-cookies --output-document $tddir/openssl-1.0.1h.tar.gz http://www.openssl.org/source/openssl-1.0.1h.tar.gz";


	if(-e "$destination")
	{
		if(-e "$ENV{OPENSSL_HOME}")
		{
			return "";
		}
		$LOG .= $RED . "Openssl: already in place. See specs for complete instalation.\n$WHITE";
		return make_openssl($destination);
	}

	print "Downloading Openssl. It will take some time.\n";
	$LOG .= command_output($output);
	$LOG .= "\n";
	



	if($? >> 8 != 0)
	{
		$LOG .= "\nOpenssl Install: Error no GET.";
		return;
	}

	$output = "tar -zxvf $tddir/openssl-1.0.1h.tar.gz  -C \$(dirname $destination)";
	$LOG .= command_output($output);
	$LOG .= "\n";
	if($? >> 8 != 0)
	{
		$LOG .= "\nOpenssl Install: Error no TAR.";
		return;

	}
	$output = "mv \$(dirname $destination)/$dirname $destination";
	$LOG .= command_output($output);
	$LOG .= "\n";
	if($? >> 8 != 0)
	{
		$LOG .=  "\nOpenssl Install: Error no Rename.";
		return;
	}

	return make_openssl($destination);

}

sub make_openssl
{
	my $curr = $ENV{"PWD"};
	my $destination = shift;
	
	print "Making Openssl, go get some cofee.\n";

	chdir($destination) or morre("Não foi possível ir para o diretorio do openssl");

	print "\tConfig.\n";
	my $output = "config --prefix=$destination/install threads no-shared -fPIC";
	$LOG .= command_output($output);
	$LOG .= "\n";
	if($? >> 8 != 0)
	{
		chdir($curr);
		$LOG .= "\nOpenssl Install: Error no Config.";
		return;
	}

	print "\tMake.\n";
	$output = "make";
	$LOG .= command_output($output);

	$LOG .= "\n";
	if($? >> 8 != 0)
	{
		chdir($curr);
		$LOG .= "\nOpenssl Install: Error no Make.";
		return;
	}


	print "\tTest.\n";
	$output = "make test";
	$LOG .= command_output($output);
	$LOG .= "\n";
	if($? >> 8 != 0)
	{
		chdir($curr);
		$LOG .= "\nOpenssl Install: Error no Make Test.";
		return;

	}

	print "\tInstall.\n";
	$output = "make install";
	$LOG .= command_output($output);
	$LOG .= "\n";
	if($? >> 8 != 0)
	{
		chdir($curr);
		$LOG .= "\nOpenssl Install: Error no Make install.";
		return;
	}
	chdir($curr);
	return 0;
}


sub create_java_inner_dependencies
{

	my $curr = $ENV{"PWD"};
	my $output = "jar -xvf " . $ENV{"JAVA_HOME"} . "/jre/lib/rt.jar  sun/security/ec/ECPublicKeyImpl.class";
	my $outdir = $ENV{"TD_DIR"} . "/javaextract";
	chdir($outdir);
	$LOG .= command_output($output);
	chdir($curr);
}



sub install_java
{
	my $destination = shift;
	my $node = shift;
	my %version; 
	my $version_str;
	my $renamedir;
	my $output;
	my $jdk = $node->getAttribute("version");


	$LOG .= "      # ######  #    #
      # #     # #   #
      # #     # #  #
      # #     # ###
#     # #     # #  #
#     # #     # #   #
 #####  ######  #    #

  ###
   #     #    #   ####    #####    ##    #       #
   #     ##   #  #          #     #  #   #       #
   #     # #  #   ####      #    #    #  #       #
   #     #  # #       #     #    ######  #       #
   #     #   ##  #    #     #    #    #  #       #
  ###    #    #   ####      #    #    #  ######  ######";

	
	if(!exists  $JAVA{$jdk})
	{
		morre("JDK  $jdk não suportada.");
	}
	
	$output = $JAVA{$jdk}{"acquire"};
	$renamedir = $JAVA{$jdk}{"root_dir"};
	$version_str = $JAVA{$jdk}{"version_string"};
	
	
	if(-e "$destination/bin/java")
	{
		my $installed_version = command_output("$destination/bin/java -version");
		if($installed_version eq $version_str)
		{
			$LOG .= "JDK $jdk version already installed.";
			return 0;
		}
		
		
	}
	
	
	if(!create_dir($destination))
	{
		$LOG .= "Could not create java dir";
		return; 
	}

	
	
	$output =~ s/___OUTPUT___/$destination\/jdk.tar.gz/g;
	$LOG .= command_output($output);
	if($? >> 8 != 0)
	{
		return "Java Install: Error no GET.";
	}
	$output = "tar -zxvf jdk.tar  -C \$(dirname $destination)";
	$LOG .= command_output($output);
	if($? >> 8 != 0)
	{
		return "Java Install: Error no TAR.";
	}
	$output = "mv \$(dirname $destination)/$renamedir $destination";
	$LOG .= command_output($output);
	if($? >> 8 != 0)
	{
		return "Java Install: Error no Rename.";
	}
	return 0;	
}

sub echo_cmd
{
	my $command = shift;
	if($command =~ m/^\S*/g)
	{
		if(-x $& )
		{
			return 	command_output($command);
		}
	}
	return "Could not execute line: $command. Not found, empty or not executable.";
}


sub exist_dir
{
	
	my $name = shift;
	my $found = "$RED NOT FOUND\e[0m $WHITE";
	if(-d $name)
	{
		$found = "$GREEN FOUND     $WHITE";
	} else
	{
		if(-e $name)
		{
			$found = "$RED NOT A DIRECTORY$WHITE";
		}
	}
	my $message = "Directory $found: $name";
	return $message
}


sub exist_file
{
	
	my $name = shift;
	my $found = "$RED NOT FOUND\e[0m $WHITE";
	if(-e $name)
	{
		$found = "$GREEN FOUND     $WHITE";
	} else
	{
		if(-d $name)
		{
			$found = "$RED NOT A FILE$WHITE";
		}
	}
	my $message = "File      $found: $name";
	return $message
}


sub eclipse
{
	my $doc = shift;
	my $result = $doc->find("/configure/projects/project");
	my $node;
	$LOG .= "\n------------------------------------------------------------------------------------\n";
	$LOG .= "Eclipse Projects:\n";
	$LOG .= "------------------------------------------------------------------------------------\n";
	
	if ( $result->isa( 'XML::LibXML::NodeList' ) ) {
	        foreach $node ( @$result) {
	        	create_project ($node);
	        }
	}
	return 0;	
}

sub create_project
{
	my $err;
	my $node = shift;
	my $name = $node->getAttribute('name');
	$LOG .= "Project: $name\n";

	my $dir = $node->getAttribute('dir');
	$LOG .= "\tdir: $dir\n";
	my @classpath = $node->findnodes('classpath');
	my @paths;
	if(@classpath)
	{
		@paths = (@classpath)[0]->find('path')->get_nodelist();
	}
	my @sources = ($node->findnodes('sources'))[0]->find('source')->get_nodelist();
	
	my @_links = $node->findnodes('links');
	my @links;
	if(@_links)
	{
		@links = (@_links)[0]->find('link')->get_nodelist();
	}
	
	
	my $project = $templates{'project'};
	my $preferences = ($node->findnodes('preferences'))[0];
	my $temp;
	
	#Creates project dir
	if(!create_dir($dir) || !create_dir("$dir/.settings"))
	{
		#todo: Retorno para este tipo de situação.
		return -1;
	}
	
	#Replaces _____PROJECT_NAME_____ with project name
	$project =~ s/_____PROJECT_NAME_____/$name/g;


	#Resolving _____LINKED_RESOURCES_____
	my $linked = "";
	my $jdir;
	
	for my $link (@links)
	{
		my $src_dir;
		my $type;
		if(($link->hasAttribute("dir")))
		{
			$src_dir=$link->getAttribute("dir");
			$type=2;
		}
		else
		{
			if(($link->hasAttribute("file")))
			{
				$src_dir=$link->getAttribute("file");
				$type=1;
			}
			else
			{
				return -10;
			}
		}
		$temp = $templates{'linked_resources'};
		# ___SRC___
		#___LOCATION___
		#___LINK_TYPE___
		
		if(!($link->hasAttribute("base")))
		{
			return -2;
		}

		my $base = $link->getAttribute("base");
		
		$temp =~ s/___SRC___/$base/g;
		
		$temp =~ s/___LOCATION___/$src_dir/g;

		$temp =~ s/___LINK_TYPE___/$type/g;

		$linked .= $temp;
	}
		
	for my $source (@sources)
	{
		my $src_dir = $source->getAttribute("dir");
		for $jdir (with_java($src_dir))
		{
			my $base;
			$temp = $templates{'linked_resources'};
			# ___SRC___
			#___LOCATION___
			#___LINK_TYPE___			
			
			if($source->hasAttribute("base"))
			{
				$base = $source->getAttribute("base") . '/' . $jdir;
				
			} else
			{
				$base = $jdir;
			}
			$temp =~ s/___SRC___/java\/$base/g;
			my $tmpdir =  $src_dir . "/" . $jdir;
			$temp =~ s/___LOCATION___/$tmpdir/g;
			$temp =~ s/___LINK_TYPE___/2/g;
			
			$linked .= $temp;
		}
	}
	$project =~ s/_____LINKED_RESOURCES_____/$linked/g;
	write_file($dir . "/.project", $project);
	
	# Resolving classpath.
	my $cpentries = "";
	my $src_native = ($node->findnodes('sources'))[0]->getAttribute('native');
	$src_native = $src_native  ? $src_native : "";
	$cpentries .= create_cp_entry("", "src", "java", "", $src_native);
	
	if(@paths)
	{
		for my $path (@paths)
		{
			my $type = $path->getAttribute("type") eq "ref" ? "src" : $path->getAttribute("type");
			my $combine = $type eq "ref" ? "false" : "";
			my $dir =  $path->getAttribute("dir");
			my $src_dir = $path->getAttribute("source");
			my $nat_dir = $path->getAttribute("native");
			$cpentries .= "\n";
			$cpentries .= create_cp_entry($combine, $type, $dir, $src_dir, $nat_dir);
		}
	}
	
	$temp = $templates{'jdk_cp_entry'};
	my $jdk =  $preferences->getAttribute('targetPlatform');
	if(!defined $jdk or !exists $JAVA{$jdk})
	{
		morre("JDK $jdk não suportada.")
	}
	$temp =~ s/___JDK___/$JAVA{$jdk}{"jdk_string"}/ge;
	$cpentries .= "\n";
	$cpentries .= create_cp_entry("", "con", "$temp", "", $preferences->getAttribute('native'));
	
	$temp = $templates{'classpath'};
	$temp =~ s/___CP_ENTRIES___/$cpentries/g;
	write_file($dir . "/.classpath", $temp);
	
	# Creating Templates:
	$temp = $templates{'preferences'};
	$temp =~ s/___VERSION___/$preferences->getAttribute('version')/eg;
	$temp =~ s/___ILJBC___/$preferences->getAttribute('inlineJsrBytecode')/eg;
	$temp =~ s/___TARGET_PLATAFORM___/$preferences->getAttribute('targetPlatform')/eg;
	$temp =~ s/___UNUSED_LOCAL___/$preferences->getAttribute('unusedLocal')/eg;
	$temp =~ s/___COMPLIANCE___/$preferences->getAttribute('compliance')/eg;
	$temp =~ s/___LINE_NUMBER___/$preferences->getAttribute('lineNumber')/eg;
	$temp =~ s/___LOCAL_VARIABLE___/$preferences->getAttribute('localVariable')/eg;
	$temp =~ s/___SOURCE_FILE___/$preferences->getAttribute('sourceFile')/eg;
	$temp =~ s/___ASSERT_IDENTIFIER___/$preferences->getAttribute('assertIdentifier')/eg;
	$temp =~ s/___ENUM_IDENTIFIER___/$preferences->getAttribute('enumIdentifier')/eg;
	$temp =~ s/___SOURCE___/$preferences->getAttribute('source')/eg;
	write_file($dir . "/.settings/org.eclipse.jdt.core.prefs", $temp);
	

	
}

sub command_output
{
	my $file = shift;
	open (FILE, "$file  2>&1|") or morre("could not execute.");
    local $/=undef;
	my $lines = <FILE>;
	close FILE;	
	local $/="";
	chomp($lines);
	return $lines;
}


sub create_cp_entry
{
	my $temp;
	my $combine = shift // ""; 
	my $kind = shift // "";
	my $path = shift // "";
	my $source = shift // "";
	my $native = shift // "";

	$LOG .= "\tCreating classpath entry.\n\t\ttype: $kind\n\t\tpath: $path\n\t\tsource: $source\n";


	if($kind eq "") { morre ("No kinding");	}
	if($path eq "") { morre("No path");		}
	$temp =  $templates{'classpathentry'};
	$combine eq ""  ?	$temp =~ s/___COMBINE___//g : $temp =~ s/___COMBINE___/combineaccessrules=\"$combine\"/g;
	$source eq ""	?	$temp =~ s/___SOURCES___//g : $temp =~ s/___SOURCES___/sourcepath=\"$source\"/g; 
	$temp =~ s/___KIND___/$kind/g;
	$temp =~ s/___PATH___/$path/g;
	$native eq ""	?	$temp =~ s/___NATIVE___//g  : $temp =~ s/___NATIVE___/$templates{'native'}/g;
	$temp =~ s/_____NATIVE_LYBRARY_____/$native/g;
	return $temp;	
}

sub create_dir
{
	my $err;
    mkpath (shift,{ error => \$err });
	if(@$err)
	{
		for my $diag (@$err)
		{
			my ($file, $message) = %$diag;
			print $file . ': ' . $message . "\n";
		}
		return 0;
	}
	return 1;
	
}

sub with_java
{
	my $dir = shift;
	my @ret;
	opendir(DIR_H, $dir);
	my @files = grep { !/^\.{1,2}$/ } readdir (DIR_H);
    closedir(DIR_H);
	for my $file (@files)
	{
		if(-d "$dir/$file" && has_java("$dir/$file"))
		{
			push @ret,$file;
		}
	}
	return @ret;
}

sub has_java
{
	my $dir = shift;
	opendir(DIR, $dir);
	my @files = grep { !/^\.{1,2}$/ } readdir (DIR);
    closedir(DIR);
	for my $file (@files)
	{
		if("$file" =~ /\.java$/) 
		{	
			return 1;
		} else
		{
			if(-d "$dir/$file" && has_java("$dir/$file"))
			{
				return 1;
			}
		}
    }
	return 0;
}

sub replace_env
{
	my $value = shift;
#	$value =~ s/\$(\w+)/$ENV{$1}/g;
	$value =~ s#\${?(\w+)}?# exists $ENV{$1} ? $ENV{$1} : $& #ge;
	return $value;
}

sub read_file
{
	my  $filename = shift;
    open(FILE, $filename ) or morre("Cant open $filename\n");
    local $/=undef;
    my $lines = <FILE>;
    close FILE;
	return $lines;	
	
}

sub write_file
{
	my  $filename = shift;
    open(FILE, ">$filename" ) or morre("Cant open $filename\n");
	print FILE shift;
	close FILE;
	
}
