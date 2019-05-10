# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Windows DEBUG makefile for Nharu project
# Copyleft (C) 2018 by The Crypthing Initiative
# Authors:
#	diego.sohsten@caixa.gov.br
# 	yorick.flannagan@gmail.com
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
T_CFLAGS      = /ZI /Od /errorReport:prompt /MDd /Ob0 /FA /Fa$(OBJ)\ /Fd$(OBJ)\ 
T_CVARS       = /D "_DEBUG" /D "_DEBUG_"
T_LIB_LFLAGS  = 
T_JCA_LFLAGS  = /MANIFEST /DEBUG /INCREMENTAL /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /ManifestFile:"$(OUT)\nharujca.dll.intermediate.manifest" /PDB:"$(OBJ)\nharujca.pdb"
T_TST_LFLAGS  = /ManifestFile:"$(OUT)\rtest.exe.intermediate.manifest" /PDB:"$(OBJ)\rtest.pdb"
TARGET_ANT    = DEBUG=1
