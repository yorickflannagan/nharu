# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Windows DEBUG makefile for Nharu project
# Copyleft (C) 2018 by The Crypthing Initiative
# Authors:
#	diego.sohsten@caixa.gov.br
# 	yorick.flannagan@gmail.com
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
TARGET             = debug
TARGET_CVARS       = /D "_DEBUG" /D "_DEBUG_"
TARGET_CFLAGS      = /Od /RTC1 /MDd
TARGET_LIB_CFLAGS  = /Fd"$(OBJ_FILES)\nharu-lib.pdb"
TARGET_TEST_CFLAGS = /Fd"$(OBJ_FILES)\rtest.pdb"
TARGET_JCA_CFLAGS  = /Fd"$(OBJ_FILES)\nharujca.pdb"
TARGET_LFLAGS      = /DEBUG /MANIFEST /MANIFESTUAC:"level='asInvoker' uiAccess='false'"
TARGET_LIB_LFLAGS  =
TARGET_TEST_LFLAGS = /ManifestFile:"$(OUT_FILES)\rtest.exe.intermediate.manifest" /PDB:"$(OBJ_FILES)\rtest.pdb"
TARGET_JCA_LFLAGS  = /ManifestFile:"$(OUT_FILES)\nharujca.dll.intermediate.manifest" /PDB:"$(OBJ_FILES)\nharujca.pdb"
