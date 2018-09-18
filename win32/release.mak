# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Windows RELEASE makefile for Nharu project
# Copyleft (C) 2018 by The Crypthing Initiative
# Authors:
#	diego.sohsten@caixa.gov.br
# 	yorick.flannagan@gmail.com
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
TARGET             = release
TARGET_CVARS       = /D "NDEBUG"
TARGET_CFLAGS      = /GL /Gy /O2 /Oi /MD
TARGET_LIB_CFLAGS  =
TARGET_TEST_CFLAGS =
TARGET_JCA_CFLAGS  =
TARGET_LFLAGS      = /MANIFEST:NO /LTCG:incremental /OPT:REF /SAFESEH /OPT:ICF
TARGET_LIB_LFLAGS  = /LTCG
TARGET_TEST_LFLAGS =
TARGET_JCA_LFLAGS  =
