# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Windows RELEASE makefile for Nharu project
# Copyleft (C) 2018 by The Crypthing Initiative
# Authors:
#	diego.sohsten@caixa.gov.br
# 	yorick.flannagan@gmail.com
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
TARGET       = release
T_CFLAGS     = /GL /Gy /errorReport:none /O2 /MD
T_CVARS      = /D "NDEBUG"
T_LIB_LFLAGS = /LTCG
T_JCA_LFLAGS = /MANIFEST:NO /OPT:REF /SAFESEH /INCREMENTAL:NO /OPT:ICF
T_TST_LFLAGS = /MANIFEST:NO /OPT:REF /SAFESEH /INCREMENTAL:NO /OPT:ICF
TARGET_ANT   = DEBUG=0