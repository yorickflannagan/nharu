# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Windows DEBUG makefile for Nharu project
# Copyleft (C) 2018 by The Crypthing Initiative
# Authors:
#	diego.sohsten@caixa.gov.br
# 	yorick.flannagan@gmail.com
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
TARGET            = debug
TARGET_CVARS      = /D "_DEBUG" /D "_DEBUG_"
TARGET_CFLAGS     = /Od /RTC1 /MDd
TARGET_LIB_LFLAGS = /DEBUG
