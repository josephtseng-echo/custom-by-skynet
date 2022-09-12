#SRC_DIR = ./mylualib-src
#LIB_DIR = ../myluaclib
#
#SRC = ${wildcard ${SRC_DIR}/*.c}
#LIB = ${patsubst lua-%.c, ${LIB_DIR}/%.so, ${notdir ${SRC}}}
#
#
#all:${LIB}
#
#${LIB_DIR}/%.so:${SRC_DIR}/lua-%.c
#	cc -g -O2 -Wall -Iskynet/3rd/lua -fPIC --shared $< -o $@ -lcurl
#
#.PHONY:clean
#clean:
#	rm ${LIB}	
ROOT = ..
SKYNET_ROOT = /data/env/skynet
BIN = $(ROOT)/myluaclib/
config ?= debug
existDir=$(shell if [ -d $(soPath) ]; then echo "yes"; else echo "no"; fi;)

JSON = json

all: createln $(BIN)mypack.so $(BIN)mypacket.so
FLAG = -g -Wall -Iskynet/3rd/lua -fPIC --shared
INCLUDE = -I$(SKYNET_ROOT)/skynet-src
LIB = 

createln:

$(BIN)mypack.so: lua-mypack.c
	gcc $(FLAG) $(LIB) $(INCLUDE) lua-mypack.c -o $@ 
	
$(BIN)mypacket.so: lua-mypacket.c
	gcc $(FLAG) $(LIB) $(INCLUDE) lua-mypacket.c -o $@	

clean:
	rm -f $(BIN)*

rebuild: clean all	
