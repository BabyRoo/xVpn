.PHONY: all clean

CC          = $(CROSS_COMPILE)gcc
LD          = $(CROSS_COMPILE)ld
AS          = $(CROSS_COMPILE)as
AR          = $(CROSS_COMPILE)ar

export AS LD CC 

include scripts/Kbuild.include

libs-y += app/
libs-y += ringbuff/
libs-y += listbuff/

my-dirs	:= $(patsubst %/,%,$(filter %/, $(libs-y)))	

libs-y := $(patsubst %/, %/built-in.o, $(libs-y))	

my-main := $(libs-y)					

ALL-y	+= xVpnClient


all:	$(ALL-y)

xVpnClient: $(my-main) FORCE
	$(CC) -o $@ $(libs-y) -lpthread -g  -lcrypto -lssl


$(my-main): $(my-dirs) ;

PHONY += $(my-dirs)
$(my-dirs): FORCE					
	$(MAKE) $(build)=$@

# read all saved command lines

targets := $(wildcard $(sort $(targets)))

PHONY += FORCE
FORCE:

clean: 
	set -e; \
	for dir in $(my-dirs); \
	do \
		$(MAKE) -f scripts/Makefile.clean obj=$$dir;\
	done	
	rm -fr $(ALL-y)



