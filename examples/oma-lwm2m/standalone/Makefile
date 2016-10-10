PROJECT = lwm2m-example

all:	$(PROJECT)

COREDIRS = sys lib
APPSDIRS = er-coap oma-lwm2m ipso-objects rest-engine
TARGETCDIR = oma-lwm2m-src
TARGETCDIRS = ${addprefix $(TARGETCDIR)/,$(COREDIRS) $(APPSDIRS)}
SOURCEDIRS = . ${addprefix $(TARGETCDIR)/,. $(APPSDIRS)}
SOURCE_FILES = coap-ipv4.c ntimer-native.c

CFLAGS += ${addprefix -I,$(SOURCEDIRS)}

vpath %.c $(SOURCEDIRS)

-include Makefile.contiki

ifndef OBJECT_FILES
 SOURCE_FILES += ${wildcard ${addsuffix /*.c,$(TARGETCDIRS)} }
 OBJECT_FILES = $(SOURCE_FILES:.c=.o)
endif

$(PROJECT): $(PROJECT).c $(OBJECT_FILES)
	$(CC) $(CFLAGS) -o $@ $(PROJECT).c $(OBJECT_FILES)

lib:	liblwm2m.a

clean::
	@-rm -f $(OBJECT_FILES) *.o liblwm2m.a $(PROJECT)

liblwm2m.a: $(OBJECT_FILES)
	$(AR) rvs $@ $(OBJECT_FILES)

%.o:	%.c
	$(CC) $(CFLAGS) -c $< -o $@
