CONTIKI_PROJECT = mqtt-demo

all: $(CONTIKI_PROJECT)

PROJECTDIRS += ../../examples/ipso-objects
PROJECT_SOURCEFILES += example-ipso-object.c

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

APPS += er-coap
APPS += oma-lwm2m
APPS += ipso-objects
APPS += mqtt

ifdef WITH_BOOTSTRAP
CFLAGS += -DREGISTER_WITH_LWM2M_BOOTSTRAP_SERVER=1
endif

CONTIKI=../../..
CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include
