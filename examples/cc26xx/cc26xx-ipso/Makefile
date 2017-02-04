CONTIKI_PROJECT = mqtt-demo

all: $(CONTIKI_PROJECT)

TARGET=srf06-cc26xx
BOARD=sensortag/cc2650

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

APPS += er-coap
APPS += oma-lwm2m
APPS += ipso-objects
APPS += mqtt

ifdef WITH_BOOTSTRAP
CFLAGS += -DREGISTER_WITH_LWM2M_BOOTSTRAP_SERVER=1
endif

PROJECTDIRS += ../../ipso-objects
PROJECT_SOURCEFILES += example-ipso-objects.c

CONTIKI=../../..
CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include
