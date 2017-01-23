/*
 * Copyright (c) 2016, SICS, Swedish ICT AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *         An OMA LWM2M standalone example to demonstrate how to use
 *         the Contiki OMA LWM2M library from a native application.
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "sys/ntimer.h"
#include "lwm2m-engine.h"
#include "lwm2m-rd-client.h"
#include "lwm2m-firmware.h"
#include "lwm2m-server.h"
#include "lwm2m-security.h"
#include "lwm2m-device.h"
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

void ipso_sensor_temp_init(void);
void ipso_control_test_init(void);
void ipso_blockwise_test_init(void);

/*---------------------------------------------------------------------------*/
static void
callback(ntimer_t *timer)
{
  /* Automatic notifcation on two things... for test!*/
  lwm2m_notify_observers("3303/0/5700");
  lwm2m_notify_observers("3/0/13");
  ntimer_reset(timer, 10000);
}
/*---------------------------------------------------------------------------*/
#ifndef LWM2M_DEFAULT_RD_SERVER
/* Default to leshan.eclipse.org */
#define LWM2M_DEFAULT_RD_SERVER "5.39.83.206"
#endif /* LWM2M_DEFAULT_RD_SERVER */
/*---------------------------------------------------------------------------*/
void
start_application(int argc, char *argv[])
{
  static ntimer_t nt;
  const char *default_server = LWM2M_DEFAULT_RD_SERVER;
  coap_endpoint_t server_ep;
  int has_server_ep = 0;

  if(argc > 1) {
    default_server = argv[1];
  }

  if(default_server != NULL && *default_server != '\0') {
    if(coap_endpoint_parse(default_server, strlen(default_server), &server_ep) == 0) {
      fprintf(stderr, "failed to parse the server address '%s'\n", default_server);
      exit(1);
    }
    has_server_ep = 1;
  }

  /* Example using network timer */
  ntimer_set_callback(&nt, callback);
  ntimer_set(&nt, 10000);

  /* Initialize the OMA LWM2M engine */
  lwm2m_engine_init();

  /* Register default LWM2M objects */
  /* lwm2m_engine_register_default_objects(); */

  ipso_sensor_temp_init();
  ipso_control_test_init();
  ipso_blockwise_test_init();

  lwm2m_firmware_init();
  lwm2m_device_init();
  lwm2m_security_init();
  lwm2m_server_init();

  if(has_server_ep) {
    /* start RD client */
    printf("Starting RD client to register at ");
    coap_endpoint_print(&server_ep);
    printf("\n");

#define BOOTSTRAP 0
#if BOOTSTRAP
    lwm2m_rd_client_register_with_bootstrap_server(&server_ep);
    lwm2m_rd_client_use_bootstrap_server(1);
#else
    lwm2m_rd_client_register_with_server(&server_ep);
#endif
    lwm2m_rd_client_use_registration_server(1);
    lwm2m_rd_client_init("abcde");
  } else {
    fprintf(stderr, "No registration server specified.\n");
  }
}
/*---------------------------------------------------------------------------*/
