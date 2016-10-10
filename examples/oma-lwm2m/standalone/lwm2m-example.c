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
#include "coap-ipv4.h"
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/*---------------------------------------------------------------------------*/
static void
callback(ntimer_t *timer)
{
  printf("uptime: %"PRIu64"\n", ntimer_uptime());
  ntimer_reset(timer, 10000);
}
/*---------------------------------------------------------------------------*/
void
start_application(int argc, char *argv[])
{
  static ntimer_t nt;
  coap_endpoint_t server_ep;

  /* Example using network timer */
  ntimer_set_callback(&nt, callback);
  ntimer_set(&nt, 10000);

  /* Initialize the OMA LWM2M engine */
  lwm2m_engine_init();

  /* Register default LWM2M objects */
  lwm2m_engine_register_default_objects();

  /* set server and port */
  server_ep.addr.sin_family = AF_INET;
  server_ep.addr.sin_port = htons(5683);
  inet_aton("172.16.31.179", &server_ep.addr.sin_addr);
  server_ep.addr_len = sizeof(server_ep.addr);

  /* start RD client */
  lwm2m_rd_client_register_with_server(&server_ep);
  lwm2m_rd_client_use_registration_server(1);
  lwm2m_rd_client_init("?ep=abcde");
}
/*---------------------------------------------------------------------------*/
