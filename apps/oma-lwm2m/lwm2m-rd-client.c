/*
 * Copyright (c) 2015, Yanzi Networks AB.
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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \addtogroup oma-lwm2m
 * @{
 */

/**
 * \file
 *         Implementation of the Contiki OMA LWM2M engine
 *         Registration and bootstrap client
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

#include "contiki.h"
#include "lwm2m-engine.h"
#include "lwm2m-object.h"
#include "lwm2m-device.h"
#include "lwm2m-plain-text.h"
#include "lwm2m-json.h"
#include "er-coap.h"
#include "er-coap-engine.h"
#include "er-coap-blocking-api.h"
#include "oma-tlv.h"
#include "oma-tlv-reader.h"
#include "oma-tlv-writer.h"
#include "net/ipv6/uip-ds6.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif /* UIP_CONF_IPV6_RPL */

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

#define REMOTE_PORT        UIP_HTONS(COAP_DEFAULT_PORT)
#define BS_REMOTE_PORT     UIP_HTONS(5685)

PROCESS(lwm2m_rd_client, "LWM2M Engine");

static uip_ipaddr_t server_ipaddr;
static uint16_t server_port = REMOTE_PORT;
static uip_ipaddr_t bs_server_ipaddr;
static uint16_t bs_server_port = BS_REMOTE_PORT;

static coap_endpoint_t bs_server_endpoint;
static coap_endpoint_t server_endpoint;

static uint8_t use_bootstrap = 0;
static uint8_t has_bootstrap_server_info = 0;
static uint8_t use_registration = 0;
static uint8_t has_registration_server_info = 0;
static uint8_t registered = 0;
static uint8_t bootstrapped = 0; /* bootstrap made... */

static char *endpoint;
static char rd_data[128]; /* allocate some data for the RD */

/*---------------------------------------------------------------------------*/
static int
index_of(const uint8_t *data, int offset, int len, uint8_t c)
{
  if(offset < 0) {
    return offset;
  }
  for(; offset < len; offset++) {
    if(data[offset] == c) {
      return offset;
    }
  }
  return -1;
}

/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
static int
has_network_access(void)
{
#if UIP_CONF_IPV6_RPL
  if(rpl_get_any_dag() == NULL) {
    return 0;
  }
#endif /* UIP_CONF_IPV6_RPL */
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
client_chunk_handler(void *response)
{
#if (DEBUG) & DEBUG_PRINT
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  PRINTF("|%.*s\n", len, (char *)chunk);
#endif /* (DEBUG) & DEBUG_PRINT */
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_use_bootstrap_server(int use)
{
  use_bootstrap = use != 0;
  if(use_bootstrap) {
    process_poll(&lwm2m_rd_client);
  }
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_use_registration_server(int use)
{
  use_registration = use != 0;
  if(use_registration) {
    process_poll(&lwm2m_rd_client);
  }
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_register_with_server(const uip_ipaddr_t *server, uint16_t port)
{
  uip_ipaddr_copy(&server_ipaddr, server);
  if(port != 0) {
    server_port = port;
  } else {
    server_port = REMOTE_PORT;
  }
  has_registration_server_info = 1;
  registered = 0;
  if(use_registration) {
    process_poll(&lwm2m_rd_client);
  }
}
/*---------------------------------------------------------------------------*/
static int
update_registration_server(void)
{
  if(has_registration_server_info) {
    return 1;
  }

#if UIP_CONF_IPV6_RPL
  {
    rpl_dag_t *dag;

    /* Use the DAG id as server address if no other has been specified */
    dag = rpl_get_any_dag();
    if(dag != NULL) {
      uip_ipaddr_copy(&server_ipaddr, &dag->dag_id);
      server_port = REMOTE_PORT;
      return 1;
    }
  }
#endif /* UIP_CONF_IPV6_RPL */

  return 0;
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_register_with_bootstrap_server(const uip_ipaddr_t *server,
                                            uint16_t port)
{
  uip_ipaddr_copy(&bs_server_ipaddr, server);
  if(port != 0) {
    bs_server_port = port;
  } else {
    bs_server_port = BS_REMOTE_PORT;
  }
  has_bootstrap_server_info = 1;
  bootstrapped = 0;
  registered = 0;
  if(use_bootstrap) {
    process_poll(&lwm2m_rd_client);
  }
}
/*---------------------------------------------------------------------------*/
static int
update_bootstrap_server(void)
{
  if(has_bootstrap_server_info) {
    return 1;
  }

#if UIP_CONF_IPV6_RPL
  {
    rpl_dag_t *dag;

    /* Use the DAG id as server address if no other has been specified */
    dag = rpl_get_any_dag();
    if(dag != NULL) {
      uip_ipaddr_copy(&bs_server_ipaddr, &dag->dag_id);
      bs_server_port = REMOTE_PORT;
      return 1;
    }
  }
#endif /* UIP_CONF_IPV6_RPL */

  return 0;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(lwm2m_rd_client, ev, data)
{
  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static struct etimer et;

  PROCESS_BEGIN();

  printf("RD Client started with endpoint '%s'\n", endpoint);

  etimer_set(&et, 15 * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      if(!has_network_access()) {
        /* Wait until for a network to join */
      } else if(use_bootstrap && bootstrapped == 0) {
        if(update_bootstrap_server()) {
          /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
          coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
          coap_set_header_uri_path(request, "/bs");
          coap_set_header_uri_query(request, endpoint);

          printf("Registering ID with bootstrap server [");
          uip_debug_ipaddr_print(&bs_server_ipaddr);
          printf("]:%u as '%s'\n", uip_ntohs(bs_server_port), endpoint);

          COAP_BLOCKING_REQUEST(&bs_server_endpoint, request,
                                client_chunk_handler);
          bootstrapped++;
        }
      } else if(use_bootstrap && bootstrapped == 1) {
        lwm2m_context_t context;
        const lwm2m_instance_t *instance = NULL;
        const lwm2m_resource_t *rsc;
        const uint8_t *first;
        int len;

        PRINTF("*** Bootstrap - checking for server info...\n");

        /* get the security object */
        instance = lwm2m_engine_get_first_instance_of_object(LWM2M_OBJECT_SECURITY_ID, &context);
        if(instance != NULL) {
          /* get the server URI */
          context.resource_id = LWM2M_SECURITY_SERVER_URI;
          rsc = lwm2m_get_resource(instance, &context);
          first = lwm2m_object_get_resource_string(rsc, &context);
          len = lwm2m_object_get_resource_strlen(rsc, &context);
          if(first != NULL && len > 0) {
            int start, end;
            uip_ipaddr_t addr;
            int32_t port;
            uint8_t secure = 0;

            PRINTF("**** Found security instance using: %.*s\n", len, first);
            /* TODO Should verify it is a URI */

            /* Check if secure */
            secure = strncmp((const char *)first, "coaps:", 6) == 0;

            /* Only IPv6 supported */
            start = index_of(first, 0, len, '[');
            end = index_of(first, start, len, ']');
            if(start > 0 && end > start &&
               uiplib_ipaddrconv((const char *)&first[start], &addr)) {
              if(first[end + 1] == ':' &&
                 lwm2m_plain_text_read_int(first + end + 2, len - end - 2, &port)) {
              } else if(secure) {
                /**
                 * Secure CoAP should use a different port but for now
                 * the same port is used.
                 */
                port = COAP_DEFAULT_PORT;
              } else {
                port = COAP_DEFAULT_PORT;
              }
              PRINTF("Server address ");
              PRINT6ADDR(&addr);
              PRINTF(" port %" PRId32 "%s\n", port, secure ? " (secure)" : "");
              if(secure) {
                printf("Secure CoAP requested but not supported - can not bootstrap\n");
              } else {
                lwm2m_rd_client_register_with_server(&addr,
                                                  UIP_HTONS((uint16_t)port));
                bootstrapped++;
              }
            } else {
              printf("** failed to parse URI %.*s\n", len, first);
            }
          }
        }

        if(bootstrapped == 1) {
          /* Not ready. Lets retry with the bootstrap server again */
          bootstrapped = 0;
        }

      } else if(use_registration && !registered &&
                update_registration_server()) {
        int len;
        registered = 1;

        /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
        coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
        coap_set_header_uri_path(request, "/rd");
        coap_set_header_uri_query(request, endpoint);

        /* generate the rd data */
        len = lwm2m_engine_get_rd_data(rd_data, sizeof(rd_data));

        coap_set_payload(request, (uint8_t *)rd_data, len);

        printf("Registering with [");
        uip_debug_ipaddr_print(&server_ipaddr);
        printf("]:%u lwm2m endpoint '%s': '%.*s'\n", uip_ntohs(server_port),
               endpoint, len, rd_data);
        COAP_BLOCKING_REQUEST(&server_endpoint, request,
                              client_chunk_handler);
      }
      /* for now only register once...   registered = 0; */
      etimer_set(&et, 15 * CLOCK_SECOND);
    }
  }
  PROCESS_END();
}

void
lwm2m_rd_client_init(char *ep)
{
  endpoint = ep;
  process_start(&lwm2m_rd_client, NULL);
}
