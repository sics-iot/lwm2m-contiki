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

#include "lwm2m-engine.h"
#include "lwm2m-object.h"
#include "lwm2m-device.h"
#include "lwm2m-plain-text.h"
#include "lwm2m-json.h"
#include "er-coap.h"
#include "er-coap-engine.h"
#include "er-coap-endpoint.h"
#include "er-coap-callback-api.h"
#include "oma-tlv.h"
#include "oma-tlv-reader.h"
#include "oma-tlv-writer.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif /* UIP_CONF_IPV6_RPL */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

#define REMOTE_PORT        UIP_HTONS(COAP_DEFAULT_PORT)
#define BS_REMOTE_PORT     UIP_HTONS(5685)

static coap_endpoint_t bs_server_endpoint;
static coap_endpoint_t server_endpoint;

static uint8_t use_bootstrap = 0;
static uint8_t has_bootstrap_server_info = 0;
static uint8_t use_registration = 0;
static uint8_t has_registration_server_info = 0;
static uint8_t registered = 0;
static uint8_t bootstrapped = 0; /* bootstrap made... */

static struct request_state rd_request_state;

/* The states for the RD client state machine */
#define INIT               0
#define WAIT_NETWORK       1
#define DO_BOOTSTRAP       3
#define BOOTSTRAP_SENT     4
#define BOOTSTRAP_DONE     5
#define DO_REGISTRATION    6
#define REGISTRATION_SENT  7
#define REGISTRATION_DONE  8


static uint8_t rd_state = 0;
static uint64_t wait_until_network_check = 0;

static char *endpoint;
static uint8_t rd_data[128]; /* allocate some data for the RD */

static ntimer_t rd_timer;

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
void
lwm2m_rd_client_use_bootstrap_server(int use)
{
  use_bootstrap = use != 0;
  if(use_bootstrap) {
    rd_state = INIT;
  }
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_use_registration_server(int use)
{
  use_registration = use != 0;
  if(use_registration) {
    rd_state = INIT;
  }
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_register_with_server(coap_endpoint_t *server)
{
  coap_endpoint_copy(&server_endpoint, server);
  has_registration_server_info = 1;
  registered = 0;
  if(use_registration) {
    rd_state = INIT;
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
      /* create coap-endpoint? */
      /* uip_ipaddr_copy(&server_ipaddr, &dag->dag_id); */
      /* server_port = REMOTE_PORT; */
      return 1;
    }
  }
#endif /* UIP_CONF_IPV6_RPL */

  return 0;
}
/*---------------------------------------------------------------------------*/
void
lwm2m_rd_client_register_with_bootstrap_server(const coap_endpoint_t  *server)
{
  coap_endpoint_copy(&bs_server_endpoint, server);
  has_bootstrap_server_info = 1;
  bootstrapped = 0;
  registered = 0;
  if(use_bootstrap) {
    rd_state = INIT;
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
      /* create coap endpoint */
      /* uip_ipaddr_copy(&bs_server_ipaddr, &dag->dag_id); */
      /* bs_server_port = REMOTE_PORT; */
      return 1;
    }
  }
#endif /* UIP_CONF_IPV6_RPL */

  return 0;
}
/*---------------------------------------------------------------------------*/
static void
bootstrap_callback(struct request_state *state)
{
  PRINTF("Bootstrap callback!\n");
  rd_state = BOOTSTRAP_DONE;
}
/*---------------------------------------------------------------------------*/
static void
registration_callback(struct request_state *state)
{
  PRINTF("Registration callback! Success: %d\n", state->response != NULL);
  /* check state and possibly set registration to done */
  rd_state = REGISTRATION_DONE;
}
/*---------------------------------------------------------------------------*/
/* ntimer callback */
static void
periodic_process(ntimer_t *timer)
{
  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */
  uint64_t now;

  /* reschedule the eimter */
  ntimer_reset(&rd_timer, 500);
  now = ntimer_uptime();

  PRINTF("RD Client - state: %d\n", rd_state);

  switch(rd_state) {
  case INIT:
    PRINTF("RD Client started with endpoint '%s'\n", endpoint);
    rd_state = WAIT_NETWORK;
    break;
  case WAIT_NETWORK:
    if(now > wait_until_network_check) {
      /* check each 10 seconds before next check */
      PRINTF("Checking for network... %lu\n",
             (unsigned long)wait_until_network_check);
      wait_until_network_check = now + 10000;
      if(has_network_access()) {
        /* Either do bootstrap then registration */
        if(use_bootstrap) {
          rd_state = DO_BOOTSTRAP;
        } else {
          rd_state = DO_REGISTRATION;
        }
      }
      /* Otherwise wait until for a network to join */
    }
    break;
  case DO_BOOTSTRAP:
    if(use_bootstrap && bootstrapped == 0) {
      if(update_bootstrap_server()) {
        /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
        coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
        coap_set_header_uri_path(request, "/bs");
        coap_set_header_uri_query(request, endpoint);

        PRINTF("Registering ID with bootstrap server [");
        coap_endpoint_print(&bs_server_endpoint);
        PRINTF("] as '%s'\n", endpoint);

        coap_send_request(&rd_request_state, &bs_server_endpoint, request,
                          bootstrap_callback);

        rd_state = BOOTSTRAP_SENT;
      }
    }
    break;
  case BOOTSTRAP_SENT:
    /* Just wait for bootstrap to be done...  */
    break;
  case BOOTSTRAP_DONE:
    /* check that we should still use bootstrap */
    if(use_bootstrap) {
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
          uint8_t secure = 0;

          PRINTF("**** Found security instance using: %.*s\n", len, first);
          /* TODO Should verify it is a URI */
          /* Check if secure */
          secure = strncmp((const char *)first, "coaps:", 6) == 0;

          coap_endpoint_parse((const char *) first, len, &server_endpoint);
          PRINTF("Server address:");
          coap_endpoint_print(&server_endpoint);
          PRINTF("\n");
          if(secure) {
            PRINTF("Secure CoAP requested but not supported - can not bootstrap\n");
          } else {
            lwm2m_rd_client_register_with_server(&server_endpoint);
            bootstrapped++;
          }
        } else {
          PRINTF("** failed to parse URI %.*s\n", len, first);
        }
      }

      /* if we did not register above - then fail this and restart... */
      if(bootstrapped == 1) {
        /* Not ready. Lets retry with the bootstrap server again */
        rd_state = DO_BOOTSTRAP;
      }
    }
    break;
  case DO_REGISTRATION:
    if(use_registration && !registered &&
       update_registration_server()) {
      int len;

      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
      coap_set_header_uri_path(request, "/rd");
      coap_set_header_uri_query(request, endpoint);

      /* generate the rd data */
      len = lwm2m_engine_get_rd_data(rd_data, sizeof(rd_data));

      coap_set_payload(request, rd_data, len);

      PRINTF("Registering with [");
      coap_endpoint_print(&server_endpoint);
      PRINTF("] lwm2m endpoint '%s': '%.*s'\n",
             endpoint, len, (char *) rd_data);
      /* COAP_BLOCKING_REQUEST(&server_endpoint, request, */
      /*                       client_chunk_handler); */
      coap_send_request(&rd_request_state, &server_endpoint, request,
                        registration_callback);
      rd_state = REGISTRATION_SENT;
    }
  case REGISTRATION_SENT:
    /* just wait until the callback kicks us to the next state... */
    break;
  case REGISTRATION_DONE:
    /* All is done! */
    PRINTF("registration done\n");
    break;
  default:
    PRINTF("Unhandled state: %d\n", rd_state);
  }
}

void
lwm2m_rd_client_init(char *ep)
{
  endpoint = ep;
  rd_state = INIT;
  /* Example using network timer */
  ntimer_set_callback(&rd_timer, periodic_process);
  ntimer_set(&rd_timer, 500); /* call the RD client 2 times per second */
}
