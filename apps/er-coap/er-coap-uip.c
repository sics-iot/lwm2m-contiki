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
 *         CoAP transport implementation for uIPv6
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "contiki.h"
#include "sys/cc.h"
#include "net/ip/uip-udp-packet.h"
#include "net/ip/uiplib.h"
#include "er-coap.h"
#include "er-coap-engine.h"
#include "er-coap-endpoint.h"
#include "er-coap-transport.h"
#include "er-coap-transactions.h"

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

/* sanity check for configured values */
#if COAP_MAX_PACKET_SIZE > (UIP_BUFSIZE - UIP_IPH_LEN - UIP_UDPH_LEN)
#error "UIP_CONF_BUFFER_SIZE too small for REST_MAX_CHUNK_SIZE"
#endif

#define SERVER_LISTEN_PORT      UIP_HTONS(COAP_SERVER_PORT)

/* direct access into the buffer */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#if NETSTACK_CONF_WITH_IPV6
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#else
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN])
#endif

PROCESS(coap_engine, "CoAP Engine");

static struct uip_udp_conn *udp_conn = NULL;
/*---------------------------------------------------------------------------*/
void
coap_endpoint_print(const coap_endpoint_t *ep)
{
  printf("[");
  uip_debug_ipaddr_print(&ep->ipaddr);
  printf("]:%u", uip_ntohs(ep->port));
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_copy(coap_endpoint_t *destination,
                   const coap_endpoint_t *from)
{
  uip_ipaddr_copy(&destination->ipaddr, &from->ipaddr);
  destination->port = from->port;
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_cmp(const coap_endpoint_t *e1, const coap_endpoint_t *e2)
{
  if(!uip_ipaddr_cmp(&e1->ipaddr, &e2->ipaddr)) {
    return 0;
  }
  return e1->port == e2->port;
}
/*---------------------------------------------------------------------------*/
static int
index_of(const char *data, int offset, int len, uint8_t c)
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
int get_port(const char *inbuf, size_t len, uint32_t *value)
{
  int i;
  *value = 0;
  for(i = 0; i < len; i++) {
    if(inbuf[i] >= '0' && inbuf[i] <= '9') {
      *value = *value * 10 + (inbuf[i] - '0');
    } else {
      break;
    }
  }
  return i;
}

int
coap_endpoint_parse(const char *text, size_t size, coap_endpoint_t *ep)
{
  /* Only IPv6 supported */
  int start = index_of(text, 0, size, '[');
  int end = index_of(text, start, size, ']');
  int secure = strncmp((const char *)text, "coaps:", 6) == 0;
  uint32_t port;
  if(start > 0 && end > start &&
     uiplib_ipaddrconv((const char *)&text[start], &ep->ipaddr)) {
    if(text[end + 1] == ':' &&
       get_port(text + end + 2, size - end - 2, &port)) {
      ep->port = UIP_HTONS(port);
    } else if(secure) {
      /**
       * Secure CoAP should use a different port but for now
       * the same port is used.
       */
      ep->port = SERVER_LISTEN_PORT;
    } else {
      ep->port = SERVER_LISTEN_PORT;
    }
    return 1;
  } else {
    if(uiplib_ipaddrconv((const char *)&text, &ep->ipaddr)) {
      ep->port = SERVER_LISTEN_PORT;
      return 1;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static const coap_endpoint_t *
get_src_endpoint(void)
{
  static coap_endpoint_t src;
  uip_ipaddr_copy(&src.ipaddr, &UIP_IP_BUF->srcipaddr);
  src.port = UIP_UDP_BUF->srcport;
  return &src;
}
/*---------------------------------------------------------------------------*/
uint8_t *
coap_databuf(void)
{
  return uip_appdata;
}
/*---------------------------------------------------------------------------*/
uint16_t
coap_datalen()
{
  return uip_datalen();
}
/*---------------------------------------------------------------------------*/
void
coap_transport_init(void)
{
  process_start(&coap_engine, NULL);
}
/*---------------------------------------------------------------------------*/
static void
process_data(void)
{
  PRINTF("receiving UDP datagram from: ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(":%u\n  Length: %u\n", uip_ntohs(UIP_UDP_BUF->srcport),
         uip_datalen());

  coap_receive(get_src_endpoint(), uip_appdata, uip_datalen());
}
/*---------------------------------------------------------------------------*/
void
coap_send_message(const coap_endpoint_t *ep, const uint8_t *data,
                  uint16_t length)
{
  if(ep == NULL) {
    PRINTF("failed to send - no endpoint\n");
  } else {
    uip_udp_packet_sendto(udp_conn, data, length, &ep->ipaddr, ep->port);

    PRINTF("-sent UDP datagram (%u)-\n", length);
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_engine, ev, data)
{
  PROCESS_BEGIN();

  /* new connection with remote host */
  udp_conn = udp_new(NULL, 0, NULL);
  udp_bind(udp_conn, SERVER_LISTEN_PORT);
  PRINTF("Listening on port %u\n", uip_ntohs(udp_conn->lport));

  while(1) {
    PROCESS_YIELD();

    if(ev == tcpip_event) {
      if(uip_newdata()) {
        process_data();
      }
    }
  } /* while (1) */

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
