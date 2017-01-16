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
 *         A native IPv4 transport for CoAP
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "er-coap.h"
#include "er-coap-endpoint.h"
#include "er-coap-engine.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define DEBUG 1
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTEP(ep) coap_endpoint_print(ep)
#else
#define PRINTF(...)
#define PRINTEP(ep)
#endif

#define BUFSIZE 1280

typedef union {
  uint32_t u32[(BUFSIZE + 3) / 4];
  uint8_t u8[BUFSIZE];
} coap_buf_t;

static int coap_ipv4_fd = -1;

static coap_endpoint_t last_source;
static coap_buf_t coap_aligned_buf;
static uint16_t coap_buf_len;
/*---------------------------------------------------------------------------*/
static const coap_endpoint_t *
coap_src_endpoint(void)
{
  return &last_source;
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_copy(coap_endpoint_t *destination, const coap_endpoint_t *from)
{
  memcpy(destination, from, sizeof(coap_endpoint_t));
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_cmp(const coap_endpoint_t *e1, const coap_endpoint_t *e2)
{
  return memcmp(e1, e2, sizeof(coap_endpoint_t)) == 0;
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_print(const coap_endpoint_t *ep)
{
  const char *address;
  address = inet_ntoa(ep->addr.sin_addr);
  if(address != NULL) {
    printf("%s:%u", address, ntohs(ep->addr.sin_port));
  } else {
    printf("<#N/A>");
  }
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_parse(const char *text, size_t size, coap_endpoint_t *ep)
{
  /* text = format coap://host:port/... we assume */
  /* will not work for know - on the TODO */
  /* set server and port */
  char host[32];
  int hlen = 0;

  int secure;
  int offset = 0;
  int i;
  printf("Parsing: %.*s\n", (int)size, text);
  if(strncmp("coap://", text, 7) == 0) {
    secure = 0;
    offset = 7;
    PRINTF("COAP found\n");
  } else if(strncmp("coaps://", text, 8) == 0) {
    secure = 1;
    offset = 8;
    PRINTF("COAPS found\n");
  }

  for(int i = offset; i < size && text[i] != ':' && text[i] != '/';
      i++) {
    host[hlen++] = text[i];
  }
  host[hlen] = 0;

  PRINTF("HOST:%s\n", host);

  ep->addr.sin_family = AF_INET;
  ep->addr.sin_port = htons(COAP_DEFAULT_PORT);
  ep->addr_len = sizeof(ep->addr);
  if(inet_aton(host, &ep->addr.sin_addr) == 0) {
    /* Failed to parse the address */
    return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
uint8_t *
coap_databuf(void)
{
  return coap_aligned_buf.u8;
}
/*---------------------------------------------------------------------------*/
uint16_t
coap_datalen()
{
  return coap_buf_len;
}
/*---------------------------------------------------------------------------*/
static int
coap_ipv4_set_fd(fd_set *rset, fd_set *wset)
{
  if(coap_ipv4_fd >= 0) {
    FD_SET(coap_ipv4_fd, rset);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
coap_ipv4_handle_fd(fd_set *rset, fd_set *wset)
{
  int len;

  if(coap_ipv4_fd < 0) {
    return;
  }
  if(!FD_ISSET(coap_ipv4_fd, rset)) {
    return;
  }

  last_source.addr_len = sizeof(last_source.addr);
  len = recvfrom(coap_ipv4_fd, coap_databuf(), BUFSIZE, 0,
                 (struct sockaddr *)&last_source.addr, &last_source.addr_len);
  if(len == -1) {
    if(errno == EAGAIN) {
      return;
    }
    err(1, "coap-ipv4: recv");
    return;
  }
  PRINTF("RECV from ");
  PRINTEP(&last_source);
  PRINTF(" %u bytes\n", len);
  coap_buf_len = len;

  if(DEBUG) {
    int i;
    uint8_t *data;
    data = coap_databuf();
    PRINTF("Received:");
    for(i = 0; i < len; i++) {
      PRINTF("%02x", data[i]);
    }
    PRINTF("\n");
  }

  coap_receive(coap_src_endpoint(), coap_databuf(), coap_datalen());
}
/*---------------------------------------------------------------------------*/
static const struct select_callback udp_callback = {
  coap_ipv4_set_fd, coap_ipv4_handle_fd
};
/*---------------------------------------------------------------------------*/
void
coap_transport_init(void)
{
  static struct sockaddr_in server;

  coap_ipv4_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(coap_ipv4_fd == -1) {
    fprintf(stderr, "Could not create CoAP UDP socket\n");
    exit(1);
    return;
  }

  memset((void *)&server, 0, sizeof(server));

#undef  COAP_SERVER_PORT
#define COAP_SERVER_PORT 4711

  server.sin_family = AF_INET;
  server.sin_port = htons(COAP_SERVER_PORT);
  server.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(coap_ipv4_fd, (struct sockaddr *)&server, sizeof(server)) == -1) {
    PRINTF("Could not bind CoAP UDP port to %u\n", COAP_SERVER_PORT);
    exit(1);
  }

  printf("CoAP server listening on port %u\n", COAP_SERVER_PORT);
  select_set_callback(coap_ipv4_fd, &udp_callback);
}
/*---------------------------------------------------------------------------*/
void
coap_send_message(const coap_endpoint_t *ep, const uint8_t *data, uint16_t len)
{
  if(coap_ipv4_fd >= 0) {
    if(sendto(coap_ipv4_fd, data, len, 0,
              (struct sockaddr *)&ep->addr, ep->addr_len) < 1) {
      PRINTF("failed to send to ");
      PRINTEP(ep);
      PRINTF(" %u bytes: %s\n", len, strerror(errno));
    } else {
      PRINTF("SENT to ");
      PRINTEP(ep);
      PRINTF(" %u bytes\n", len);

      if(DEBUG) {
        int i;
        PRINTF("Sent:");
        for(i = 0; i < len; i++) {
          PRINTF("%02x", data[i]);
        }
        PRINTF("\n");
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
