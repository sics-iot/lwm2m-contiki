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
 *         A HEX text transport for CoAP
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "er-coap.h"
#include "er-coap-endpoint.h"
#include "er-coap-engine.h"
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

static coap_endpoint_t last_source;
static coap_buf_t coap_aligned_buf;
static uint16_t coap_buf_len;
/*---------------------------------------------------------------------------*/
const coap_endpoint_t *
coap_src_endpoint(void)
{
  return &last_source;
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_copy(coap_endpoint_t *destination, const coap_endpoint_t *from)
{
  *destination = *from;
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_cmp(const coap_endpoint_t *e1, const coap_endpoint_t *e2)
{
  return *e1 == *e2;
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_print(const coap_endpoint_t *ep)
{
  printf("%u", *ep);
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_parse(const char *text, size_t size, coap_endpoint_t *ep)
{
  /* Hex based CoAP has no addresses, just writes data to standard out */
  *ep = last_source = 0;
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
hextod(char c)
{
  if(c >= '0' && c <= '9') {
    return c - '0';
  }
  if(c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if(c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
static void
stdin_callback(const char *line)
{
  uint8_t *buf;
  int i, len, llen, v1, v2;

  if(strncmp("COAPHEX:", line, 8) != 0) {
    /* Not a CoAP message */
    return;
  }

  line += 8;
  llen = strlen(line);
  if((llen & 1) != 0) {
    /* Odd number of characters - not hex */
    fprintf(stderr, "ERROR: %s\n", line);
    return;
  }

  buf = coap_databuf();
  for(i = 0, len = 0; i < llen; i += 2, len++) {
    v1 = hextod(line[i]);
    v2 = hextod(line[i + 1]);
    if(v1 < 0 || v2 < 0) {
      /* Not hex */
      fprintf(stderr, "ERROR: %s\n", line);
      return;
    }
    buf[len] = (uint8_t)(((v1 << 4) | v2) & 0xff);
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
void
coap_transport_init(void)
{
  select_set_stdin_callback(stdin_callback);

  printf("CoAP listening on standard in\n");
}
/*---------------------------------------------------------------------------*/
void
coap_send_message(const coap_endpoint_t *ep, const uint8_t *data, uint16_t len)
{
  int i;
  printf("COAPHEX:");
  for(i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}
/*---------------------------------------------------------------------------*/
