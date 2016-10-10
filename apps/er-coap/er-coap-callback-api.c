/*
 * Copyright (c) 2016, SICS Swedish ICT
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
 *
 *
 */

/**
 * \file
 *      Callback API for doing CoAP requests
 *      Adapted from the blocking API
 * \author
 *      Joakim Eriksson, joakime@sics.se
 */


#include "sys/cc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "er-coap-engine.h"
#include "er-coap-callback-api.h"
#include "er-coap-transactions.h"

#define DEBUG 1
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

/* These should go into the state struct so that we can have multiple
   requests */

static uint8_t more;
static uint32_t res_block;
static uint8_t block_error;


static void coap_request_callback(void *callback_data, void *response);

/*---------------------------------------------------------------------------*/

static void
progress_request(struct request_state *state) {
  coap_packet_t *request = state->request;
  request->mid = coap_get_mid();
  if((state->transaction =
      coap_new_transaction(request->mid, state->remote_endpoint))) {
    state->transaction->callback = coap_request_callback;
    state->transaction->callback_data = state;

    if(state->block_num > 0) {
      coap_set_header_block2(request, state->block_num, 0,
                             REST_MAX_CHUNK_SIZE);
    }
    state->transaction->packet_len =
      coap_serialize_message(request, state->transaction->packet);

    coap_send_transaction(state->transaction);
    PRINTF("Requested #%lu (MID %u)\n", (unsigned long) state->block_num,
           request->mid);
  }
}

/*---------------------------------------------------------------------------*/

static void
coap_request_callback(void *callback_data, void *response)
{
  struct request_state *state = (struct request_state *)callback_data;
  state->response = (coap_packet_t *)response;

  PRINTF("COAP: request callback\n");

  if(!state->response) {
    PRINTF("Server not responding giving up...\n");
    state->callback(state);
    return;
  }

  /* Got a response */
  coap_get_header_block2(state->response, &res_block, &more, NULL, NULL);
  PRINTF("Received #%lu%s (%u bytes)\n",
         (unsigned long) res_block, (unsigned) more ? "+" : "",
         state->response->payload_len);

  if(res_block == state->block_num) {
    /* Call the callback function as we have more data */
    state->callback(state);
    ++(state->block_num);
  } else {
    PRINTF("WRONG BLOCK %lu/%lu\n", (unsigned long) res_block,
           (unsigned long) state->block_num);
    ++block_error;
  }

  if(more && block_error < COAP_MAX_ATTEMPTS) {
    progress_request(state);
  } else {
    /* failure - now we give up and notify the callback */
    state->response = NULL;
    state->callback(state);
  }
}

/*---------------------------------------------------------------------------*/

void
coap_send_request(struct request_state *state, coap_endpoint_t *endpoint,
                  coap_packet_t *request,
                  void (*callback)(struct request_state *state))
{
  /* can we have these variables shared between multiple requests? */
  /* ripped from blocking request */
  more = 0;
  res_block = 0;
  block_error = 0;

  state->block_num = 0;
  state->response = NULL;
  state->request = request;
  state->remote_endpoint = endpoint;
  state->callback = callback;

  progress_request(state);
}
