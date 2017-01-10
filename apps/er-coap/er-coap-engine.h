/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      CoAP implementation for the REST Engine.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#ifndef ER_COAP_ENGINE_H_
#define ER_COAP_ENGINE_H_

#include "er-coap.h"
#include "er-coap-transactions.h"
#include "er-coap-observe.h"
#include "er-coap-separate.h"
#include "er-coap-observe-client.h"
#include "er-coap-transport.h"

typedef int (*coap_handler_callback_t)(coap_packet_t *request,
                                       coap_packet_t *response,
                                       uint8_t *buffer,
                                       uint16_t buffer_size,
                                       int32_t *offset);

typedef struct coap_handler coap_handler_t;

struct coap_handler {
  coap_handler_t *next;
  coap_handler_callback_t handler;
};

#define COAP_HANDLER(name, handler) \
  coap_handler_t name = { NULL, handler }

void coap_add_handler(coap_handler_t *handler);
void coap_remove_handler(coap_handler_t *handler);

void coap_init_engine(void);

int coap_receive(const coap_endpoint_t *src,
                 uint8_t *payload, uint16_t payload_length);

int er_coap_call_handlers(coap_packet_t *request, coap_packet_t *response,
                          uint8_t *buffer, uint16_t buffer_size,
                          int32_t *offset);

/*---------------------------------------------------------------------------*/

#endif /* ER_COAP_ENGINE_H_ */
