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

typedef struct resource_s resource_t;
typedef struct periodic_resource_s periodic_resource_t;

#include "er-coap.h"
#include "coap-timer.h"
#include "lib/list.h"

/*
 * The maximum buffer size that is provided for resource responses and must be
 * respected due to the limited IP buffer.  Larger data must be handled by the
 * resource and will be sent chunk-wise through a TCP stream or CoAP blocks.
 */
#ifndef REST_MAX_CHUNK_SIZE
#define REST_MAX_CHUNK_SIZE     64
#endif

typedef enum {
  COAP_HANDLER_STATUS_CONTINUE,
  COAP_HANDLER_STATUS_PROCESSED
} coap_handler_status_t;

typedef coap_handler_status_t
(* coap_handler_callback_t)(coap_packet_t *request,
                            coap_packet_t *response,
                            uint8_t *buffer, uint16_t buffer_size,
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

coap_handler_status_t er_coap_call_handlers(coap_packet_t *request,
                                            coap_packet_t *response,
                                            uint8_t *buffer,
                                            uint16_t buffer_size,
                                            int32_t *offset);

/*---------------------------------------------------------------------------*/
/* signatures of handler functions */
typedef void (*restful_handler)(void *request, void *response,
                                uint8_t *buffer, uint16_t preferred_size,
                                int32_t *offset);
typedef void (*restful_final_handler)(resource_t *resource,
                                      void *request, void *response);
typedef void (*restful_periodic_handler)(void);
typedef void (*restful_response_handler)(void *data, void *response);
typedef void (*restful_trigger_handler)(void);

/* data structure representing a resource in REST */
struct resource_s {
  resource_t *next;               /* for LIST, points to next resource defined */
  const char *url;                /*handled URL */
  coap_resource_flags_t flags;    /* handled RESTful methods */
  const char *attributes;         /* link-format attributes */
  restful_handler get_handler;    /* handler function */
  restful_handler post_handler;   /* handler function */
  restful_handler put_handler;    /* handler function */
  restful_handler delete_handler; /* handler function */
  union {
    periodic_resource_t *periodic; /* special data depending on flags */
    restful_trigger_handler trigger;
    restful_trigger_handler resume;
  };
};

struct periodic_resource_s {
  uint32_t period;
  coap_timer_t periodic_timer;
  const restful_periodic_handler periodic_handler;
};

/*
 * Macro to define a RESTful resource.
 * Resources are statically defined for the sake of efficiency and better memory management.
 */
#define RESOURCE(name, attributes, get_handler, post_handler, put_handler, delete_handler) \
  resource_t name = { NULL, NULL, NO_FLAGS, attributes, get_handler, post_handler, put_handler, delete_handler, { NULL } }

#define PARENT_RESOURCE(name, attributes, get_handler, post_handler, put_handler, delete_handler) \
  resource_t name = { NULL, NULL, HAS_SUB_RESOURCES, attributes, get_handler, post_handler, put_handler, delete_handler, { NULL } }

#define SEPARATE_RESOURCE(name, attributes, get_handler, post_handler, put_handler, delete_handler, resume_handler) \
  resource_t name = { NULL, NULL, IS_SEPARATE, attributes, get_handler, post_handler, put_handler, delete_handler, { .resume = resume_handler } }

#define EVENT_RESOURCE(name, attributes, get_handler, post_handler, put_handler, delete_handler, event_handler) \
  resource_t name = { NULL, NULL, IS_OBSERVABLE, attributes, get_handler, post_handler, put_handler, delete_handler, { .trigger = event_handler } }

/*
 * Macro to define a periodic resource.
 * The corresponding [name]_periodic_handler() function will be called every period.
 * For instance polling a sensor and publishing a changed value to subscribed clients would be done there.
 * The subscriber list will be maintained by the final_handler rest_subscription_handler() (see rest-mapping header file).
 */
#define PERIODIC_RESOURCE(name, attributes, get_handler, post_handler, put_handler, delete_handler, period, periodic_handler) \
  static periodic_resource_t periodic_##name = { period, { 0 }, periodic_handler }; \
  resource_t name = { NULL, NULL, IS_OBSERVABLE | IS_PERIODIC, attributes, get_handler, post_handler, put_handler, delete_handler, { .periodic = &periodic_##name } }

/*---------------------------------------------------------------------------*/
/**
 *
 * \brief      Resources wanted to be accessible should be activated with the following code.
 * \param resource
 *             A RESTful resource defined through the RESOURCE macros.
 * \param path
 *             The local URI path where to provide the resource.
 */
void rest_activate_resource(resource_t *resource, const char *path);
/*---------------------------------------------------------------------------*/
/**
 * \brief      Returns the list of registered RESTful resources.
 * \return     The resource list.
 */
list_t rest_get_resources(void);
/*---------------------------------------------------------------------------*/

#include "er-coap-transactions.h"
#include "er-coap-observe.h"
#include "er-coap-separate.h"
#include "er-coap-observe-client.h"
#include "er-coap-transport.h"

#endif /* ER_COAP_ENGINE_H_ */
