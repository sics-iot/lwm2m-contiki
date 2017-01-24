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
 *
 */

/**
 * \file
 *         Implementation of the Contiki OMA LWM2M server
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

#include <stdint.h>
#include "lwm2m-object.h"
#include "lwm2m-engine.h"
#include "lwm2m-server.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

#ifdef LWM2M_CONF_SERVER_MAX_COUNT
#define MAX_COUNT LWM2M_CONF_SERVER_MAX_COUNT
#else
#define MAX_COUNT 2
#endif

static int lwm2m_callback(lwm2m_object_instance_t *object,
                          lwm2m_context_t *ctx);

static const uint16_t resources[] = {LWM2M_SERVER_SHORT_SERVER_ID,
                                     LWM2M_SERVER_LIFETIME_ID};

lwm2m_object_instance_t server_object;

static server_value_t server_instances[MAX_COUNT];

static int
lwm2m_server_create(int instance_id)
{
  int i;
  for(i = 0; i < MAX_COUNT; i++) {
    /* Not used if callback is non-existend */
    if(server_instances[i].reg_object.callback == NULL) {
      server_instances[i].reg_object.callback = lwm2m_callback;
      server_instances[i].reg_object.object_id = LWM2M_OBJECT_SERVER_ID;
      server_instances[i].reg_object.instance_id = instance_id;
      server_instances[i].reg_object.resource_ids = resources;
      server_instances[i].reg_object.resource_count = sizeof(resources) / sizeof(uint16_t);
      lwm2m_engine_add_object((lwm2m_object_instance_t *) &server_instances[i]);
      return 1;
    }
  }
  return 0;
}

static int
lwm2m_callback(lwm2m_object_instance_t *object,
               lwm2m_context_t *ctx)
{
  /* NOTE: the create operation will only create an instance and should
     avoid reading out data */
  int32_t value;
  server_value_t *server;
  server = (server_value_t *) object;

  if(ctx->operation == LWM2M_OP_CREATE) {
    PRINTF("Creating new instance: %d\n", ctx->object_instance_id);
    if(lwm2m_server_create(ctx->object_instance_id)) {
      return ctx->object_instance_id;
    }
    return 0;
  } else if(ctx->operation == LWM2M_OP_WRITE) {
    PRINTF("Write to: %d\n", ctx->resource_id);
    switch(ctx->resource_id) {
    case LWM2M_SERVER_LIFETIME_ID:
      lwm2m_object_read_int(ctx, ctx->inbuf, ctx->insize, &value);
      PRINTF("Got lifetime: %d\n", (int) value);
      server->lifetime = value;
    }
  } else if(ctx->operation == LWM2M_OP_READ) {
    switch(ctx->resource_id) {
    case LWM2M_SERVER_LIFETIME_ID:
      lwm2m_object_write_int(ctx, server->lifetime);
      break;
    }
  }

  return 1;
}

/*---------------------------------------------------------------------------*/
void
lwm2m_server_init(void)
{
  PRINTF("*** Init lwm2m-server\n");

  server_object.object_id = LWM2M_OBJECT_SERVER_ID;
  server_object.instance_id = 0xffff; /* Generic instance */
  server_object.resource_ids = resources;
  server_object.resource_count = sizeof(resources) / sizeof(uint16_t);
  server_object.callback = lwm2m_callback;

  lwm2m_engine_add_object(&server_object);
}
/*---------------------------------------------------------------------------*/
/** @} */
