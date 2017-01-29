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
 *         Implementation of the Contiki OMA LWM2M security
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

#include <stdint.h>
#include "lwm2m-object.h"
#include "lwm2m-engine.h"
#include "lwm2m-security.h"

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

lwm2m_object_instance_t security_object;

static lwm2m_security_value_t security_instances[MAX_COUNT];
static int lwm2m_callback(lwm2m_object_instance_t *object,
                          lwm2m_context_t *ctx);
static const uint16_t resources[] = {
  LWM2M_SECURITY_SERVER_URI_ID, LWM2M_SECURITY_BOOTSTRAP_SERVER_ID,
  LWM2M_SECURITY_MODE_ID, LWM2M_SECURITY_CLIENT_PKI_ID,
  LWM2M_SECURITY_SERVER_PKI_ID, LWM2M_SECURITY_KEY_ID,
  LWM2M_SECURITY_SHORT_SERVER_ID
};

/*---------------------------------------------------------------------------*/
int
lwm2m_security_instance_count(void)
{
  return MAX_COUNT;
}

lwm2m_security_value_t *lwm2m_security_get_instance(int index) {
  if(index < MAX_COUNT &&
     security_instances[index].reg_object.callback != NULL) {
    return &security_instances[index];
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
static int
lwm2m_security_create(int instance_id)
{
  int i;
  for(i = 0; i < MAX_COUNT; i++) {
    /* Not used if callback is non-existend */
    if(security_instances[i].reg_object.callback == NULL) {
      security_instances[i].reg_object.callback = lwm2m_callback;
      security_instances[i].reg_object.object_id = LWM2M_OBJECT_SECURITY_ID;
      security_instances[i].reg_object.instance_id = instance_id;
      security_instances[i].reg_object.resource_ids = resources;
      security_instances[i].reg_object.resource_count = sizeof(resources) / sizeof(uint16_t);
      lwm2m_engine_add_object((lwm2m_object_instance_t *) &security_instances[i]);
      PRINTF("SEC: Create new security instance\n");
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
  int iv;
  lwm2m_security_value_t *security;
  security = (lwm2m_security_value_t *) object;

  if(ctx->operation == LWM2M_OP_CREATE) {
    PRINTF("SEC: Creating new instance: %d\n", ctx->object_instance_id);
    if(lwm2m_security_create(ctx->object_instance_id)) {
      return ctx->object_instance_id;
    }
    return 0;
  } else if(ctx->operation == LWM2M_OP_WRITE) {
    /* Handle the writes */
    switch(ctx->resource_id) {
    case LWM2M_SECURITY_SERVER_URI_ID:
      PRINTF("Writing security URI value: len: %d\n", (int)ctx->insize);
      value = lwm2m_object_read_string(ctx, ctx->inbuf, ctx->insize, security->server_uri, URI_SIZE);
      /* This is string... */
      security->server_uri_len = ctx->last_value_len;
      break;
    case LWM2M_SECURITY_BOOTSTRAP_SERVER_ID:
      value = lwm2m_object_read_boolean(ctx, ctx->inbuf, ctx->insize, &iv);
      PRINTF("Set Bootstrap: %d\n", iv);
      if(value > 0) {
        security->bootstrap = (uint8_t) iv;
      }
    case LWM2M_SECURITY_MODE_ID:
      {
        int32_t v2;
        PRINTF("Writing security MODE value: len: %d\n", (int)ctx->insize);
        value = lwm2m_object_read_int(ctx, ctx->inbuf, ctx->insize, &v2);
        security->security_mode = v2;
      }
      break;
    case LWM2M_SECURITY_CLIENT_PKI_ID:
      PRINTF("Writing client PKI: len: %d\n", (int)ctx->insize);
      value = lwm2m_object_read_string(ctx, ctx->inbuf, ctx->insize, security->public_key, KEY_SIZE);
      security->public_key_len = ctx->last_value_len;
      break;
    case LWM2M_SECURITY_KEY_ID:
      PRINTF("Writing client secret key: len: %d\n", (int)ctx->insize);
      value = lwm2m_object_read_string(ctx, ctx->inbuf, ctx->insize, security->secret_key, URI_SIZE);
      security->secret_key_len = ctx->last_value_len;
      break;
    }
  } else if(ctx->operation == LWM2M_OP_READ) {
    switch(ctx->resource_id) {
    case LWM2M_SECURITY_SERVER_URI_ID:
      lwm2m_object_write_string(ctx, (const char *) security->server_uri,
                                security->server_uri_len);
      break;
    default:
      return 0;
    }
  }
  return 1;
}

/*---------------------------------------------------------------------------*/
void
lwm2m_security_init(void)
{
  /* Register the generic object */
  security_object.object_id = LWM2M_OBJECT_SECURITY_ID;
  security_object.instance_id = 0xffff; /* Generic instance */
  security_object.resource_ids = resources;
  security_object.resource_count = sizeof(resources) / sizeof(uint16_t);
  security_object.callback = lwm2m_callback;

  PRINTF("*** Init lwm2m-security\n");
  lwm2m_engine_add_object(&security_object);
}
/*---------------------------------------------------------------------------*/
/** @} */
