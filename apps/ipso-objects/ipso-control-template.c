/*
 * Copyright (c) 2016, SICS Swedish ICT AB
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
 * \addtogroup ipso-objects
 * @{
 *
 */

/**
 * \file
 *         Implementation of OMA LWM2M / IPSO sensor template.
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */
#include "ipso-control-template.h"
#include "lwm2m-engine.h"
#include "sys/ntimer.h"
#include <string.h>
#include <stdio.h>

#define IPSO_ONOFF        5850
#define IPSO_DIMMER       5851
#define IPSO_ON_TIME      5852

/*---------------------------------------------------------------------------*/
static int
lwm2m_callback(lwm2m_object_instance_t *object,
               lwm2m_context_t *ctx)
{
  /* Here we cast to our sensor-template struct */
  ipso_control_t *control;
  const uint8_t *inbuf;
  int inlen;
  int32_t v;
  int rs;

  control = (ipso_control_t *) object;

  /* setup input buffer - TODO: should be handled in lwm2m-engine */
  inlen = REST.get_request_payload(ctx->request, &inbuf);

  /* Do the stuff */
  if(ctx->level == 1) {
    /* Should not happen 3303 */
    return 0;
  }
  if(ctx->level == 2) {
    /* This is a get whole object - or write whole object 3303/0 */
    /* No support right now... need to add support for this later */
    return 0;
  }
  if(ctx->level == 3) {
    /* This is a get request on 3303/0/3700 */
    /* NOW we assume a get.... which might be wrong... */
    if(ctx->operation == LWM2M_OP_READ) {
      switch(ctx->resource_id) {
      case IPSO_ONOFF:
        lwm2m_object_write_int(ctx, control->value > 0);
        break;
      case IPSO_DIMMER:
        lwm2m_object_write_int(ctx, control->value);
        break;
      case IPSO_ON_TIME:
        lwm2m_object_write_int(ctx, control->on_time + (ntimer_uptime() - control->last_on_time) / 1000);
        break;
      default:
        return 0;
      }
    } else if(ctx->operation == LWM2M_OP_WRITE) {
      switch(ctx->resource_id) {
      case IPSO_ONOFF:
      case IPSO_DIMMER:
        rs = ctx->reader->read_int(ctx, inbuf, inlen, &v);
        if(rs == 0) {
          return 0;
        }
        if(v > 100) {
          v = 100;
        }
        if(v < 0) {
          v = 0;
        }
        if(v != control->value) {
          if(v == 0 && control->value > 0) {
            control->on_time += (ntimer_uptime() - control->last_on_time) / 1000;
          }
          if(v > 0 && control->value == 0) {
            control->last_on_time = ntimer_uptime();
          }
          /* Call the callback and if ok update the value */
          if(control->set_value(v) == LWM2M_STATUS_OK) {
            control->value = v;
          }
        }
        break;
      case IPSO_ON_TIME:
        rs = ctx->reader->read_int(ctx, inbuf, inlen, &v);
        if(rs == 0) {
          return 0;
        }
        if(v == 0) {
          control->on_time = 0;
        }
        break;
      default:
        return 0;
      }
    }
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
int
ipso_control_add(ipso_control_t *control)
{
  if(control->reg_object.instance_id == 0) {
    control->reg_object.instance_id =
      lwm2m_engine_recommend_instance_id(control->reg_object.object_id);
  }
  control->reg_object.callback = lwm2m_callback;
  lwm2m_engine_add_object(&control->reg_object);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
ipso_control_remove(ipso_control_t *control)
{
  lwm2m_engine_remove_object(&control->reg_object);
  return 1;
}
/*---------------------------------------------------------------------------*/
