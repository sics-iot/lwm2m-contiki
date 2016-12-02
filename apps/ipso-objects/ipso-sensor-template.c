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
#include "ipso-sensor-template.h"
#include "lwm2m-engine.h"
#include <string.h>
#include <stdio.h>

#define IPSO_SENSOR_VALUE     5700
#define IPSO_SENSOR_UNIT      5701
#define IPSO_SENSOR_MIN_VALUE 5601
#define IPSO_SENSOR_MAX_VALUE 5602
#define IPSO_SENSOR_MIN_RANGE 5603
#define IPSO_SENSOR_MAX_RANGE 5604

#define IPSO_SENSOR_RESET_MINMAX 5605
/*---------------------------------------------------------------------------*/
uint32_t last_value;
size_t my_write_float32fix(const lwm2m_context_t *ctx, uint8_t *outbuf, size_t outlen, int32_t value, int bits) {
  last_value = value;
  return 0;
}

struct lwm2m_writer fake_writer = {
  .write_float32fix = my_write_float32fix
};
/*---------------------------------------------------------------------------*/
static int init = 0;
static ntimer_t nt;

/* Currently support max 4 periodic sensors */
#define MAX_PERIODIC 4
struct periodic_sensor {
  ipso_sensor_value_t *value;
  uint16_t ticks_left;
} periodics[MAX_PERIODIC];

static void
timer_callback(ntimer_t *timer)
{
  int i;
  printf("timer callback at %"PRIu64"\n", ntimer_uptime());
  ntimer_reset(timer, 1000);

  for(i = 0; i < MAX_PERIODIC; i++) {
    if(periodics[i].value != NULL) {
      printf("*** Sensor periodic - time left:%d\n", periodics[i].ticks_left);
      if(periodics[i].ticks_left > 0) {
        periodics[i].ticks_left--;
      } else {
        struct lwm2m_context ctx;
        ctx.writer = &fake_writer;
        periodics[i].value->sensor->write_callback(&ctx);
        periodics[i].ticks_left = periodics->value->sensor->update_interval;
        printf("Got last value: %d\n", last_value);
      }
    }
  }
}

static void
add_periodic(ipso_sensor_t *sensor)
{
  int i;
  for(i = 0; i < MAX_PERIODIC; i++) {
    if(periodics[i].value == NULL) {
      periodics[i].value = sensor->sensor_value;
      periodics[i].ticks_left = sensor->update_interval;
      return;
    }
  }
}
/*---------------------------------------------------------------------------*/
static int
lwm2m_callback(lwm2m_object_instance_t *object,
                          lwm2m_context_t *ctx)
{
  /* Here we cast to our sensor-template struct */
  ipso_sensor_t *sensor;
  ipso_sensor_value_t *value;
  value = (ipso_sensor_value_t *) object;
  sensor = value->sensor;

  /* Do the stuff */
  if(ctx->level == 1) {
    /* Should not happen 3303 */
    return 0;
  }
  if(ctx->level == 2) {
    /* This is a get whole object - or write whole object 3303/0 */
    return 0;
  }
  if(ctx->level == 3) {
    /* This is a get request on 3303/0/3700 */
    /* NOW we assume a get.... which might be wrong... */
    printf("*** Someone called: %d/%d/%d with op=%d\n",
           ctx->object_id, ctx->object_instance_id, ctx->resource_id, ctx->operation);

    if(ctx->operation == LWM2M_OP_READ) {
      switch(ctx->resource_id) {
      case IPSO_SENSOR_UNIT:
        if(sensor->unit != NULL) {
          lwm2m_object_write_string(ctx, sensor->unit, strlen(sensor->unit));
        }
        break;
      case IPSO_SENSOR_MAX_RANGE:
        lwm2m_object_write_float32fix(ctx, (sensor->max_range * 1024) / 1000, 10);
        break;
      case IPSO_SENSOR_MIN_RANGE:
        lwm2m_object_write_float32fix(ctx, (sensor->min_range * 1024) / 1000, 10);
        break;
      case IPSO_SENSOR_MAX_VALUE:
        lwm2m_object_write_float32fix(ctx, (value->min_value * 1024) / 1000, 10);
        break;
      case IPSO_SENSOR_MIN_VALUE:
        lwm2m_object_write_float32fix(ctx, (value->min_value * 1024) / 1000, 10);
        break;
      case IPSO_SENSOR_VALUE:
        if(sensor->write_callback != NULL) {
          sensor->write_callback(ctx);
        }
        break;
      default:
        return 0;
      }
    } else if(ctx->operation == LWM2M_OP_EXECUTE) {
      if(ctx->resource_id == IPSO_SENSOR_RESET_MINMAX) {
        printf("Reset to last value");
        value->min_value = value->last_value;
        value->max_value = value->last_value;
      }
    }
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
int
ipso_sensor_add(ipso_sensor_t *sensor)
{
  if(!init && sensor->update_interval > 0) {
    ntimer_set_callback(&nt, timer_callback);
    ntimer_set(&nt, 1000);
    init = 1;
    add_periodic(sensor);
  }

  if(sensor->sensor_value == NULL) {
    return 0;
  }
  sensor->sensor_value->reg_object.object_id = sensor->object_id;
  sensor->sensor_value->sensor = sensor;
  sensor->sensor_value->reg_object.instance_id = lwm2m_engine_recommend_instance_id(sensor->object_id);
  sensor->sensor_value->reg_object.callback = lwm2m_callback;
  lwm2m_engine_add_object(&sensor->sensor_value->reg_object);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
ipso_sensor_remove(ipso_sensor_t *sensor)
{
  lwm2m_engine_remove_object(&sensor->sensor_value->reg_object);
  return 1;
}
/*---------------------------------------------------------------------------*/
