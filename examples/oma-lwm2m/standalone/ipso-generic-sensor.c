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
 */

/**
 * \file
 *         Implementation of OMA LWM2M / IPSO Generic Sensor
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

#include <stdint.h>
#include "lwm2m-object.h"
#include "lwm2m-engine.h"
#include "er-coap-engine.h"
#include <string.h>

#define NR_INSTANCES 3

static int32_t min_val[NR_INSTANCES];
static int32_t max_val[NR_INSTANCES];
/* Note - these values are set in fractions of 1024 so 1.0 = 1024 */
static int32_t min_range_val[NR_INSTANCES] = {-2048,233,-3000};
static int32_t max_range_val[NR_INSTANCES] = {4711, 4712, 1024 * 4};

static void notify(int instance, int id);

/*---------------------------------------------------------------------------*/
static int
read_value_from_instance(int instance_index, int instance, int32_t *value)
{
  /* just some value... */
  int32_t v = instance * 100 + 32;

  if(instance >= NR_INSTANCES) {
    return 0;
  }

  /* Convert milliCelsius to fix float */
  *value = (v * LWM2M_FLOAT32_FRAC);

  if(*value < min_val[instance_index]) {
    min_val[instance_index] = *value;
    notify(instance, 5601);
  }
  if(*value > max_val[instance_index]) {
    max_val[instance_index] = *value;
    notify(instance, 5602);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
read_value(lwm2m_context_t *ctx, uint8_t *outbuf, size_t outsize)
{
  int32_t value;
  /* Here we should check which of the instance it is... */
  if(read_value_from_instance(ctx->object_instance_index, ctx->object_instance_id, &value)) {
    return ctx->writer->write_float32fix(ctx, outbuf, outsize,
                                         value, LWM2M_FLOAT32_BITS);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
read_from_vars(lwm2m_context_t *ctx, uint8_t *outbuf, size_t outsize) {
  int instance = ctx->object_instance_index;
  int32_t *the_var;
  if(instance >= NR_INSTANCES) {
    return 0;
  }
  if(ctx->resource_id == 5603) {
    the_var = min_range_val;
  } else if(ctx->resource_id == 5604) {
    the_var = max_range_val;
  } else if(ctx->resource_id == 5601) {
    the_var = min_val;
  } else if(ctx->resource_id == 5602) {
    the_var = max_val;
  } else {
    return 0;
  }

  return ctx->writer->write_float32fix(ctx, outbuf, outsize, the_var[instance], LWM2M_FLOAT32_BITS);
}
/*---------------------------------------------------------------------------*/
static int
read_unit(lwm2m_context_t *ctx, uint8_t *outbuf, size_t outsize) {
  int instance = ctx->object_instance_index;
  char *unit;
  if(instance >= NR_INSTANCES) {
    return 0;
  }
  /* Just pick som good units here! */
  if(instance == 0) {
    unit = "RPM";
  } else {
    unit = "CEL";
  }

  return ctx->writer->write_string(ctx, outbuf, outsize, unit, strlen(unit));
}

/*---------------------------------------------------------------------------*/
LWM2M_RESOURCES(gen_sensor_resources,
                /* Temperature (Current) */
                LWM2M_RESOURCE_CALLBACK(5700, { read_value, NULL, NULL }),
                /* Units */
                LWM2M_RESOURCE_CALLBACK(5701, { read_unit, NULL, NULL }),
                /* Min Range Value */
                LWM2M_RESOURCE_CALLBACK(5603, { read_from_vars, NULL, NULL}),
                /* Max Range Value */
                LWM2M_RESOURCE_CALLBACK(5604, { read_from_vars, NULL, NULL}),
                /* Min Measured Value */
                LWM2M_RESOURCE_CALLBACK(5601, { read_from_vars, NULL, NULL}),
                /* Max Measured Value */
                LWM2M_RESOURCE_CALLBACK(5602, { read_from_vars, NULL, NULL}),
                );
LWM2M_INSTANCES(gen_sensor_instances,
                LWM2M_INSTANCE(0, gen_sensor_resources),
                LWM2M_INSTANCE(1, gen_sensor_resources),
                LWM2M_INSTANCE(2, gen_sensor_resources));
LWM2M_OBJECT(gen_sensor, 3300, gen_sensor_instances);
/*---------------------------------------------------------------------------*/

static void
notify(int instance, int id) {
  char path[20];
  snprintf(path, sizeof(path), "/%d/%d", instance, id);
  lwm2m_object_notify_observers(&gen_sensor, path);
}


void
ipso_generic_sensor_init(void)
{
  int32_t v;

  /* register this device and its handlers - the handlers automatically
     sends in the object to handle */
  lwm2m_engine_register_object(&gen_sensor);
 }
/*---------------------------------------------------------------------------*/
/** @} */
