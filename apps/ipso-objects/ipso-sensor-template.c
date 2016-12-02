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


/*---------------------------------------------------------------------------*/
static int lwm2m_callback(lwm2m_object_instance_t *object,
                          lwm2m_context_t *ctx,
                          coap_packet_t *request,
                          coap_packet_t *response,
                          uint8_t *buffer, uint16_t buf_size,
                          int32_t *offset) {
  /* Do the stuff */
  
  return 1;
}
/*---------------------------------------------------------------------------*/
int
ipso_sensor_add(ipso_sensor_t *sensor)
{
  if(sensor->sensor_value == NULL) {
    return 0;
  }
  sensor->sensor_value->reg_object.object_id = sensor->object_id;
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
