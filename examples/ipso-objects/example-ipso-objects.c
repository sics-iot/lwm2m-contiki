/*
 * Copyright (c) 2015, Yanzi Networks AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      OMA LWM2M and IPSO Objects example.
 * \author
 *      Joakim Eriksson, joakime@sics.se
 *      Niclas Finne, nfi@sics.se
 */

#include "contiki.h"
#include "lwm2m-engine.h"
#include "lwm2m-rd-client.h"
#include "ipso-objects.h"
#include "ipso-sensor-template.h"

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

#ifndef REGISTER_WITH_LWM2M_BOOTSTRAP_SERVER
#define REGISTER_WITH_LWM2M_BOOTSTRAP_SERVER 0
#endif

#ifndef REGISTER_WITH_LWM2M_SERVER
#define REGISTER_WITH_LWM2M_SERVER 1
#endif

#if BOARD_SENSORTAG
#include "board-peripherals.h"


/* Temperature reading */
static lwm2m_status_t
read_temp_value(int32_t *value)
{
  int val;
  val = hdc_1000_sensor.value(HDC_1000_SENSOR_TYPE_TEMP);
  /* convert to milli celcius */
  *value = 100 * val;
  return LWM2M_STATUS_OK;
}
/*---------------------------------------------------------------------------*/
static ipso_sensor_value_t temp_value;

static const ipso_sensor_t temp_sensor = {
  .object_id = 3303,
  .sensor_value = &temp_value,
  .max_range = 100000, /* 100 cel milli celcius */
  .min_range = -10000, /* -10 cel milli celcius */
  .get_value_in_millis = read_temp_value,
  .unit = "Cel",
  .update_interval = 10
};
#endif


#ifndef LWM2M_SERVER_ADDRESS
#define LWM2M_SERVER_ADDRESS "fd02::1"
#endif

PROCESS(example_ipso_objects, "IPSO object example");
AUTOSTART_PROCESSES(&example_ipso_objects);
/*---------------------------------------------------------------------------*/
static void
setup_lwm2m_servers(void)
{
#ifdef LWM2M_SERVER_ADDRESS
  coap_endpoint_t server_ep;
  if(coap_endpoint_parse(LWM2M_SERVER_ADDRESS, strlen(LWM2M_SERVER_ADDRESS),
                         &server_ep) != 0) {
    lwm2m_rd_client_register_with_bootstrap_server(&server_ep);
    lwm2m_rd_client_register_with_server(&server_ep);
  }
#endif /* LWM2M_SERVER_ADDRESS */

  lwm2m_rd_client_use_bootstrap_server(REGISTER_WITH_LWM2M_BOOTSTRAP_SERVER);
  lwm2m_rd_client_use_registration_server(REGISTER_WITH_LWM2M_SERVER);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(example_ipso_objects, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  PRINTF("Starting IPSO objects example\n");

  /* Initialize the OMA LWM2M engine */
  lwm2m_engine_init();

  /* Register default LWM2M objects */
  lwm2m_engine_register_default_objects();

#if BOARD_SENSORTAG
  ipso_sensor_add(&temp_sensor);
  ipso_button_init();

  SENSORS_ACTIVATE(hdc_1000_sensor);

#else
  /* Register default IPSO objects - such as button..*/
  ipso_objects_init();
#endif


  setup_lwm2m_servers();

  while(1) {
    PROCESS_WAIT_EVENT();
  }

  PROCESS_END();
}
