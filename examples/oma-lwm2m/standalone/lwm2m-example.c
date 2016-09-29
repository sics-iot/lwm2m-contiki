/*
 * Copyright (c) 2016, SICS, Swedish ICT AB.
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
 */

/**
 * \file
 *         An OMA LWM2M standalone example to demonstrate how to use
 *         the Contiki OMA LWM2M library from a native application.
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "sys/ntimer.h"
#include "lwm2m-engine.h"
#include "coap-ipv4.h"
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <inttypes.h>
/*---------------------------------------------------------------------------*/
static void
callback(ntimer_t *timer)
{
  printf("uptime: %"PRIu64"\n", ntimer_uptime());
  ntimer_reset(timer, 10000);
}
/*---------------------------------------------------------------------------*/
int
main(int argc, char * argv[])
{
  static ntimer_t nt;
  uint64_t next_time;
  fd_set fdr;
  fd_set fdw;
  int maxfd;
  int retval;
  struct timeval tv;

  /* Example using network timer */
  ntimer_set_callback(&nt, callback);
  ntimer_set(&nt, 10000);

  /* Initialize the OMA LWM2M engine */
  lwm2m_engine_init();

  /* Register default LWM2M objects */
  lwm2m_engine_register_default_objects();

  while(1) {
    tv.tv_sec = 0;
    tv.tv_usec = 250;

    next_time = ntimer_time_to_next_expiration();
    if(next_time > 0) {
      tv.tv_sec = next_time / 1000;
      tv.tv_usec = (next_time % 1000) * 1000;
      if(tv.tv_usec == 0 && tv.tv_sec == 0) {
        /*
         * ntimer time resolution is milliseconds. Avoid millisecond
         * busy loops.
         */
        tv.tv_usec = 250;
      }
    }

    FD_ZERO(&fdr);
    FD_ZERO(&fdw);
    maxfd = 0;
    if(coap_ipv4_fd >= 0) {
      if(coap_ipv4_set_fd(&fdr, &fdw)) {
        maxfd = coap_ipv4_fd;
      }
    }

    retval = select(maxfd + 1, &fdr, &fdw, NULL, &tv);
    if(retval < 0) {
      if(errno != EINTR) {
        perror("select");
      }
    } else if(retval > 0) {
      /* timeout => retval == 0 */
      if(coap_ipv4_fd >= 0) {
        coap_ipv4_handle_fd(&fdr, &fdw);
      }
    }

    /* Process network timers */
    for(retval = 0; retval < 5 && ntimer_run(); retval++);
  }

  return 0;
}
/*---------------------------------------------------------------------------*/
