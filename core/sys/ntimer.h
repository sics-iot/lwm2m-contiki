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
 *         Network timer API.
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#ifndef NTIMER_H_
#define NTIMER_H_

#include "contiki-conf.h"
#include <stdint.h>

typedef struct ntimer ntimer_t;
struct ntimer {
  ntimer_t *next;
  void (* callback)(ntimer_t *);
  void *user_data;
  uint64_t expiration_time;
};

typedef struct {
  void     (* init)(void);
  uint64_t (* uptime)(void);
  void     (* update)(void);
} ntimer_driver_t;

#ifndef NTIMER_DRIVER
#ifdef NTIMER_CONF_DRIVER
#define NTIMER_DRIVER NTIMER_CONF_DRIVER
#else /* NTIMER_CONF_DRIVER */
#define NTIMER_DRIVER ntimer_default_driver
#endif /* NTIMER_CONF_DRIVER */
#endif /* NTIMER_DRIVER */

extern const ntimer_driver_t NTIMER_DRIVER;

/*
 * milliseconds since boot
 */
static inline uint64_t
ntimer_uptime(void)
{
  return NTIMER_DRIVER.uptime();
}

/*
 * seconds since boot
 */
static inline uint32_t
ntimer_seconds(void)
{
  return (uint32_t)(NTIMER_DRIVER.uptime() / 1000);
}

static inline void
ntimer_set_callback(ntimer_t *timer, void (* callback)(ntimer_t *))
{
  timer->callback = callback;
}

static inline void *
ntimer_get_user_data(ntimer_t *timer)
{
  return timer->user_data;
}

static inline void
ntimer_set_user_data(ntimer_t *timer, void *data)
{
  timer->user_data = data;
}

static inline int
ntimer_expired(const ntimer_t *timer)
{
  return timer->expiration_time <= ntimer_uptime();
}

void ntimer_stop(ntimer_t *timer);

void ntimer_set(ntimer_t *timer, uint64_t time);

/**
 * Set the ntimer to expire the specified time after the previous
 * expiration time. If the new expiration time has already passed, the
 * timer will expire as soon as possible.
 *
 * If the timer has not yet expired when this function is called, the
 * time until the timer expires will be extended by the specified time.
 */
void ntimer_reset(ntimer_t *timer, uint64_t time);

/**
 * Returns the time until next timer expires or 0 if there already
 * exists expired timers that have not yet been processed.
 * Returns a time in the future if there are no timers pending.
 */
uint64_t ntimer_time_to_next_expiration(void);

/**
 * Must be called periodically to process any expired ntimers.
 * Returns non-zero if it needs to run again to process more timers.
 */
int ntimer_run(void);

void ntimer_init(void);

#endif /* NTIMER_H_ */
