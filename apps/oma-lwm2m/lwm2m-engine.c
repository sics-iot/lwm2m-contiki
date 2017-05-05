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
 */

/**
 * \file
 *         Implementation of the Contiki OMA LWM2M engine
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

#include "lwm2m-engine.h"
#include "lwm2m-object.h"
#include "lwm2m-device.h"
#include "lwm2m-plain-text.h"
#include "lwm2m-json.h"
#include "er-coap-constants.h"
#include "er-coap-engine.h"
#include "oma-tlv.h"
#include "oma-tlv-reader.h"
#include "oma-tlv-writer.h"
#include "lib/list.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#include "net/ipv6/uip-ds6.h"
#endif /* UIP_CONF_IPV6_RPL */

#define DEBUG 1
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTS(l,s,f) do { int i;					\
    for(i = 0; i < l; i++) printf(f, s[i]); \
    } while(0)
#define PRINTPRE(p,l,s) do { PRINTF(p);PRINTS(l,s,"%c"); } while(0);
#else
#define PRINTF(...)
#define PRINTS(l,s,f)
#define PRINTPRE(p,l,s);
#endif

#ifndef LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX
#ifdef LWM2M_DEVICE_MODEL_NUMBER
#define LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX LWM2M_DEVICE_MODEL_NUMBER
#else /* LWM2M_DEVICE_MODEL_NUMBER */
#define LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX "Contiki-"
#endif /* LWM2M_DEVICE_MODEL_NUMBER */
#endif /* LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX */

#ifdef LWM2M_ENGINE_CONF_USE_RD_CLIENT
#define USE_RD_CLIENT LWM2M_ENGINE_CONF_USE_RD_CLIENT
#else
#define USE_RD_CLIENT 1
#endif /* LWM2M_ENGINE_CONF_USE_RD_CLIENT */

#if USE_RD_CLIENT
#include "lwm2m-rd-client.h"
#endif

/* MACRO for getting out resource ID from resource array ID + flags */
#define RSC_ID(x) (x & 0xffff)
#define RSC_READABLE(x) ((x & LWM2M_RESOURCE_READ) > 0)
#define RSC_WRITABLE(x) ((x & LWM2M_RESOURCE_WRITE) > 0)

/* This is a double-buffer for generating BLOCKs in CoAP - the idea
   is that typical LWM2M resources will fit 1 block unless they themselves
   handle BLOCK transfer - having a double sized buffer makes it possible
   to allow writing more than one block before sending the full block.
   The RFC seems to indicate that all blocks execept the last one should
   be full.
*/
static uint8_t d_buf[COAP_MAX_BLOCK_SIZE * 2];
static lwm2m_buffer_t lwm2m_buf = {
  .len = 0, .size =  COAP_MAX_BLOCK_SIZE * 2, .buffer = d_buf
};

/* obj-id / ... */
static uint16_t lwm2m_buf_lock[4];
static uint64_t lwm2m_buf_lock_timeout = 0;

static lwm2m_write_opaque_callback current_opaque_callback;
static int current_opaque_offset = 0;

void lwm2m_device_init(void);
void lwm2m_security_init(void);
void lwm2m_server_init(void);
static lwm2m_object_instance_t *lwm2m_engine_get_object_instance(const lwm2m_context_t *context);

static coap_handler_status_t lwm2m_handler_callback(coap_packet_t *request,
                                                    coap_packet_t *response,
                                                    uint8_t *buffer,
                                                    uint16_t buffer_size,
                                                    int32_t *offset);
static lwm2m_object_instance_t *
lwm2m_engine_next_object_instance(const lwm2m_context_t *context, lwm2m_object_instance_t *last);


COAP_HANDLER(lwm2m_handler, lwm2m_handler_callback);
LIST(object_list);

/*---------------------------------------------------------------------------*/
static int
u16toa(uint8_t *buf, uint16_t v)
{
  int pos = 0;
  int div = 10000;
  /* Max size = 5 */
  while(div > 0) {
    buf[pos] = '0' + (v / div) % 10;
    /* if first non-zero found or we have found that before */
    if(buf[pos] > '0' || pos > 0 || div == 1) pos++;
    div = div / 10;
  }
  return pos;
}
/*---------------------------------------------------------------------------*/
static int
append_reg_tag(uint8_t *rd_data, size_t size, int oid, int iid, int rid)
{
  int pos = 0;
  rd_data[pos++] = '<';
  rd_data[pos++] = '/';
  pos += u16toa(&rd_data[pos], oid);
  if(iid > -1 && iid != 0xffff && size > pos) {
    rd_data[pos++] = '/';
    pos += u16toa(&rd_data[pos], iid);
    if(rid > -1 && size > pos) {
      rd_data[pos++] = '/';
      pos += u16toa(&rd_data[pos], rid);
    }
  }
  rd_data[pos++] = '>';
  return pos;
}
/*---------------------------------------------------------------------------*/
/* This is intended to switch out a block2 transfer buffer
 * It assumes that ctx containts the double buffer and that the outbuf is to
 * be the new buffer in ctx.
 */
static int
double_buffer_flush(lwm2m_context_t *ctx, lwm2m_buffer_t *outbuf, int size)
{
  /* Copy the data from the double buffer in ctx to the outbuf and move data */
  /* If the buffer is less than size - we will output all and get remaining down
     to zero */
  if(ctx->outbuf->len < size) {
    size = ctx->outbuf->len;
  }
  if(ctx->outbuf->len >= size && outbuf->size >= size) {
    PRINTF("Double buffer - copying out %d bytes remaining: %d\n",
           size, ctx->outbuf->len - size);
    memcpy(outbuf->buffer, ctx->outbuf->buffer, size);
    memcpy(ctx->outbuf->buffer, &ctx->outbuf->buffer[size],
           ctx->outbuf->len - size);
    ctx->outbuf->len -= size;
    outbuf->len = size;
    return outbuf->len;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
#if DEBUG
static inline const char *
get_method_as_string(rest_resource_flags_t method)
{
  if(method == METHOD_GET) {
    return "GET";
  } else if(method == METHOD_POST) {
    return "POST";
  } else if(method == METHOD_PUT) {
    return "PUT";
  } else if(method == METHOD_DELETE) {
    return "DELETE";
  } else {
    return "UNKNOWN";
  }
}
#endif
/*--------------------------------------------------------------------------*/
static int
parse_path(const char *path, int path_len,
           uint16_t *oid, uint16_t *iid, uint16_t *rid)
{
  int ret;
  int pos;
  uint16_t val;
  char c = 0;

  /* get object id */
  PRINTF("Parse PATH:");
  PRINTS(path_len, path, "%c");
  PRINTF("\n");

  ret = 0;
  pos = 0;
  do {
    val = 0;
    /* we should get a value first - consume all numbers */
    while(pos < path_len && (c = path[pos]) >= '0' && c <= '9') {
      val = val * 10 + (c - '0');
      pos++;
    }
    /* Slash will mote thing forward - and the end will be when pos == pl */
    if(c == '/' || pos == path_len) {
      PRINTF("Setting %u = %u\n", ret, val);
      if(ret == 0) *oid = val;
      if(ret == 1) *iid = val;
      if(ret == 2) *rid = val;
      ret++;
      pos++;
    } else {
      PRINTF("Error: illegal char '%c' at pos:%d\n", c, pos);
      return -1;
    }
  } while(pos < path_len);
  return ret;
}
/*--------------------------------------------------------------------------*/
static int
lwm2m_engine_parse_context(const char *path, int path_len,
                           coap_packet_t *request, coap_packet_t *response,
                           uint8_t *outbuf, size_t outsize,
                           lwm2m_context_t *context)
{
  int ret;
  if(context == NULL || path == NULL) {
    return 0;
  }

  ret = parse_path(path, path_len, &context->object_id,
                   &context->object_instance_id, &context->resource_id);

  if(ret > 0) {
    context->level = ret;
  }

  return ret;
}

/*---------------------------------------------------------------------------*/
void lwm2m_engine_set_opaque_callback(lwm2m_context_t *ctx, lwm2m_write_opaque_callback cb)
{
  /* Here we should set the callback for the opaque that we are currently generating... */
  /* And we should in the future associate the callback with the CoAP message info - MID */
  PRINTF("Setting opaque handler - offset: %d,%d\n", ctx->offset, ctx->outbuf->len);

  current_opaque_offset = 0;
  current_opaque_callback = cb;
}
/*---------------------------------------------------------------------------*/
int
lwm2m_engine_get_rd_data(uint8_t *rd_data, int size)
{
  lwm2m_object_instance_t *o;
  int pos;
  int len;

  pos = 0;

  for(o = list_head(object_list); o != NULL; o = o->next) {
    if(pos > 0) {
      rd_data[pos++] = ',';
    }
    len = append_reg_tag(&rd_data[pos], size - pos,
                         o->object_id, o->instance_id, -1);
    if(len > 0 && len < size - pos) {
      pos += len;
    }
  }
  rd_data[pos] = 0;
  return pos;
}
/*---------------------------------------------------------------------------*/
void
lwm2m_engine_init(void)
{
  list_init(object_list);

#ifdef LWM2M_ENGINE_CLIENT_ENDPOINT_NAME
  const char *endpoint = LWM2M_ENGINE_CLIENT_ENDPOINT_NAME;

#else /* LWM2M_ENGINE_CLIENT_ENDPOINT_NAME */
  static char endpoint[32];
  int len, i;
  uint8_t state;
  uip_ipaddr_t *ipaddr;

  len = strlen(LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX);
  /* ensure that this fits with the hex-nums */
  if(len > sizeof(endpoint) - 13) {
    len = sizeof(endpoint) - 13;
  }
  memcpy(endpoint, LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX, len);

  /* pick an IP address that is PREFERRED or TENTATIVE */
  ipaddr = NULL;
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      ipaddr = &(uip_ds6_if.addr_list[i]).ipaddr;
      break;
    }
  }

  if(ipaddr != NULL) {
    for(i = 0; i < 6; i++) {
      /* assume IPv6 for now */
      uint8_t b = ipaddr->u8[10 + i];
      endpoint[len++] = (b >> 4) > 9 ? 'A' - 10 + (b >> 4) : '0' + (b >> 4);
      endpoint[len++] = (b & 0xf) > 9 ? 'A' - 10 + (b & 0xf) : '0' + (b & 0xf);
    }
  }

  /* a zero at end of string */
  endpoint[len] = 0;

#endif /* LWM2M_ENGINE_CLIENT_ENDPOINT_NAME */

  rest_init_engine();

  /* Register the CoAP handler for lightweight object handling */
  coap_add_handler(&lwm2m_handler);

#if USE_RD_CLIENT
  lwm2m_rd_client_init(endpoint);
#endif
}
/*---------------------------------------------------------------------------*/
void
lwm2m_engine_register_default_objects(void)
{
  lwm2m_security_init();
  lwm2m_server_init();
  lwm2m_device_init();
}
/*---------------------------------------------------------------------------*/
/**
 * @brief  Set the writer pointer to the proper writer based on the Accept: header
 *
 * @param[in] context  LWM2M context to operate on
 * @param[in] accept   Accept type number from CoAP headers
 *
 * @return The content type of the response if the selected writer is used
 */
static unsigned int
lwm2m_engine_select_writer(lwm2m_context_t *context, unsigned int accept)
{
  switch(accept) {
    case LWM2M_TLV:
    case LWM2M_OLD_TLV:
      context->writer = &oma_tlv_writer;
      break;
    case LWM2M_TEXT_PLAIN:
    case TEXT_PLAIN:
      context->writer = &lwm2m_plain_text_writer;
      break;
    case LWM2M_JSON:
    case LWM2M_OLD_JSON:
    case APPLICATION_JSON:
      context->writer = &lwm2m_json_writer;
      break;
    default:
      PRINTF("Unknown Accept type %u, using LWM2M plain text\n", accept);
      context->writer = &lwm2m_plain_text_writer;
      /* Set the response type to plain text */
      accept = LWM2M_TEXT_PLAIN;
      break;
  }
  context->content_type = accept;
  return accept;
}
/*---------------------------------------------------------------------------*/
/**
 * @brief  Set the reader pointer to the proper reader based on the Content-format: header
 *
 * @param[in] context        LWM2M context to operate on
 * @param[in] content_format Content-type type number from CoAP headers
 */
static void
lwm2m_engine_select_reader(lwm2m_context_t *context, unsigned int content_format)
{
  switch(content_format) {
    case LWM2M_TLV:
    case LWM2M_OLD_TLV:
      context->reader = &oma_tlv_reader;
      break;
    case LWM2M_TEXT_PLAIN:
    case TEXT_PLAIN:
      context->reader = &lwm2m_plain_text_reader;
      break;
    default:
      PRINTF("Unknown content type %u, using LWM2M plain text\n",
             content_format);
      context->reader = &lwm2m_plain_text_reader;
      break;
  }
}

/*---------------------------------------------------------------------------*/
/* Lightweight object instances */
/*---------------------------------------------------------------------------*/
static lwm2m_object_instance_t *last_ins;
static int last_rsc_pos;

/* Multi read will handle read of JSON / TLV or Discovery (Link Format) */
static lwm2m_status_t
perform_multi_resource_read_op(lwm2m_object_instance_t *instance,
                               lwm2m_context_t *ctx)
{
  int size = ctx->outbuf->size;
  int len = 0;
  uint8_t initialized = 0; /* used for commas, etc */
  uint8_t num_read = 0;
  lwm2m_buffer_t *outbuf;

  /* copy out the out-buffer as read will use its own - will be same for disoc when
     read is fixed */
  outbuf = ctx->outbuf;

  /* Currently we only handle one incoming read request at a time - so we return
     BUZY or service unavailable */
  if(lwm2m_buf_lock[0] != 0 && (lwm2m_buf_lock_timeout > ntimer_uptime()) &&
     ((lwm2m_buf_lock[1] != ctx->object_id) ||
      (lwm2m_buf_lock[2] != ctx->object_instance_id) ||
      (lwm2m_buf_lock[3] != ctx->resource_id))) {
    PRINTF("Multi-read: already exporting resource: %d/%d/%d\n",
           lwm2m_buf_lock[1], lwm2m_buf_lock[2], lwm2m_buf_lock[3]);
    return LWM2M_STATUS_SERVICE_UNAVAILABLE;
  }

  PRINTF("MultiRead: %d/%d/%d lv:%d offset:%d\n",
         ctx->object_id, ctx->object_instance_id, ctx->resource_id, ctx->level, ctx->offset);

  /* Make use of the double buffer */
  ctx->outbuf = &lwm2m_buf;

  if(ctx->offset == 0) {
    /* First GET request - need to setup all buffers and reset things here */
    last_ins = instance;
    last_rsc_pos = 0;
    /* reset any callback */
    current_opaque_callback = NULL;
    /* reset lwm2m_buf_len - so that we can use the double-size buffer */
    lwm2m_buf_lock[0] = 1; /* lock "flag" */
    lwm2m_buf_lock[1] = ctx->object_id;
    lwm2m_buf_lock[2] = ctx->object_instance_id;
    lwm2m_buf_lock[3] = ctx->resource_id;
    lwm2m_buf.len = 0;
    /* Here we should print top node */
  } else {
    /* offset > 0 - assume that we are already in a disco or multi get*/
    instance = last_ins;
    /* we assume that this was initialized */
    initialized = 1;
    ctx->writer_flags |= WRITER_OUTPUT_VALUE;
    if(last_ins == NULL) {
      ctx->offset = -1;
      ctx->outbuf->buffer[0] = ' ';
    }
  }
  lwm2m_buf_lock_timeout = ntimer_uptime() + 1000;

  while(instance != NULL) {
    /* Do the discovery or read */
    if(instance->resource_ids != NULL && instance->resource_count > 0) {
      /* show all the available resources (or read all) */
      while(last_rsc_pos < instance->resource_count) {
        PRINTF("READ: %x %x %x lv:%d\n", instance->resource_ids[last_rsc_pos], RSC_ID(instance->resource_ids[last_rsc_pos]), ctx->resource_id, ctx->level);

        /* Check if this is a object read or if it is the correct resource */
        if(ctx->level < 3 || ctx->resource_id == RSC_ID(instance->resource_ids[last_rsc_pos])) {
          /* ---------- Discovery operation ------------- */
          /* If this is a discovery all the object, instance, and resource triples should be
             generted */
          if(ctx->operation == LWM2M_OP_DISCOVER) {
            int dim = 0;
            len = snprintf((char *) &ctx->outbuf->buffer[ctx->outbuf->len],
                           size - ctx->outbuf->len,
                           (ctx->outbuf->len == 0 && ctx->offset == 0) ? "</%d/%d/%d>":",</%d/%d/%d>",
                           instance->object_id, instance->instance_id,
                           RSC_ID(instance->resource_ids[last_rsc_pos]));
            if(instance->resource_dim_callback != NULL &&
               (dim = instance->resource_dim_callback(instance,
                                                      RSC_ID(instance->resource_ids[last_rsc_pos]))) > 0) {
              len += snprintf((char *) &ctx->outbuf->buffer[ctx->outbuf->len + len],
                              size - ctx->outbuf->len - len,  ";dim=%d", dim);
            }
            /* here we have "read" out something */
            num_read++;
            ctx->outbuf->len += len;
            if(len < 0 || ctx->outbuf->len >= size) {
              double_buffer_flush(ctx, outbuf, size);

              PRINTF("Copied lwm2m buf - remaining: %d\n", lwm2m_buf.len);
              /* switch buffer */
              ctx->outbuf = outbuf;
              ctx->writer_flags |= WRITER_HAS_MORE;
              ctx->offset += size;
              return LWM2M_STATUS_OK;
            }
            /* ---------- Read operation ------------- */
          } else if(ctx->operation == LWM2M_OP_READ) {
            lwm2m_status_t success;
            uint8_t lv;

            lv = ctx->level;

            /* Do not allow a read on a non-readable */
            if(lv == 3 && !RSC_READABLE(instance->resource_ids[last_rsc_pos])) {
              lwm2m_buf_lock[0] = 0;
              return LWM2M_STATUS_OPERATION_NOT_ALLOWED;
            }
            /* Set the resource ID is ctx->level < 3 */
            if(lv < 3) {
              ctx->resource_id = RSC_ID(instance->resource_ids[last_rsc_pos]);
            }
            if(lv < 2) {
              ctx->object_instance_id = instance->instance_id;
            }

            if(RSC_READABLE(instance->resource_ids[last_rsc_pos])) {
              ctx->level = 3;
              if(!initialized) {
                /* Now we need to initialize the object writing for this new object */
                len = ctx->writer->init_write(ctx);
                ctx->outbuf->len += len;
                PRINTF("INIT WRITE len:%d size:%d\n", len, (int) ctx->outbuf->size);
                initialized = 1;
              }

              if(current_opaque_callback == NULL) {
                PRINTF("Doing the callback to the resource %d\n", ctx->outbuf->len);
                /* No special opaque callback to handle - use regular callback */
                success = instance->callback(instance, ctx);
                PRINTF("After the callback to the resource %d %d\n", ctx->outbuf->len, success);

                if(success != LWM2M_STATUS_OK) {
                  /* What to do here? */
                  PRINTF("Callback failed: %d\n", success);
                  if(lv < 3) {
                    if(success == LWM2M_STATUS_NOT_FOUND) {
                      /* ok with a not found during a multi read - what more
                         is ok? */
                    } else {
                      lwm2m_buf_lock[0] = 0;
                      return success;
                    }
                  } else {
                    lwm2m_buf_lock[0] = 0;
                    return success;
                  }
                }
              }
              if(current_opaque_callback != NULL) {
                int old_offset = ctx->offset;
                int num_write = COAP_MAX_BLOCK_SIZE - ctx->outbuf->len;
                /* Check if the callback did set a opaque callback function - then
                   we should produce data via that callback until the opaque has fully
                   been handled */
                ctx->offset = current_opaque_offset;
                PRINTF("Calling the opaque handler %x\n", ctx->writer_flags);
                success =
                  current_opaque_callback(instance, ctx, num_write);
                if((ctx->writer_flags & WRITER_HAS_MORE) == 0) {
                  /* This opaque stream is now done! */
                  PRINTF("Setting opaque callback to null - it is done!\n");
                  current_opaque_callback = NULL;
                } else if(ctx->outbuf->len < COAP_MAX_BLOCK_SIZE) {
                  lwm2m_buf_lock[0] = 0;
                  return LWM2M_STATUS_ERROR;
                }
                current_opaque_offset += num_write;
                ctx->offset = old_offset;
                PRINTF("Setting back offset to: %d\n", ctx->offset);
              }

              /* here we have "read" out something */
              num_read++;
              /* We will need to handle no-success and other things */
              PRINTF("Called %u/%u/%u outlen:%u ok:%u\n",
                     ctx->object_id, ctx->object_instance_id, ctx->resource_id,
                     ctx->outbuf->len, success);

              /* we need to handle full buffer, etc here also! */
              ctx->level = lv;
            } else {
              PRINTF("Resource not readable\n");
            }
          }
        }
        if(current_opaque_callback == NULL) {
          /* This resource is now done - (only when the opaque is also done) */
          last_rsc_pos++;
        } else {
          PRINTF("Opaque is set - continue with that.\n");
        }

        if(ctx->outbuf->len >= COAP_MAX_BLOCK_SIZE) {
          PRINTF("**** CoAP MAX BLOCK Reached!!! **** SEND\n");
          /* If the produced data is larger than a CoAP block we need to send
             this now */
          if(ctx->outbuf->len < 2 * COAP_MAX_BLOCK_SIZE) {
            /* We assume that size is equal to COAP_MAX_BLOCK_SIZE here */
            double_buffer_flush(ctx, outbuf, size);

            PRINTF("Copied lwm2m buf - remaining: %d\n", lwm2m_buf.len);
            /* switch buffer */
            ctx->outbuf = outbuf;
            ctx->writer_flags |= WRITER_HAS_MORE;
            ctx->offset += size;
            /* OK - everything went well... but we have more. - keep the lock here! */
            return LWM2M_STATUS_OK;
          } else {
            PRINTF("*** ERROR Overflow?\n");
            return LWM2M_STATUS_ERROR;
          }
        }
      }
    }

    instance = lwm2m_engine_next_object_instance(ctx, instance);
    last_ins = instance;
    if(ctx->operation == LWM2M_OP_READ) {
      PRINTF("END Writer %d ->", ctx->outbuf->len);
      len = ctx->writer->end_write(ctx);
      ctx->outbuf->len += len;
      PRINTF("%d\n", ctx->outbuf->len);
    }

    initialized = 0;
    last_rsc_pos = 0;
  }

  /* did not read anything even if we should have - on single item */
  if (num_read == 0 && ctx->level == 3) {
    lwm2m_buf_lock[0] = 0;
    return LWM2M_STATUS_NOT_FOUND;
  }

  /* seems like we are done! - flush buffer */
  len = double_buffer_flush(ctx, outbuf, size);
  ctx->outbuf = outbuf;
  ctx->offset += len;

  /* If there is still data in the double-buffer - indicate that so that we get another
     callback */
  if(lwm2m_buf.len > 0) {
    ctx->writer_flags |= WRITER_HAS_MORE;
  } else {
    /* OK - everything went well we are done, unlock and return */
    lwm2m_buf_lock[0] = 0;
  }

  PRINTF("At END: Copied lwm2m buf %d\n", len);

  return LWM2M_STATUS_OK;
}
/*---------------------------------------------------------------------------*/
static lwm2m_object_instance_t *
create_instance(lwm2m_context_t *context,
                lwm2m_object_instance_t *instance)
{
  /* If not discovery or create - this is a regular OP - do the callback */
  PRINTF("CREATE OP on object:%d\n", instance->object_id);
  context->operation = LWM2M_OP_CREATE;
  /* NOTE: context->object_instance_id needs to be set before calling */
  lwm2m_status_t status = instance->callback(instance, context);
  if(status == LWM2M_STATUS_OK) {
    PRINTF("Created instance: %d\n", context->object_instance_id);
    instance = lwm2m_engine_get_object_instance(context);
    context->operation = LWM2M_OP_WRITE;
    REST.set_response_status(context->response, CREATED_2_01);
#if USE_RD_CLIENT
    lwm2m_rd_client_set_update_rd();
#endif
    return instance;
  } else {
    /* Can not create... */
    return NULL;
  }
}
/*---------------------------------------------------------------------------*/
#define MODE_NONE      0
#define MODE_INSTANCE  1
#define MODE_VALUE     2
#define MODE_READY     3

static lwm2m_object_instance_t *
get_or_create_instance(lwm2m_context_t *ctx, uint16_t oid, uint8_t *created)
{
  lwm2m_object_instance_t *instance;
  int lv = ctx->level;
  instance = lwm2m_engine_get_object_instance(ctx);
  PRINTF("Instance: %u/%u/%u = %p\n", ctx->object_id,
         ctx->object_instance_id, ctx->resource_id, instance);
  /* by default we assume that the instance is not created... so we set flag to zero */
  if(created != NULL) *created = 0;
  if(instance == NULL) {
    /* Find a generic instance for create */
    ctx->object_instance_id = LWM2M_OBJECT_INSTANCE_NONE;
    instance = lwm2m_engine_get_object_instance(ctx);
    if(instance == NULL) {
      return NULL;
    }
    ctx->level = 2; /* create use 2? */
    ctx->object_instance_id = oid;
    if((instance = create_instance(ctx, instance)) != NULL) {
      PRINTF("Instance %d created\n", instance->instance_id);
      /* set created flag to one */
      if(created != NULL) *created = 1;
    }
    ctx->level = lv;
  }
  return instance;
}

static int
check_write(lwm2m_object_instance_t *instance, int rid)
{
  int i;
  if(instance->resource_ids != NULL && instance->resource_count > 0) {
    int count = instance->resource_count;
    for(i = 0; i < count; i++) {
      if(RSC_ID(instance->resource_ids[i]) == rid &&
         RSC_WRITABLE(instance->resource_ids[i])) {
        /* yes - writable */
        return 1;
      }
    }
  }
  return 0;
}

static lwm2m_status_t
process_tlv_write(lwm2m_context_t *ctx, int rid, uint8_t *data, int len)
{
  lwm2m_object_instance_t *instance;
  uint8_t created = 0;
  ctx->inbuf->buffer = data;
  ctx->inbuf->pos = 0;
  ctx->inbuf->size = len;
  ctx->level = 3;
  ctx->resource_id = rid;
  PRINTF("  Doing callback to %u/%u/%u\n", ctx->object_id,
         ctx->object_instance_id, ctx->resource_id);
  instance = get_or_create_instance(ctx, ctx->object_instance_id, &created);
  if(instance != NULL && instance->callback != NULL) {
    if(created || check_write(instance, rid)) {
      return instance->callback(instance, ctx);
    } else {
      return LWM2M_STATUS_OPERATION_NOT_ALLOWED;
    }
  }
  return LWM2M_STATUS_ERROR;
}

static lwm2m_status_t
perform_multi_resource_write_op(lwm2m_object_instance_t *instance,
                                lwm2m_context_t *ctx, int format)
{
  /* Only for JSON and TLV formats */
  uint16_t oid = 0, iid = 0, rid = 0;
  uint8_t olv = 0;
  uint8_t mode = 0;
  uint8_t *inbuf;
  int inpos;
  size_t insize;

  olv = ctx->level;
  inbuf = ctx->inbuf->buffer;
  inpos = ctx->inbuf->pos;
  insize = ctx->inbuf->size;

  PRINTF("Multi Write \n");
  if(format == LWM2M_JSON || format == LWM2M_OLD_JSON) {
    struct json_data json;

    while(lwm2m_json_next_token(ctx, &json)) {
      int i;
      uint8_t created = 0;
      PRINTF("JSON: '");
      for(i = 0; i < json.name_len; i++) PRINTF("%c", json.name[i]);
      PRINTF("':'");
      for(i = 0; i < json.value_len; i++) PRINTF("%c", json.value[i]);
      PRINTF("'\n");
      if(json.name[0] == 'n') {
        i = parse_path((const char *) json.value, json.value_len, &oid, &iid, &rid);
        if(i > 0) {
          if(ctx->level == 1) {
            ctx->level = 3;
            ctx->object_instance_id = oid;
            ctx->resource_id = iid;

            instance = get_or_create_instance(ctx, oid, &created);
          }
          if(instance != NULL && instance->callback != NULL) {
            mode |= MODE_INSTANCE;
          } else {
            /* Failure... */
            return LWM2M_STATUS_ERROR;
          }
        }
      } else {
        /* HACK - assume value node - can it be anything else? */
        mode |= MODE_VALUE;
        /* update values */
        inbuf = ctx->inbuf->buffer;
        inpos = ctx->inbuf->pos;

        ctx->inbuf->buffer = json.value;
        ctx->inbuf->pos = 0;
        ctx->inbuf->size = json.value_len;
      }

      if(mode == MODE_READY) {
        /* allow write if just created - otherwise not */
        if(!created && !check_write(instance, ctx->resource_id)) {
          return LWM2M_STATUS_OPERATION_NOT_ALLOWED;
        }
        if(instance->callback(instance, ctx) != LWM2M_STATUS_OK) {
          /* TODO what to do here */
        }
        mode = MODE_NONE;
        ctx->inbuf->buffer = inbuf;
        ctx->inbuf->pos = inpos;
        ctx->inbuf->size = insize;
        ctx->level = olv;
      }
    }
  } else if(format == LWM2M_TLV || format == LWM2M_OLD_TLV) {
    size_t len;
    oma_tlv_t tlv;
    int tlvpos = 0;
    lwm2m_status_t status;
    while(tlvpos < insize) {
      len = oma_tlv_read(&tlv, &inbuf[tlvpos], insize - tlvpos);
      PRINTF("Got TLV format First is: type:%d id:%d len:%d (p:%d len:%d/%d)\n",
             tlv.type, tlv.id, (int) tlv.length,
             (int) tlvpos, (int) len, (int) insize);
      if(tlv.type == OMA_TLV_TYPE_OBJECT_INSTANCE) {
        oma_tlv_t tlv2;
        int len2;
        int pos = 0;
        ctx->object_instance_id = tlv.id;
        if(tlv.length == 0) {
          /* Create only - no data */
          if((instance = create_instance(ctx, instance)) == NULL) {
            return LWM2M_STATUS_ERROR;
          }
        }
        while(pos < tlv.length && (len2 = oma_tlv_read(&tlv2, &tlv.value[pos],
                                                       tlv.length - pos))) {
          PRINTF("   TLV type:%d id:%d len:%d (len:%d/%d)\n",
                 tlv2.type, tlv2.id, (int) tlv2.length,
                 (int) len2, (int) insize);
          if(tlv2.type == OMA_TLV_TYPE_RESOURCE) {
            status = process_tlv_write(ctx, tlv2.id,
                                       (uint8_t *)&tlv.value[pos], len2);
            if(status != LWM2M_STATUS_OK) {
              return status;
            }
          }
          pos += len2;
        }
      } else if(tlv.type == OMA_TLV_TYPE_RESOURCE) {
        status = process_tlv_write(ctx, tlv.id, (uint8_t *)&inbuf[tlvpos], len);
        if(status != LWM2M_STATUS_OK) {
          return status;
        }
        REST.set_response_status(ctx->response, CHANGED_2_04);
      }
      tlvpos += len;
    }
  }
  /* Here we have a success! */
  return LWM2M_STATUS_OK;
}

/*---------------------------------------------------------------------------*/
uint16_t
lwm2m_engine_recommend_instance_id(uint16_t object_id)
{
  lwm2m_object_instance_t *instance;
  uint16_t min_id = 0xffff;
  uint16_t max_id = 0;
  int found = 0;
  for(instance = list_head(object_list); instance != NULL ; instance = instance->next) {
    if(instance->object_id == object_id
       && instance->instance_id != LWM2M_OBJECT_INSTANCE_NONE) {
      found++;
      if(instance->instance_id > max_id) {
        max_id = instance->instance_id;
      }
      if(instance->instance_id < min_id) {
        min_id = instance->instance_id;
      }
    }
  }
  if(found == 0) {
    /* No existing instances found */
    return 0;
  }
  if(min_id > 0) {
    return min_id - 1;
  }
  return max_id + 1;
}
/*---------------------------------------------------------------------------*/
void
lwm2m_engine_add_object(lwm2m_object_instance_t *object)
{
  list_add(object_list, object);
}
/*---------------------------------------------------------------------------*/
void
lwm2m_engine_remove_object(lwm2m_object_instance_t *object)
{
  list_remove(object_list, object);
}
/*---------------------------------------------------------------------------*/
static lwm2m_object_instance_t *
lwm2m_engine_get_object_instance(const lwm2m_context_t *context)
{
  lwm2m_object_instance_t *i;
  for(i = list_head(object_list); i != NULL ; i = i->next) {
    if(i->object_id == context->object_id &&
       ((context->level < 2) || i->instance_id == context->object_instance_id)) {
      return i;
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
static lwm2m_object_instance_t *
lwm2m_engine_next_object_instance(const lwm2m_context_t *context, lwm2m_object_instance_t *last)
{
  while(last != NULL) {
    last = last->next;
    if(last != NULL && last->object_id == context->object_id &&
       ((context->level < 2) || last->instance_id == context->object_instance_id)) {
      return last;
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
static coap_handler_status_t
lwm2m_handler_callback(coap_packet_t *request, coap_packet_t *response,
                       uint8_t *buffer, uint16_t buffer_size, int32_t *offset)
{
  const char *url;
  int url_len;
  unsigned int format;
  unsigned int accept;
  int depth;
  lwm2m_context_t context;
  lwm2m_object_instance_t *instance;
  uint32_t bnum;
  uint8_t bmore;
  uint16_t bsize;
  uint32_t boffset;
  lwm2m_status_t success;
  lwm2m_buffer_t inbuf;
  lwm2m_buffer_t outbuf;

  /* Initialize the context */
  memset(&context, 0, sizeof(context));
  memset(&outbuf, 0, sizeof(outbuf));
  memset(&inbuf, 0, sizeof(inbuf));

  context.outbuf = &outbuf;
  context.inbuf = &inbuf;

  /* Set CoAP request/response for now */
  context.request = request;
  context.response = response;

  /* Set out buffer */
  context.outbuf->buffer = buffer;
  context.outbuf->size = buffer_size;

  /* Set input buffer */
  context.offset = offset != NULL ? *offset : 0;
  context.inbuf->size = coap_get_payload(request, (const uint8_t **) &context.inbuf->buffer);
  context.inbuf->pos = 0;

  /* Set default reader/writer */
  context.reader = &lwm2m_plain_text_reader;
  context.writer = &oma_tlv_writer;


  url_len = REST.get_url(request, &url);

  if(url_len == 2 && strncmp("bs", url, 2) == 0) {
    PRINTF("BOOTSTRAPPED!!!\n");
    REST.set_response_status(response, CHANGED_2_04);
    return COAP_HANDLER_STATUS_PROCESSED;
  }

  depth = lwm2m_engine_parse_context(url, url_len, request, response,
                                     buffer, buffer_size, &context);

  PRINTF("URL:'");
  PRINTS(url_len, url, "%c");
  PRINTF("' CTX:%u/%u/%u dp:%u bs:%d\n", context.object_id, context.object_instance_id,
	 context.resource_id, depth, buffer_size);
  /* Get format and accept */
  if(!REST.get_header_content_type(request, &format)) {
    PRINTF("lwm2m: No format given. Assume text plain...\n");
    format = TEXT_PLAIN;
  } else if(format == LWM2M_TEXT_PLAIN) {
    /* CoAP content format text plain - assume LWM2M text plain */
    format = TEXT_PLAIN;
  }
  if(!REST.get_header_accept(request, &accept)) {
    PRINTF("lwm2m: No Accept header, using same as Content-format %d\n",
           format);
    accept = format;
  }

  /**
   * 1 => Object only
   * 2 => Object and Instance
   * 3 => Object and Instance and Resource
   */
  if(depth < 1) {
    /* No possible object id found in URL - ignore request */
    if(REST.get_method_type(request) == METHOD_DELETE) {
      PRINTF("This is a delete all - for bootstrap...\n");
      context.operation = LWM2M_OP_DELETE;
      REST.set_response_status(response, DELETED_2_02);
#if USE_RD_CLIENT
      lwm2m_rd_client_set_update_rd();
#endif
      return COAP_HANDLER_STATUS_PROCESSED;
    }
    return COAP_HANDLER_STATUS_CONTINUE;
  }

  instance = lwm2m_engine_get_object_instance(&context);
  if(instance == NULL && REST.get_method_type(request) == METHOD_PUT) {
    /* ALLOW generic instance if CREATE / WRITE*/
    int iid = context.object_instance_id;
    context.object_instance_id = LWM2M_OBJECT_INSTANCE_NONE;
    instance = lwm2m_engine_get_object_instance(&context);
    context.object_instance_id = iid;
  }

  if(instance == NULL || instance->callback == NULL) {
    /* No matching object/instance found - ignore request */
    return COAP_HANDLER_STATUS_CONTINUE;
  }

  PRINTF("lwm2m Context: %u/%u/%u  found: %d\n",
         context.object_id,
         context.object_instance_id, context.resource_id, depth);
  /*
   * Select reader and writer based on provided Content type and
   * Accept headers.
   */
  lwm2m_engine_select_reader(&context, format);
  lwm2m_engine_select_writer(&context, accept);

  switch(REST.get_method_type(request)) {
  case METHOD_PUT:
    /* can also be write atts */
    context.operation = LWM2M_OP_WRITE;
    REST.set_response_status(response, CHANGED_2_04);
    break;
  case METHOD_POST:
    if(context.level < 2) {
      /* write to a instance */
      context.operation = LWM2M_OP_WRITE;
      REST.set_response_status(response, CHANGED_2_04);
    } else if(context.level == 3) {
      context.operation = LWM2M_OP_EXECUTE;
      REST.set_response_status(response, CHANGED_2_04);
    }
    break;
  case METHOD_GET:
    if(accept == APPLICATION_LINK_FORMAT) {
      context.operation = LWM2M_OP_DISCOVER;
    } else {
      context.operation = LWM2M_OP_READ;
    }
    REST.set_response_status(response, CONTENT_2_05);
    break;
  case METHOD_DELETE:
    context.operation = LWM2M_OP_DELETE;
    REST.set_response_status(response, DELETED_2_02);
#if USE_RD_CLIENT
    lwm2m_rd_client_set_update_rd();
#endif
    break;
  default:
    break;
  }

  /* Create might be made here - or anywhere at the write ? */
  if(instance->instance_id == LWM2M_OBJECT_INSTANCE_NONE &&
     context.level == 2 && context.operation == LWM2M_OP_WRITE) {
    if((instance = create_instance(&context, instance)) == NULL) {
      return COAP_HANDLER_STATUS_CONTINUE;
    }
  }

#if DEBUG
  /* for debugging */
  PRINTPRE("lwm2m: [", url_len, url);
  PRINTF("] %s Format:%d ID:%d bsize:%u offset:%d\n",
         get_method_as_string(REST.get_method_type(request)),
         format, context.object_id, buffer_size, (int) *offset);
  if(format == LWM2M_TEXT_PLAIN) {
    /* a string */
    const uint8_t *data;
    int plen = REST.get_request_payload(request, &data);
    if(plen > 0) {
      PRINTF("Data: '");
      PRINTS(plen, data, "%c");
      PRINTF("'\n");
    }
  }
#endif /* DEBUG */

  /* PUT/POST - e.g. write will not send in offset here - Maybe in the future? */
  if((offset != NULL && *offset == 0) &&
     IS_OPTION(request, COAP_OPTION_BLOCK1)) {
    coap_get_header_block1(request, &bnum, &bmore, &bsize, &boffset);
    context.offset = boffset;
  }

    /* This is a discovery operation */
  if(context.operation == LWM2M_OP_DISCOVER) {
    /* Assume only one disco at a time... */
    success = perform_multi_resource_read_op(instance, &context);
  } else if(context.operation == LWM2M_OP_READ) {
    PRINTF("Multi READ\n");
    success = perform_multi_resource_read_op(instance, &context);
  } else if(context.operation == LWM2M_OP_WRITE) {
    success = perform_multi_resource_write_op(instance, &context, format);
  } else {
    /* If not discovery - this is a regular OP - do the callback */
    success = instance->callback(instance, &context);
  }

  if(success == LWM2M_STATUS_OK) {
    /* Handle blockwise 1 */
    if(IS_OPTION(request, COAP_OPTION_BLOCK1)) {
      PRINTF("Setting BLOCK 1 num:%d o2:%d o:%d\n", (int) bnum, (int) boffset,
             (int) (offset != NULL ? *offset : 0));
      coap_set_header_block1(response, bnum, 0, bsize);
    }

    if(context.outbuf->len > 0) {
      PRINTPRE("lwm2m: [", url_len, url);
      PRINTF("] replying with %u bytes\n", context.outbuf->len);
      coap_set_payload(response, context.outbuf->buffer, context.outbuf->len);
      coap_set_header_content_format(response, context.content_type);

      if(offset != NULL) {
        PRINTF("Setting new offset: oo %d, no: %d\n", *offset, context.offset);
        if(context.writer_flags & WRITER_HAS_MORE) {
          *offset = context.offset;
        } else {
          /* this signals to CoAP that there is no more CoAP packets to expect */
          *offset = -1;
        }
      }
    } else {
      PRINTPRE("lwm2m: [", url_len, url);
      PRINTF("] no data in reply\n");
    }
  } else {
    if(success == LWM2M_STATUS_NOT_FOUND) {
      coap_set_status_code(response, NOT_FOUND_4_04);
    } else if(success == LWM2M_STATUS_OPERATION_NOT_ALLOWED) {
      coap_set_status_code(response, METHOD_NOT_ALLOWED_4_05);
    } else {
      /* Failed to handle the request */
      coap_set_status_code(response, INTERNAL_SERVER_ERROR_5_00);
    }
    PRINTPRE("lwm2m: [", url_len, url);
    PRINTF("] resource failed: %d\n", success);
  }
  return COAP_HANDLER_STATUS_PROCESSED;
}
/*---------------------------------------------------------------------------*/
void lwm2m_notify_object_observers(lwm2m_object_instance_t *obj,
                                   uint16_t resource)
{
  char path[20]; /* 60000/60000/60000 */
  if(obj != NULL) {
    snprintf(path, 20, "%d/%d/%d", obj->object_id, obj->instance_id, resource);
    PRINTF("Notify PATH: %s\n", path);
    coap_notify_observers_sub(NULL, path);
  }
}
/*---------------------------------------------------------------------------*/
/** @} */
