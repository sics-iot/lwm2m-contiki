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


void lwm2m_device_init(void);
void lwm2m_security_init(void);
void lwm2m_server_init(void);

static int lwm2m_handler_callback(coap_packet_t *request,
                                  coap_packet_t *response,
                                  uint8_t *buffer, uint16_t buffer_size,
                                  int32_t *offset);
static lwm2m_object_instance_t *
lwm2m_engine_next_object_instance(const lwm2m_context_t *context, lwm2m_object_instance_t *last);


COAP_HANDLER(lwm2m_handler, lwm2m_handler_callback);
LIST(object_list);

static char endpoint[32];
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

static int
append_reg_tag(uint8_t *rd_data, size_t size, int oid, int iid, int rid)
{
  int pos = 0;
  rd_data[pos++] = '<';
  pos += u16toa(&rd_data[pos], oid);
  if(iid > -1 && size > pos) {
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
/*--------------------------------------------------------------------------*/
static int
lwm2m_engine_parse_context(const char *path, int path_len,
                           coap_packet_t *request, coap_packet_t *response,
                           uint8_t *outbuf, size_t outsize,
                           lwm2m_context_t *context)
{
  int len;
  int ret;
  int pos;
  uint16_t val;
  char c;
  if(context == NULL || path == NULL) {
    return 0;
  }

  memset(context, 0, sizeof(lwm2m_context_t));

  /* Set CoAP request/response for now */
  context->request = request;
  context->response = response;

  /* Set out buffer */
  context->outbuf = outbuf;
  context->outsize = outsize;

  /* Set default reader/writer */
  context->reader = &lwm2m_plain_text_reader;
  context->writer = &oma_tlv_writer;

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
      if(ret == 0) context->object_id = val;
      if(ret == 1) context->object_instance_id = val;
      if(ret == 2) context->resource_id = val;
      ret++;
      pos++;
    } else {
      PRINTF("Error: illegal char '%c' at pos:%d\n", c, pos);
      return -1;
    }
  } while(pos < path_len);
  

  if(ret > 0) {
    context->level = ret;
  }

  return ret;
}
/*---------------------------------------------------------------------------*/
int
lwm2m_engine_get_rd_data(uint8_t *rd_data, int size) {
  lwm2m_object_instance_t *o;
  int pos;
  int len, i, j;

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

  snprintf(endpoint, sizeof(endpoint) - 1,
           "?ep=" LWM2M_ENGINE_CLIENT_ENDPOINT_NAME);

#else /* LWM2M_ENGINE_CLIENT_ENDPOINT_NAME */

  int len, i;
  uint8_t state;
  uip_ipaddr_t *ipaddr;
  char client[sizeof(endpoint)];

  len = strlen(LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX);
  /* ensure that this fits with the hex-nums */
  if(len > sizeof(client) - 13) {
    len = sizeof(client) - 13;
  }
  memcpy(client, LWM2M_ENGINE_CLIENT_ENDPOINT_PREFIX, len);

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
      client[len++] = (b >> 4) > 9 ? 'A' - 10 + (b >> 4) : '0' + (b >> 4);
      client[len++] = (b & 0xf) > 9 ? 'A' - 10 + (b & 0xf) : '0' + (b & 0xf);
    }
  }

  /* a zero at end of string */
  client[len] = 0;
  /* create endpoint */
  snprintf(endpoint, sizeof(endpoint) - 1, "?ep=%s", client);

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
  //  lwm2m_security_init();
  //  lwm2m_server_init();
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

static int
perform_multi_resource_op(lwm2m_object_instance_t *instance,
                          lwm2m_context_t *ctx)
{
  int pos = 0;
  int size = ctx->outsize;
  int len = 0;
  uint8_t initialized = 0; /* used for commas, etc */

  if(ctx->offset == 0) {
    last_ins = instance;
    last_rsc_pos = 0;
    /* Here we should print top node */
  } else {
    /* offset > 0 - assume that we are already in a disco or multi get*/
    instance = last_ins;
    if(last_ins == NULL) {
      ctx->offset = -1;
      ctx->outbuf[0] = ' ';
      pos = 1;
    }
  }

  if(ctx->operation == LWM2M_OP_DISCOVER) {
    PRINTF("DISCO - o:%d s:%d lsr:%d lv:%d\n", ctx->offset, size, last_rsc_pos, ctx->level);
  }
  while(instance != NULL) {
    /* Do the discovery */
    /* Just object this time... */
    if(instance->resource_ids != NULL && instance->resource_count > 0) {
      /* show all the available resources (or read all) */
      while(last_rsc_pos < instance->resource_count) {
        if(ctx->level < 3 || ctx->resource_id == instance->resource_ids[last_rsc_pos]) {
          if(ctx->operation == LWM2M_OP_DISCOVER) {
            len = snprintf((char *) &ctx->outbuf[pos], size - pos,
                           pos == 0 && ctx->offset == 0 ? "</%d/%d/%d>":",</%d/%d/%d>",
                           instance->object_id, instance->instance_id, instance->resource_ids[last_rsc_pos]);
            if(len < 0 || len + pos >= size) {
              /* ok we trunkated here... */
              ctx->offset += pos;
              ctx->outlen = pos;
              return 1;
            }
            pos += len;
          } else if(ctx->operation == LWM2M_OP_READ) {
            uint8_t lv;
            uint8_t success;
            lv = ctx->level;
            /* Set the resource ID is ctx->level < 3 */
            if(lv < 3) {
              ctx->resource_id = instance->resource_ids[last_rsc_pos];
            }
            if(lv < 2) {
              ctx->object_instance_id = instance->instance_id;
            }
            ctx->level = 3;
            if(!initialized) {
              len = ctx->writer->init_write(ctx);
              ctx->outlen += len;
              PRINTF("INIT WRITE len:%d\n", len);
              initialized = 1;
            }

            success = instance->callback(instance, ctx);

            /* We will need to handle no-success and other things */
            PRINTF("Called %u/%u/%u outlen:%u ok:%u\n",
                   ctx->object_id, ctx->object_instance_id,ctx->resource_id,
                   ctx->outlen, success);

            /* we need to handle full buffer, etc here also! */
            ctx->level = lv;
            pos = ctx->outlen;
          }
        }
        last_rsc_pos++;
      }
    }
    instance = lwm2m_engine_next_object_instance(ctx, instance);
    last_ins = instance;
    if(ctx->operation == LWM2M_OP_READ) {
      PRINTF("END Writer\n");
      len = ctx->writer->end_write(ctx);
      ctx->outlen += len;
      pos = ctx->outlen;
    }

    initialized = 0;
    last_rsc_pos = 0;
  }
  /* seems like we are done! */
  ctx->offset=-1;
  ctx->outlen = pos;
  return 1;
}
/*---------------------------------------------------------------------------*/
uint16_t
lwm2m_engine_recommend_instance_id(uint16_t object_id)
{
  lwm2m_object_instance_t *i;
  uint16_t min_id = 0xffff;
  uint16_t max_id = 0;
  int found = 0;
  for(i = list_head(object_list); i != NULL ; i = i->next) {
    if(i->object_id == object_id
       && i->instance_id != LWM2M_OBJECT_INSTANCE_NONE) {
      found++;
      if(i->instance_id > max_id) {
        max_id = i->instance_id;
      }
      if(i->instance_id < min_id) {
        min_id = i->instance_id;
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
static int
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
  uint8_t success = 1; /* the success boolean */

  url_len = REST.get_url(request, &url);
  depth = lwm2m_engine_parse_context(url, url_len, request, response,
                                     buffer, buffer_size, &context);

  PRINTF("URL:");
  PRINTS(url_len, url, "%c");
  PRINTF(" CTX:%u/%u/%u\n", context.object_id, context.object_instance_id,
	 context.resource_id);
  /* Get format and accept */
  if(!REST.get_header_content_type(request, &format)) {
    PRINTF("lwm2m: No format given. Assume text plain...\n");
    format = TEXT_PLAIN;
  } else if(format == LWM2M_TEXT_PLAIN) {
    /* CoAP content format text plain - assume LWM2M text plain */
    format = TEXT_PLAIN;
  }
  if(!REST.get_header_accept(request, &accept)) {
    PRINTF("lwm2m: No Accept header, using same as Content-format...\n");
    accept = format;
  }

  /**
   * 1 => Object only
   * 2 => Object and Instance
   * 3 => Object and Instance and Resource
   */
  if(depth < 1) {
    /* No possible object id found in URL - ignore request */
    return 0;
  }

  instance = lwm2m_engine_get_object_instance(&context);
  if(instance == NULL || instance->callback == NULL) {
    /* No matching object/instance found - ignore request */
    return 0;
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
    if(context.level == 2) {
      /* write to a instance */
      context.operation = LWM2M_OP_WRITE;
      REST.set_response_status(response, CHANGED_2_04);
    } else if(context.level == 3) {
      context.operation = LWM2M_OP_EXECUTE;
      REST.set_response_status(response, CHANGED_2_04);
    }
    break;
  case METHOD_GET:
    /* Assuming that we haev already taken care of discovery... it will be read q*/
    if(accept == APPLICATION_LINK_FORMAT) {
      context.operation = LWM2M_OP_DISCOVER;
    } else {
      context.operation = LWM2M_OP_READ;
    }
    REST.set_response_status(response, CONTENT_2_05);
    break;
  default:
    break;
  }

#if DEBUG
  /* for debugging */
  PRINTPRE("lwm2m: [", url_len, url);
  PRINTF("] %s Format:%d ID:%d bsize:%u\n",
         get_method_as_string(REST.get_method_type(request)),
         format, context.object_id, buffer_size);
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

  context.offset = offset != NULL ? *offset : 0;
  context.insize = coap_get_payload(request, (const uint8_t **) &context.inbuf);
  context.inpos = 0;

  /* PUT/POST - e.g. write will not send in offset here - Maybe in the future? */
  if((offset != NULL && *offset == 0) &&
     IS_OPTION(request, COAP_OPTION_BLOCK1)) {
    coap_get_header_block1(request, &bnum, &bmore, &bsize, &boffset);
    context.offset = boffset;
  }

    /* This is a discovery operation */
  if(context.operation == LWM2M_OP_DISCOVER) {
    /* Assume only one disco at a time... */
    success = perform_multi_resource_op(instance, &context);
  } else if (context.operation == LWM2M_OP_READ) {
    PRINTF("Multi GET\n");
    success = perform_multi_resource_op(instance, &context);
  } else {
    /* If not discovery or create - this is a regular OP - do the callback */
    success = instance->callback(instance, &context);
  }

  if(success) {
    /* Handle blockwise 1 */
    if(IS_OPTION(request, COAP_OPTION_BLOCK1)) {
      PRINTF("Setting BLOCK 1 num:%d o2:%d o:%d\n", bnum, boffset,
             (offset != NULL ? *offset : 0));
      coap_set_header_block1(response, bnum, 0, bsize);
    }

    if(context.outlen > 0) {
      PRINTPRE("lwm2m: [", url_len, url);
      PRINTF("] replying with %u bytes\n", context.outlen);
      REST.set_response_payload(response, context.outbuf, context.outlen);
      REST.set_header_content_type(response, context.content_type);

      if(offset != NULL) {
        *offset = context.offset;
      }
    } else {
      PRINTPRE("lwm2m: [", url_len, url);
      PRINTF("] no data in reply\n");
    }
  } else {
    /* Failed to handle the request */
    REST.set_response_status(response, INTERNAL_SERVER_ERROR_5_00);
    PRINTPRE("lwm2m: [", url_len, url);
    PRINTF("] resource failed\n");
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
/** @} */
