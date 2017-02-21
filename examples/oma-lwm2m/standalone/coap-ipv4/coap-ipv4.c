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
 *         A native IPv4 transport for CoAP
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "er-coap.h"
#include "er-coap-endpoint.h"
#include "er-coap-engine.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define DEBUG 1
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTEP(ep) coap_endpoint_print(ep)
#else
#define PRINTF(...)
#define PRINTEP(ep)
#endif

#if WITH_DTLS
#include "tinydtls.h"
#include "dtls.h"
#include "dtls_debug.h"
#endif /* WITH_DTLS */

#define BUFSIZE 1280

typedef union {
  uint32_t u32[(BUFSIZE + 3) / 4];
  uint8_t u8[BUFSIZE];
} coap_buf_t;

static int coap_ipv4_fd = -1;

static coap_endpoint_t last_source;
static coap_buf_t coap_aligned_buf;
static uint16_t coap_buf_len;

#if WITH_DTLS
static dtls_context_t *dtls_context = NULL;
static dtls_handler_t cb;
#endif

/*---------------------------------------------------------------------------*/
static const coap_endpoint_t *
coap_src_endpoint(void)
{
  return &last_source;
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_is_secure(const coap_endpoint_t *ep)
{
  return ep->secure;
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_is_connected(const coap_endpoint_t *ep)
{
  if(ep->secure) {
#if WITH_DTLS
    session_t session;
    dtls_peer_t *peer;
    memset(&session, 0, sizeof(session));
    memcpy(&session.addr, &ep->addr, ep->addr_len);
    session.size = ep->addr_len;
    peer = dtls_get_peer(dtls_context, &session);
    if(peer != NULL) {
      /* only if handshake is done! */
      return dtls_peer_is_connected(peer);
    }
#endif /* WITH_DTLS */
    return 0;
  }
  /* Assume that the UDP socket is already up... */
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_connect(coap_endpoint_t *ep)
{
  if(ep->secure == 0) {
    return 1;
  }
#if WITH_DTLS
  session_t dst; /* needs to be updated to ipv4 coap endpoint */
  memset(&dst, 0, sizeof(session_t));

  memcpy(&dst.addr, &ep->addr, sizeof(ep->addr));

  PRINTF("DTLS EP:");
  PRINTEP(ep);
  PRINTF("\n");

  dst.size = ep->addr_len;
  /* setup all address info here... should be done to connect */

  dtls_connect(dtls_context, &dst);
#endif
  return 1;
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_disconnect(coap_endpoint_t *ep)
{
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_copy(coap_endpoint_t *destination, const coap_endpoint_t *from)
{
  memcpy(destination, from, sizeof(coap_endpoint_t));
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_cmp(const coap_endpoint_t *e1, const coap_endpoint_t *e2)
{
  return memcmp(e1, e2, sizeof(coap_endpoint_t)) == 0;
}
/*---------------------------------------------------------------------------*/
void
coap_endpoint_print(const coap_endpoint_t *ep)
{
  const char *address;
  address = inet_ntoa(ep->addr.sin_addr);
  if(address != NULL) {
    printf("coap%s://%s:%u",ep->secure ? "s":"",
           address, ntohs(ep->addr.sin_port));
  } else {
    printf("<#N/A>");
  }
}
/*---------------------------------------------------------------------------*/
int
coap_endpoint_parse(const char *text, size_t size, coap_endpoint_t *ep)
{
  /* text = format coap://host:port/... we assume */
  /* will not work for know - on the TODO */
  /* set server and port */
  char host[32];
  uint16_t port;
  int hlen = 0;
  int secure;
  int offset = 0;
  int i;
  PRINTF("CoAP-IPv4: Parsing endpoint: %.*s\n", (int)size, text);
  if(strncmp("coap://", text, 7) == 0) {
    secure = 0;
    offset = 7;
    PRINTF("COAP found\n");
  } else if(strncmp("coaps://", text, 8) == 0) {
    secure = 1;
    offset = 8;
    PRINTF("COAPS found\n");
  } else {
    secure = 0;
  }

  for(i = offset; i < size && text[i] != ':' && text[i] != '/' &&
        hlen < sizeof(host) - 1; i++) {
    host[hlen++] = text[i];
  }
  host[hlen] = 0;

  port = secure == 0 ? COAP_DEFAULT_PORT : COAP_DEFAULT_SECURE_PORT;
  if(text[i] == ':') {
    /* Parse IPv4 endpoint port */
    port = atoi(&text[i + 1]);
  }

  PRINTF("CoAP-IPv4: endpoint %s:%u\n", host, port);

  ep->addr.sin_family = AF_INET;
  ep->addr.sin_port = htons(port);
  ep->addr_len = sizeof(ep->addr);
  ep->secure = secure;
  if(inet_aton(host, &ep->addr.sin_addr) == 0) {
    /* Failed to parse the address */
    PRINTF("CoAP-IPv4: Failed to parse endpoint host '%s'\n", host);
    return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
uint8_t *
coap_databuf(void)
{
  return coap_aligned_buf.u8;
}
/*---------------------------------------------------------------------------*/
uint16_t
coap_datalen()
{
  return coap_buf_len;
}
/*---------------------------------------------------------------------------*/
static int
coap_ipv4_set_fd(fd_set *rset, fd_set *wset)
{
  if(coap_ipv4_fd >= 0) {
    FD_SET(coap_ipv4_fd, rset);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
coap_ipv4_handle_fd(fd_set *rset, fd_set *wset)
{
  int len;
#if WITH_DTLS
  session_t session;
  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
#endif /* WITH_DTLS */

  if(coap_ipv4_fd < 0) {
    return;
  }
  if(!FD_ISSET(coap_ipv4_fd, rset)) {
    return;
  }

  last_source.addr_len = sizeof(last_source.addr);
  len = recvfrom(coap_ipv4_fd, coap_databuf(), BUFSIZE, 0,
                 (struct sockaddr *)&last_source.addr, &last_source.addr_len);
  if(len == -1) {
    if(errno == EAGAIN) {
      return;
    }
    err(1, "CoAP-IPv4: recv");
    return;
  }
  PRINTF("RECV from ");
  PRINTEP(&last_source);
  PRINTF(" %u bytes\n", len);
  coap_buf_len = len;

  if(DEBUG) {
    int i;
    uint8_t *data;
    data = coap_databuf();
    PRINTF("Received:");
    for(i = 0; i < len; i++) {
      PRINTF("%02x", data[i]);
    }
    PRINTF("\n");
  }

#if WITH_DTLS
  /* DTLS receive??? */
  memcpy(&session.addr, &last_source, last_source.addr_len);
  session.size = last_source.addr_len;

  dtls_handle_message(dtls_context, &session, coap_databuf(), coap_datalen());
#else
  coap_receive(coap_src_endpoint(), coap_databuf(), coap_datalen());
#endif
}
/*---------------------------------------------------------------------------*/
static const struct select_callback udp_callback = {
  coap_ipv4_set_fd, coap_ipv4_handle_fd
};
/*---------------------------------------------------------------------------*/
void
coap_transport_init(void)
{
  static struct sockaddr_in server;


  dtls_set_log_level(8);

  coap_ipv4_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(coap_ipv4_fd == -1) {
    fprintf(stderr, "Could not create CoAP UDP socket\n");
    exit(1);
    return;
  }

  memset((void *)&server, 0, sizeof(server));

  server.sin_family = AF_INET;
  server.sin_port = htons(COAP_SERVER_PORT);
  server.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(coap_ipv4_fd, (struct sockaddr *)&server, sizeof(server)) == -1) {
    PRINTF("Could not bind CoAP UDP port to %u\n", COAP_SERVER_PORT);
    exit(1);
  }

  printf("CoAP server listening on port %u\n", COAP_SERVER_PORT);
  select_set_callback(coap_ipv4_fd, &udp_callback);

#if WITH_DTLS
  /* create new contet with app-data */
  dtls_context = dtls_new_context(&coap_ipv4_fd);
  if (!dtls_context) {
    PRINTF("DTLS: cannot create context\n");
    exit(-1);
  }

  dtls_set_handler(dtls_context, &cb);
#endif

}
/*---------------------------------------------------------------------------*/
void
coap_send_message(const coap_endpoint_t *ep, const uint8_t *data, uint16_t len)
{
  if(coap_endpoint_is_connected(ep)) {
    PRINTF("CoAP endpoint not connected\n");
    return;
  }
  if(coap_ipv4_fd >= 0) {
    if(sendto(coap_ipv4_fd, data, len, 0,
              (struct sockaddr *)&ep->addr, ep->addr_len) < 1) {
      PRINTF("failed to send to ");
      PRINTEP(ep);
      PRINTF(" %u bytes: %s\n", len, strerror(errno));
    } else {
      PRINTF("SENT to ");
      PRINTEP(ep);
      PRINTF(" %u bytes\n", len);

      if(DEBUG) {
        int i;
        PRINTF("Sent:");
        for(i = 0; i < len; i++) {
          PRINTF("%02x", data[i]);
        }
        PRINTF("\n");
      }
    }
  }
}
/* DTLS */
#if WITH_DTLS

/* This is input coming from the DTLS code - e.g. de-crypted input from
   the other side - peer */
static int
input_from_peer(struct dtls_context_t *ctx,
                session_t *session, uint8 *data, size_t len)
{
  size_t i;
  printf("received data:");
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  printf("\n");

  /* Send this into coap-input */
  memmove(coap_databuf(), data, len);
  coap_buf_len = len;
  coap_receive(coap_src_endpoint(), coap_databuf(), coap_datalen());

  return 0;
}

/* This is output from the DTLS code to be sent to peer (encrypted) */
static int
output_to_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len)
{
  int fd = *(int *)dtls_get_app_data(ctx);
  printf("output_to_peer len:%d %d (s-size: %d)\n", (int) len, fd,
         session->size);
  return sendto(fd, data, len, MSG_DONTWAIT,
		&session->addr.sa, session->size);
}


/* The PSK information for DTLS */
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static size_t psk_id_length = 0;
static unsigned char psk_key[PSK_MAXLEN];
static size_t psk_key_length = 0;

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx,
             const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length)
{

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (id_len) {
      dtls_debug("got psk_identity_hint: '%.*s'\n", id_len, id);
    }

    if (result_length < psk_id_length) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      dtls_warn("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      dtls_warn("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    dtls_warn("unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}


static dtls_handler_t cb = {
  .write = output_to_peer,
  .read  = input_from_peer,
  .event = NULL,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  /* .get_ecdsa_key = get_ecdsa_key, */
  /* .verify_ecdsa_key = verify_ecdsa_key */
#endif /* DTLS_ECC */
};

#endif /* WITH_DTLS */


/*---------------------------------------------------------------------------*/
