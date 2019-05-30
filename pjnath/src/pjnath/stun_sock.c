/* $Id$ */
/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
#include <pjnath/stun_sock.h>
#include <pjnath/errno.h>
#include <pjnath/stun_transaction.h>
#include <pjlib-util/srv_resolver.h>
#include <pj/activesock.h>
#include <pj/addr_resolv.h>
#include <pj/array.h>
#include <pj/assert.h>
#include <pj/ip_helper.h>
#include <pj/log.h>
#include <pj/os.h>
#include <pj/pool.h>
#include <pj/rand.h>

#if 1
#  define TRACE_(x)	PJ_LOG(5,x)
#else
#  define TRACE_(x)
#endif

enum { MAX_BIND_RETRY = 100 };

#if PJ_HAS_TCP
// The head of a RTP packet is stored in a 16 bits header, so the max size of a
// packet is 65536
#define MAX_RTP_SIZE 65536
#endif

// TODO (sblin) The incoming socks are a bit HACKY for now.
// Need a better approach
typedef struct outgoing_sock {
  pj_sock_t           fd;
  pj_activesock_t    *sock;
  pj_sockaddr_t      *addr;
} outgoing_sock;

typedef struct incoming_sock {
  pj_sock_t           fd;
  pj_activesock_t    *sock;
  pj_sockaddr         addr;
  int                 addr_len;
} incoming_sock;

typedef struct pj_stun_sock {
  char *obj_name;          /* Log identification         */
  pj_pool_t *pool;         /* Pool                       */
  void *user_data;         /* Application user data      */
  pj_bool_t is_destroying; /* Destroy already called     */
  int af;                  /* Address family             */
  pj_stun_tp_type conn_type;
  pj_stun_sock_cfg setting;
  pj_stun_config cfg; /* STUN config (ioqueue etc)  */
  pj_stun_sock_cb cb; /* Application callbacks      */

  int ka_interval;         /* Keep alive interval        */
  pj_timer_entry ka_timer; /* Keep alive timer.          */

  pj_sockaddr srv_addr;    /* Resolved server addr       */
  pj_sockaddr mapped_addr; /* Our public address         */

  pj_dns_srv_async_query *q;  /* Pending DNS query          */
  pj_sock_t main_sock_fd;     /* Socket descriptor          */
  pj_activesock_t *main_sock; /* Active socket object       */
#if PJ_HAS_TCP
  int              outgoing_nb;
  outgoing_sock    outgoing_socks[PJ_ICE_MAX_CHECKS];
  int              incoming_nb;
  incoming_sock    incoming_socks[PJ_ICE_MAX_CHECKS];
  pj_uint8_t       rx_buffer[MAX_RTP_SIZE];
  pj_uint16_t      rx_buffer_size;
  pj_uint16_t      rx_wanted_size;
#endif
  pj_ioqueue_op_key_t send_key;     /* Default send key for app   */
  pj_ioqueue_op_key_t int_send_key; /* Send key for internal      */

  pj_uint16_t tsx_id[6];      /* .. to match STUN msg       */
  pj_stun_session *stun_sess; /* STUN session               */
  pj_grp_lock_t *grp_lock;    /* Session group lock         */
} pj_stun_sock;

/* 
 * Prototypes for static functions 
 */

static pj_bool_t on_stun_sock_ready(pj_activesock_t *asock, pj_status_t status);

static pj_bool_t on_stun_sock_accept(pj_activesock_t *asock, pj_sock_t newsock,
                                     const pj_sockaddr_t *src_addr,
                                     int src_addr_len);

pj_bool_t on_connect_complete(pj_activesock_t *asock, pj_status_t status);

/* Destructor for group lock */
static void stun_sock_destructor(void *obj);

/* This callback is called by the STUN session to send packet */
pj_status_t sess_on_send_msg(pj_stun_session *sess,
				    void *token,
				    const void *pkt,
				    pj_size_t pkt_size,
				    const pj_sockaddr_t *dst_addr,
				    unsigned addr_len);

static pj_bool_t sess_fail(pj_stun_sock *stun_sock, pj_stun_sock_op op,
                           pj_status_t status);

/* This callback is called by the STUN session when outgoing transaction 
 * is complete
 */
void sess_on_request_complete(pj_stun_session *sess,
				     pj_status_t status,
				     void *token,
				     pj_stun_tx_data *tdata,
				     const pj_stun_msg *response,
				     const pj_sockaddr_t *src_addr,
				     unsigned src_addr_len);
/* DNS resolver callback */
static void dns_srv_resolver_cb(void *user_data,
				pj_status_t status,
				const pj_dns_srv_record *rec);

/* Start sending STUN Binding request */
static pj_status_t get_mapped_addr(pj_stun_sock *stun_sock);

/* Callback from active socket when incoming packet is received */
pj_bool_t on_data_recvfrom(pj_activesock_t *asock,
				  void *data,
				  pj_size_t size,
				  const pj_sockaddr_t *src_addr,
				  int addr_len,
				  pj_status_t status);

/* Callback from active socket about send status */
pj_bool_t on_data_sent(pj_activesock_t *asock,
			      pj_ioqueue_op_key_t *send_key,
			      pj_ssize_t sent);

/* Schedule keep-alive timer */
void start_ka_timer(pj_stun_sock *stun_sock);

/* Keep-alive timer callback */
void ka_timer_cb(pj_timer_heap_t *th, pj_timer_entry *te);

#define INTERNAL_MSG_TOKEN  (void*)(pj_ssize_t)1


/*
 * Retrieve the name representing the specified operation.
 */
PJ_DEF(const char*) pj_stun_sock_op_name(pj_stun_sock_op op)
{
    const char *names[] = {
	"?",
	"DNS resolution",
	"STUN Binding request",
	"Keep-alive",
	"Mapped addr. changed"
    };

    return op < PJ_ARRAY_SIZE(names) ? names[op] : "???";
}


/*
 * Initialize the STUN transport setting with its default values.
 */
PJ_DEF(void) pj_stun_sock_cfg_default(pj_stun_sock_cfg *cfg)
{
    pj_bzero(cfg, sizeof(*cfg));
    cfg->max_pkt_size = PJ_STUN_SOCK_PKT_LEN;
    cfg->async_cnt = 1;
    cfg->ka_interval = PJ_STUN_KEEP_ALIVE_SEC;
    cfg->qos_type = PJ_QOS_TYPE_BEST_EFFORT;
    cfg->qos_ignore_error = PJ_TRUE;
}


/* Check that configuration setting is valid */
static pj_bool_t pj_stun_sock_cfg_is_valid(const pj_stun_sock_cfg *cfg)
{
    return cfg->max_pkt_size > 1 && cfg->async_cnt >= 1;
}

/*
 * Initialize.
 */
PJ_DEF(pj_status_t) pj_stun_sock_alloc(pj_stun_sock *stun_sock) {
  pj_status_t status;
  pj_sockaddr bound_addr;
  pj_uint16_t max_bind_retry;
  int sock_type;

  pj_grp_lock_acquire(stun_sock->grp_lock);

  if (stun_sock->conn_type == PJ_STUN_TP_UDP)
    sock_type = pj_SOCK_DGRAM();
  else
    sock_type = pj_SOCK_STREAM();

  stun_sock->ka_interval = stun_sock->setting.ka_interval;
  if (stun_sock->ka_interval == 0)
    stun_sock->ka_interval = PJ_STUN_KEEP_ALIVE_SEC;
  /* Create socket and bind socket */
  status =
      pj_sock_socket(stun_sock->af, sock_type, 0, &stun_sock->main_sock_fd);
  if (status != PJ_SUCCESS) {
    pj_stun_sock_destroy(stun_sock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
  }

  /* Apply QoS, if specified */
  status = pj_sock_apply_qos2(
      stun_sock->main_sock_fd, stun_sock->setting.qos_type,
      &stun_sock->setting.qos_params, 2, stun_sock->obj_name, NULL);
  if (status != PJ_SUCCESS && !stun_sock->setting.qos_ignore_error) {
    pj_stun_sock_destroy(stun_sock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
  }

  /* Apply socket buffer size */
  if (stun_sock->setting.so_rcvbuf_size > 0) {
    unsigned sobuf_size = stun_sock->setting.so_rcvbuf_size;
    status = pj_sock_setsockopt_sobuf(stun_sock->main_sock_fd, pj_SO_RCVBUF(),
                                      PJ_TRUE, &sobuf_size);
    if (status != PJ_SUCCESS) {
      pj_perror(3, stun_sock->obj_name, status, "Failed setting SO_RCVBUF");
    } else {
      if (sobuf_size < stun_sock->setting.so_rcvbuf_size) {
        PJ_LOG(4, (stun_sock->obj_name,
                   "Warning! Cannot set SO_RCVBUF as configured, "
                   "now=%d, configured=%d",
                   sobuf_size, stun_sock->setting.so_rcvbuf_size));
      } else {
        PJ_LOG(5, (stun_sock->obj_name, "SO_RCVBUF set to %d", sobuf_size));
      }
    }
  }
  if (stun_sock->setting.so_sndbuf_size > 0) {
    unsigned sobuf_size = stun_sock->setting.so_sndbuf_size;
    status = pj_sock_setsockopt_sobuf(stun_sock->main_sock_fd, pj_SO_SNDBUF(),
                                      PJ_TRUE, &sobuf_size);
    if (status != PJ_SUCCESS) {
      pj_perror(3, stun_sock->obj_name, status, "Failed setting SO_SNDBUF");
    } else {
      if (sobuf_size < stun_sock->setting.so_sndbuf_size) {
        PJ_LOG(4, (stun_sock->obj_name,
                   "Warning! Cannot set SO_SNDBUF as configured, "
                   "now=%d, configured=%d",
                   sobuf_size, stun_sock->setting.so_sndbuf_size));
      } else {
        PJ_LOG(5, (stun_sock->obj_name, "SO_SNDBUF set to %d", sobuf_size));
      }
    }
  }

  /* Bind socket */
  max_bind_retry = MAX_BIND_RETRY;
  if (stun_sock->setting.port_range &&
      stun_sock->setting.port_range < max_bind_retry)
    max_bind_retry = stun_sock->setting.port_range;
  pj_sockaddr_init(stun_sock->af, &bound_addr, NULL, 0);
  if (stun_sock->setting.bound_addr.addr.sa_family == pj_AF_INET() ||
      stun_sock->setting.bound_addr.addr.sa_family == pj_AF_INET6()) {
    pj_sockaddr_cp(&bound_addr, &stun_sock->setting.bound_addr);
  }
  status = pj_sock_bind_random(stun_sock->main_sock_fd, &bound_addr,
                               stun_sock->setting.port_range, max_bind_retry);
  if (status != PJ_SUCCESS) {
    pj_stun_sock_destroy(stun_sock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
  }

  /* Init active socket configuration */
  {
    pj_activesock_cfg activesock_cfg;
    pj_activesock_cb activesock_cb;

    pj_activesock_cfg_default(&activesock_cfg);
    activesock_cfg.grp_lock = stun_sock->grp_lock;
    activesock_cfg.async_cnt = stun_sock->setting.async_cnt;
    activesock_cfg.concurrency = 0;

    /* Create the active socket */
    pj_bzero(&activesock_cb, sizeof(activesock_cb));
    activesock_cb.on_data_sent = &on_data_sent;
    activesock_cb.on_data_recvfrom = &on_data_recvfrom;

#if PJ_HAS_TCP
    if (stun_sock->conn_type != PJ_STUN_TP_UDP) {
      activesock_cb.on_accept_complete = &on_stun_sock_accept;
      // Will be ready to accept incoming connections from the external world
      status = pj_sock_listen(stun_sock->main_sock_fd, PJ_SOMAXCONN);
      if (status != PJ_SUCCESS) {
        pj_stun_sock_destroy(stun_sock);
        pj_grp_lock_release(stun_sock->grp_lock);
        return status;
      }
    } else {
      activesock_cb.on_connect_complete = &on_stun_sock_ready;
    }
#else
    activesock_cb.on_connect_complete = &on_stun_sock_ready;
#endif

    status =
        pj_activesock_create(stun_sock->pool, stun_sock->main_sock_fd,
                             sock_type, &activesock_cfg, stun_sock->cfg.ioqueue,
                             &activesock_cb, stun_sock, &stun_sock->main_sock);

    if (status != PJ_SUCCESS) {
      pj_stun_sock_destroy(stun_sock);
      pj_grp_lock_release(stun_sock->grp_lock);
      return status;
    }

#if PJ_HAS_TCP
    if (stun_sock->conn_type != PJ_STUN_TP_UDP) {
      status =
          pj_activesock_start_accept(stun_sock->main_sock, stun_sock->pool);
    } else {
      status = PJ_SUCCESS;
    }
    if (status == PJ_SUCCESS) {
      on_stun_sock_ready(stun_sock->main_sock, PJ_SUCCESS);
    } else if (status != PJ_EPENDING) {
      char addrinfo[PJ_INET6_ADDRSTRLEN + 10];
      pj_perror(3, stun_sock->pool->obj_name, status, "Failed to connect to %s",
                pj_sockaddr_print(&bound_addr, addrinfo, sizeof(addrinfo), 3));
      pj_stun_sock_destroy(stun_sock);
      pj_grp_lock_release(stun_sock->grp_lock);
      return status;
    }
#else
    on_stun_sock_ready(stun_sock->main_sock, PJ_SUCCESS);
#endif
  }

  pj_grp_lock_release(stun_sock->grp_lock);
  return status;
}

/*
 * Create the STUN transport using the specified configuration.
 */
PJ_DEF(pj_status_t) pj_stun_sock_create( pj_stun_config *cfg,
                                         const char *name,
                                         int af,
                                         pj_stun_tp_type conn_type,
                                         const pj_stun_sock_cb *cb,
                                         const pj_stun_sock_cfg *setting,
                                         void *user_data,
pj_stun_sock **p_stun_sock)
{
  pj_stun_sock *stun_sock;
  pj_stun_sock_cfg default_cfg;
  pj_pool_t *pool;
  pj_status_t status;

  PJ_ASSERT_RETURN(cfg && cb && p_stun_sock, PJ_EINVAL);
  PJ_ASSERT_RETURN(af == pj_AF_INET() || af == pj_AF_INET6(), PJ_EAFNOTSUP);
  PJ_ASSERT_RETURN(!setting || pj_stun_sock_cfg_is_valid(setting), PJ_EINVAL);
  PJ_ASSERT_RETURN(cb->on_status, PJ_EINVAL);
  PJ_ASSERT_RETURN(conn_type != PJ_STUN_TP_TCP || PJ_HAS_TCP, PJ_EINVAL);

  status = pj_stun_config_check_valid(cfg);
  if (status != PJ_SUCCESS)
    return status;

  if (!setting) {
    pj_stun_sock_cfg_default(&default_cfg);
    setting = &default_cfg;
  }

  if (!name) {
    switch (conn_type) {
    case PJ_STUN_TP_UDP:
      name = "udpstun%p";
      break;
    case PJ_STUN_TP_TCP:
      name = "tcpstun%p";
      break;
    default:
      PJ_ASSERT_RETURN(!"Invalid STUN conn_type", PJ_EINVAL);
      name = "tcpstun%p";
      break;
    }
  }

  /* Create and init basic data structure */
  const int PJNATH_POOL_LEN_STUN_SOCK = 256;
  const int PJNATH_POOL_INC_STUN_SOCK = 512;
  pool = pj_pool_create(cfg->pf, name, PJNATH_POOL_LEN_STUN_SOCK,
                        PJNATH_POOL_INC_STUN_SOCK, NULL);
  stun_sock = PJ_POOL_ZALLOC_T(pool, pj_stun_sock);
  stun_sock->pool = pool;
  stun_sock->obj_name = pool->obj_name;
  stun_sock->user_data = user_data;
  stun_sock->af = af;
  stun_sock->conn_type = conn_type;
  stun_sock->main_sock_fd = PJ_INVALID_SOCKET;
#if PJ_HAS_TCP
  stun_sock->outgoing_nb = -1;
  stun_sock->incoming_nb = -1;
#endif

  /* Copy STUN config (this contains ioqueue, timer heap, etc.) */
  pj_memcpy(&stun_sock->cfg, cfg, sizeof(*cfg));

  /* Copy setting (QoS parameters etc */
  pj_memcpy(&stun_sock->setting, setting, sizeof(*setting));

  /* Set callback */
  pj_memcpy(&stun_sock->cb, cb, sizeof(*cb));

  if (setting->grp_lock) {
    stun_sock->grp_lock = setting->grp_lock;
  } else {
    status = pj_grp_lock_create(pool, NULL, &stun_sock->grp_lock);
    if (status != PJ_SUCCESS) {
      pj_pool_release(pool);
      return status;
    }
  }

  pj_grp_lock_add_ref(stun_sock->grp_lock);
  pj_grp_lock_add_handler(stun_sock->grp_lock, pool, stun_sock,
                          &stun_sock_destructor);

  /* Create STUN session */
  {
    pj_stun_session_cb sess_cb;

    pj_bzero(&sess_cb, sizeof(sess_cb));
    sess_cb.on_request_complete = &sess_on_request_complete;
    sess_cb.on_send_msg = &sess_on_send_msg;
    status = pj_stun_session_create(&stun_sock->cfg, stun_sock->obj_name,
                                    &sess_cb, PJ_FALSE, stun_sock->grp_lock,
                                    &stun_sock->stun_sess, conn_type);
    if (status != PJ_SUCCESS) {
      pj_stun_sock_destroy(stun_sock);
      return status;
    }
  }

  pj_stun_sock_alloc(stun_sock);

  /* Done */
  *p_stun_sock = stun_sock;
  return PJ_SUCCESS;
}


/*
 * Notification when outgoing TCP socket has been connected.
 */
static pj_bool_t
on_stun_sock_ready(pj_activesock_t *asock, pj_status_t status)
{
  pj_stun_sock *stun_sock;
  stun_sock = (pj_stun_sock *)pj_activesock_get_user_data(asock);
  if (!stun_sock)
    return PJ_FALSE;

  pj_grp_lock_acquire(stun_sock->grp_lock);

  /* TURN session may have already been destroyed here.
   * See ticket #1557 (http://trac.pjsip.org/repos/ticket/1557).
   */
  if (!stun_sock->stun_sess) {
    sess_fail(stun_sock, PJ_STUN_SESS_DESTROYED, status);
    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_FALSE;
    }

    if (status != PJ_SUCCESS) {
      sess_fail(stun_sock, PJ_STUN_TCP_CONNECT_ERROR, status);
      pj_grp_lock_release(stun_sock->grp_lock);
      return PJ_FALSE;
    }

    if (stun_sock->conn_type != PJ_STUN_TP_UDP) {
        PJ_LOG(5,(stun_sock->obj_name, "TCP connected"));
    }

    /* Start asynchronous read operations */
    pj_status_t result = pj_activesock_start_recvfrom(
        asock, stun_sock->pool, stun_sock->setting.max_pkt_size, 0);
    if (result != PJ_SUCCESS) {
        return PJ_FALSE;
    };

    /* Associate us with the STUN session */
    pj_stun_session_set_user_data(stun_sock->stun_sess, stun_sock);

    /* Initialize random numbers to be used as STUN transaction ID for
     * outgoing Binding request. We use the 80bit number to distinguish
     * STUN messages we sent with STUN messages that the application sends.
     * The last 16bit value in the array is a counter.
     */
    unsigned i;
    for (i=0; i<PJ_ARRAY_SIZE(stun_sock->tsx_id); ++i) {
        stun_sock->tsx_id[i] = (pj_uint16_t) pj_rand();
    }
    stun_sock->tsx_id[5] = 0;


    /* Init timer entry */
    stun_sock->ka_timer.cb = &ka_timer_cb;
    stun_sock->ka_timer.user_data = stun_sock;

    if (status != PJ_SUCCESS) {
        pj_stun_sock_destroy(stun_sock);
        pj_grp_lock_release(stun_sock->grp_lock);
        return status;
    }

    /* Init send keys */
    pj_ioqueue_op_key_init(&stun_sock->send_key,
                           sizeof(stun_sock->send_key));
    pj_ioqueue_op_key_init(&stun_sock->int_send_key,
                           sizeof(stun_sock->int_send_key));

    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_TRUE;
}

pj_bool_t
parse_rx_packet(pj_stun_sock *stun_sock, void *data, pj_size_t size,
                const pj_sockaddr_t *rx_addr, unsigned sock_addr_len) {
    pj_uint16_t parsed = 0;
    pj_status_t result = PJ_TRUE;
    pj_status_t status;

    do {
        pj_uint16_t pkt_len = size - parsed;
        pj_uint8_t *current_packet = ((pj_uint8_t *)(data)) + parsed;
        pj_grp_lock_acquire(stun_sock->grp_lock);

#if PJ_HAS_TCP
        if (stun_sock->conn_type != PJ_STUN_TP_UDP) {
            /* RFC6544, the packet is wrapped into a packet following the RFC4571 */
            pj_bool_t store_remaining = PJ_TRUE;
            if (stun_sock->rx_buffer_size != 0 || stun_sock->rx_wanted_size != 0) {
                // We currently have a packet to complete
                if (stun_sock->rx_buffer_size == 1) {
                    // We do not know the current size, parse it.
                    pkt_len = (((pj_uint8_t *)stun_sock->rx_buffer)[0] << 8) +
                              ((pj_uint8_t *)current_packet)[0];
                    stun_sock->rx_buffer_size = 0; // We have eaten the temp packet.
                    current_packet = current_packet + 1;
                    parsed += 1;
                    if (pkt_len + parsed <= size) {
                      store_remaining = PJ_FALSE;
                      parsed += pkt_len;
                    } else {
                      stun_sock->rx_wanted_size = pkt_len;
                    }
                } else if (pkt_len + stun_sock->rx_buffer_size >= stun_sock->rx_wanted_size) {
                    // We have enough data Build new packet to parse
                    store_remaining = PJ_FALSE;
                    pj_uint16_t eaten_bytes = stun_sock->rx_wanted_size - stun_sock->rx_buffer_size;
                    memcpy(stun_sock->rx_buffer + stun_sock->rx_buffer_size,
                           current_packet, eaten_bytes);
                    pkt_len = stun_sock->rx_wanted_size;
                    current_packet = stun_sock->rx_buffer;
                    parsed += eaten_bytes;
                    stun_sock->rx_buffer_size = 0;
                    stun_sock->rx_wanted_size = 0;
                }
            } else if (pkt_len > 1) {
                pkt_len = (((pj_uint8_t *)current_packet)[0] << 8) + ((pj_uint8_t *)current_packet)[1];
                current_packet = current_packet + 2;
                parsed += 2;
                if (pkt_len + parsed <= size) {
                    store_remaining = PJ_FALSE;
                    parsed += pkt_len;
                } else {
                    stun_sock->rx_wanted_size = pkt_len;
                }
            }
            if (store_remaining) {
                pj_uint16_t stored_size = size - parsed;
                memcpy(stun_sock->rx_buffer + stun_sock->rx_buffer_size,
                        current_packet, stored_size);
                stun_sock->rx_buffer_size += stored_size;
                status = pj_grp_lock_release(stun_sock->grp_lock);
                result &= status != PJ_EGONE ? PJ_TRUE : PJ_FALSE;
                break;
            }
        } else {
#endif
          parsed = size;
#if PJ_HAS_TCP
        }
#endif
        /* Check that this is STUN message */
        status = pj_stun_msg_check((const pj_uint8_t *)current_packet, pkt_len,
                                   PJ_STUN_IS_DATAGRAM | PJ_STUN_CHECK_PACKET);
        if (status != PJ_SUCCESS) {
          /* Not STUN -- give it to application */
          goto process_app_data;
        }

        /* Treat packet as STUN header and copy the STUN message type.
         * We don't want to access the type directly from the header
         * since it may not be properly aligned.
         */
        pj_stun_msg_hdr *hdr = (pj_stun_msg_hdr *)current_packet;
        pj_uint16_t type;
        pj_memcpy(&type, &hdr->type, 2);
        type = pj_ntohs(type);

        /* If the packet is a STUN Binding response and part of the
         * transaction ID matches our internal ID, then this is
         * our internal STUN message (Binding request or keep alive).
         * Give it to our STUN session.
         */
        if (!PJ_STUN_IS_RESPONSE(type) ||
            PJ_STUN_GET_METHOD(type) != PJ_STUN_BINDING_METHOD ||
            pj_memcmp(hdr->tsx_id, stun_sock->tsx_id, 10) != 0) {
          /* Not STUN Binding response, or STUN transaction ID mismatch.
           * This is not our message too -- give it to application.
           */
          goto process_app_data;
        }

        /* This is our STUN Binding response. Give it to the STUN session */
        status = pj_stun_session_on_rx_pkt(stun_sock->stun_sess, current_packet,
                                           pkt_len, PJ_STUN_IS_DATAGRAM, NULL,
                                           NULL, rx_addr, sock_addr_len);

        status = pj_grp_lock_release(stun_sock->grp_lock);
        result &= status != PJ_EGONE ? PJ_TRUE : PJ_FALSE;
        continue;

    process_app_data:
        if (stun_sock->cb.on_rx_data) {
            (*stun_sock->cb.on_rx_data)(stun_sock, current_packet,
                                        (unsigned)pkt_len, rx_addr, sock_addr_len);
            status = pj_grp_lock_release(stun_sock->grp_lock);
            result &= status != PJ_EGONE ? PJ_TRUE : PJ_FALSE;
            continue;
        }

        status = pj_grp_lock_release(stun_sock->grp_lock);
        result &= status != PJ_EGONE ? PJ_TRUE : PJ_FALSE;
    } while (parsed < size && result);
    return result;
}

pj_bool_t on_data_read(pj_activesock_t *asock, void *data, pj_size_t size,
                       pj_status_t status, pj_size_t *remainder) {

    pj_stun_sock *stun_sock;

    stun_sock = (pj_stun_sock *)pj_activesock_get_user_data(asock);
    if (!stun_sock) return PJ_FALSE;

    pj_stun_session_cb *cb = pj_stun_session_callback(stun_sock->stun_sess);
    /* Log socket error or disconnection */
    if (status != PJ_SUCCESS) {
        if (stun_sock->conn_type == PJ_STUN_TP_UDP || (status != PJ_EEOF && status != 120104 && status != 130054)) {
            PJ_PERROR(2, (stun_sock->obj_name, status, "read() error"));
        } else if (status == 120104 || status == 130054 /* RESET BY PEER */) {
            for (int i = 0; i <= stun_sock->outgoing_nb; ++i) {
                if (stun_sock->outgoing_socks[i].sock == asock) {
                    if (cb && (cb->on_peer_reset_connection)) {
                        (cb->on_peer_reset_connection)(stun_sock->stun_sess, stun_sock->outgoing_socks[i].addr);
                    }
                }
            }
        }
        return PJ_FALSE;
    }
#if PJ_HAS_TCP
    pj_sockaddr_t *rx_addr = NULL;
    unsigned sock_addr_len = 0;
    for (int i = 0; i <= stun_sock->outgoing_nb; ++i) {
        if (stun_sock->outgoing_socks[i].sock == asock) {
            rx_addr = stun_sock->outgoing_socks[i].addr;
            sock_addr_len = pj_sockaddr_get_len(rx_addr);
            if (cb && (cb->on_peer_packet))
              (cb->on_peer_packet)(stun_sock->stun_sess, stun_sock->outgoing_socks[i].addr);
        }
    }
    if (rx_addr == NULL && stun_sock->incoming_nb != -1) {
        // It's an incoming message
        rx_addr = &stun_sock->incoming_socks[stun_sock->incoming_nb].addr;
        sock_addr_len = stun_sock->incoming_socks[stun_sock->incoming_nb].addr_len;
    }
    return parse_rx_packet(stun_sock, data, size, rx_addr, sock_addr_len);
#else
    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_FALSE;
#endif
}

#if PJ_HAS_TCP
/*
 * Notification when incoming TCP socket has been connected.
 * NOTE: cf https://www.pjsip.org/docs/latest/pjlib/docs/html//structpj__activesock__cb.htm if status needed
 */
static pj_bool_t on_stun_sock_accept(pj_activesock_t *main_sock, pj_sock_t sock,
                                     const pj_sockaddr_t *src_addr,
                                     int src_addr_len) {
    pj_status_t status;
    pj_stun_sock *stun_sock;
    int sock_type = pj_SOCK_STREAM();
    stun_sock = (pj_stun_sock *)pj_activesock_get_user_data(main_sock);

    stun_sock->incoming_nb += 1;
    int nb_check = stun_sock->incoming_nb;
    pj_sock_t *fd = &stun_sock->incoming_socks[nb_check].fd;
    pj_activesock_t **asock = &stun_sock->incoming_socks[nb_check].sock;
    pj_sockaddr_cp(&stun_sock->incoming_socks[nb_check].addr, src_addr);
    stun_sock->incoming_socks[nb_check].addr_len = src_addr_len;
    *fd = sock;

    pj_activesock_cfg activesock_cfg;
    pj_activesock_cb activesock_cb;

    pj_activesock_cfg_default(&activesock_cfg);
    activesock_cfg.grp_lock = stun_sock->grp_lock;
    activesock_cfg.async_cnt = stun_sock->setting.async_cnt;
    activesock_cfg.concurrency = 0;

    /* Create the active socket */
    pj_bzero(&activesock_cb, sizeof(activesock_cb));
    activesock_cb.on_data_read = &on_data_read;
    activesock_cb.on_data_sent = &on_data_sent;

    status = pj_activesock_create(stun_sock->pool, *fd, sock_type,
                                  &activesock_cfg, stun_sock->cfg.ioqueue,
                                  &activesock_cb, stun_sock, asock);

    if (status != PJ_SUCCESS) {
      pj_stun_sock_destroy(stun_sock);
      pj_grp_lock_release(stun_sock->grp_lock);
      return status;
    }

    /* Start asynchronous read operations */
    pj_status_t result = pj_activesock_start_read(*asock, stun_sock->pool,
        stun_sock->setting.max_pkt_size, 0);
    if (result != PJ_SUCCESS) {
      return PJ_FALSE;
    };

    return PJ_TRUE;
}
#endif

/* Start socket. */
PJ_DEF(pj_status_t) pj_stun_sock_start( pj_stun_sock *stun_sock,
				        const pj_str_t *domain,
				        pj_uint16_t default_port,
				        pj_dns_resolver *resolver)
{
    pj_status_t status;

    PJ_ASSERT_RETURN(stun_sock && domain && default_port, PJ_EINVAL);

    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Check whether the domain contains IP address */
    stun_sock->srv_addr.addr.sa_family = (pj_uint16_t)stun_sock->af;
    status = pj_inet_pton(stun_sock->af, domain, 
			  pj_sockaddr_get_addr(&stun_sock->srv_addr));
    if (status != PJ_SUCCESS) {
	stun_sock->srv_addr.addr.sa_family = (pj_uint16_t)0;
    }

    /* If resolver is set, try to resolve with DNS SRV first. It
     * will fallback to DNS A/AAAA when no SRV record is found.
     */
    if (status != PJ_SUCCESS && resolver) {
	const pj_str_t res_name = pj_str("_stun._udp.");
	unsigned opt;

	pj_assert(stun_sock->q == NULL);

	/* Init DNS resolution option */
	if (stun_sock->af == pj_AF_INET6())
	    opt = (PJ_DNS_SRV_RESOLVE_AAAA_ONLY | PJ_DNS_SRV_FALLBACK_AAAA);
	else
	    opt = PJ_DNS_SRV_FALLBACK_A;

	status = pj_dns_srv_resolve(domain, &res_name, default_port, 
				    stun_sock->pool, resolver, opt,
				    stun_sock, &dns_srv_resolver_cb, 
				    &stun_sock->q);
	if (status != PJ_SUCCESS) {
	    PJ_PERROR(4,(stun_sock->obj_name, status,
			 "Failed in pj_dns_srv_resolve()"));
	}

	/* Processing will resume when the DNS SRV callback is called */

    } else {

	if (status != PJ_SUCCESS) {
	    pj_addrinfo ai;
	    unsigned cnt = 1;

	    status = pj_getaddrinfo(stun_sock->af, domain, &cnt, &ai);
	    if (cnt == 0)
		status = PJ_EAFNOTSUP;

	    if (status != PJ_SUCCESS) {
		PJ_PERROR(4,(stun_sock->obj_name, status,
			     "Failed in pj_getaddrinfo()"));
	        pj_grp_lock_release(stun_sock->grp_lock);
		return status;
	    }

	    pj_sockaddr_cp(&stun_sock->srv_addr, &ai.ai_addr);
	}

	pj_sockaddr_set_port(&stun_sock->srv_addr, (pj_uint16_t)default_port);

	/* Start sending Binding request */
	status = get_mapped_addr(stun_sock);
	if (status != PJ_SUCCESS) {
	    PJ_PERROR(4,(stun_sock->obj_name, status,
			 "Failed in sending Binding request"));
	}
    }

    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
}

/* Destructor */
static void stun_sock_destructor(void *obj)
{
    pj_stun_sock *stun_sock = (pj_stun_sock*)obj;

    if (stun_sock->q) {
	pj_dns_srv_cancel_query(stun_sock->q, PJ_FALSE);
	stun_sock->q = NULL;
    }

    /*
    if (stun_sock->stun_sess) {
	pj_stun_session_destroy(stun_sock->stun_sess);
	stun_sock->stun_sess = NULL;
    }
    */

    pj_pool_safe_release(&stun_sock->pool);

    TRACE_(("", "STUN sock %p destroyed", stun_sock));

}

/* Destroy */
PJ_DEF(pj_status_t) pj_stun_sock_destroy(pj_stun_sock *stun_sock)
{
    TRACE_((stun_sock->obj_name, "STUN sock %p request, ref_cnt=%d",
	    stun_sock, pj_grp_lock_get_ref(stun_sock->grp_lock)));

    pj_grp_lock_acquire(stun_sock->grp_lock);
    if (stun_sock->is_destroying) {
	/* Destroy already called */
	pj_grp_lock_release(stun_sock->grp_lock);
	return PJ_EINVALIDOP;
    }

    stun_sock->is_destroying = PJ_TRUE;
    pj_timer_heap_cancel_if_active(stun_sock->cfg.timer_heap,
                                   &stun_sock->ka_timer, 0);

    if (stun_sock->main_sock != NULL) {
        stun_sock->main_sock_fd = PJ_INVALID_SOCKET;
        pj_activesock_close(stun_sock->main_sock);
    } else if (stun_sock->main_sock_fd != PJ_INVALID_SOCKET) {
        pj_sock_close(stun_sock->main_sock_fd);
        stun_sock->main_sock_fd = PJ_INVALID_SOCKET;
    }

    for (int i = 0; i < stun_sock->incoming_nb ; ++i) {
        if (stun_sock->incoming_socks[i].sock != NULL) {
            stun_sock->incoming_socks[i].fd = PJ_INVALID_SOCKET;
            pj_activesock_close(stun_sock->incoming_socks[i].sock);
        } else if (stun_sock->incoming_socks[i].fd != PJ_INVALID_SOCKET) {
            pj_sock_close(stun_sock->incoming_socks[i].fd);
            stun_sock->incoming_socks[i].fd = PJ_INVALID_SOCKET;
        }
    }

    for (int i = 0; i < stun_sock->outgoing_nb ; ++i) {
        if (stun_sock->outgoing_socks[i].sock != NULL) {
            stun_sock->outgoing_socks[i].fd = PJ_INVALID_SOCKET;
            pj_activesock_close(stun_sock->outgoing_socks[i].sock);
        } else if (stun_sock->outgoing_socks[i].fd != PJ_INVALID_SOCKET) {
            pj_sock_close(stun_sock->outgoing_socks[i].fd);
            stun_sock->outgoing_socks[i].fd = PJ_INVALID_SOCKET;
        }
    }

    if (stun_sock->stun_sess) {
	pj_stun_session_destroy(stun_sock->stun_sess);
    }
    pj_grp_lock_dec_ref(stun_sock->grp_lock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_SUCCESS;
}

/* Associate user data */
PJ_DEF(pj_status_t) pj_stun_sock_set_user_data( pj_stun_sock *stun_sock,
					        void *user_data)
{
    PJ_ASSERT_RETURN(stun_sock, PJ_EINVAL);
    stun_sock->user_data = user_data;
    return PJ_SUCCESS;
}


/* Get user data */
PJ_DEF(void*) pj_stun_sock_get_user_data(pj_stun_sock *stun_sock)
{
    PJ_ASSERT_RETURN(stun_sock, NULL);
    return stun_sock->user_data;
}

/* Get group lock */
PJ_DECL(pj_grp_lock_t *) pj_stun_sock_get_grp_lock(pj_stun_sock *stun_sock)
{
    PJ_ASSERT_RETURN(stun_sock, NULL);
    return stun_sock->grp_lock;
}

/* Notify application that session has failed */
static pj_bool_t sess_fail(pj_stun_sock *stun_sock, 
			   pj_stun_sock_op op,
			   pj_status_t status)
{
    pj_bool_t ret;

    PJ_PERROR(4,(stun_sock->obj_name, status, 
	         "Session failed because %s failed",
		 pj_stun_sock_op_name(op)));

    ret = (*stun_sock->cb.on_status)(stun_sock, op, status);

    return ret;
}

/* DNS resolver callback */
static void dns_srv_resolver_cb(void *user_data,
				pj_status_t status,
				const pj_dns_srv_record *rec)
{
    pj_stun_sock *stun_sock = (pj_stun_sock*) user_data;

    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Clear query */
    stun_sock->q = NULL;

    /* Handle error */
    if (status != PJ_SUCCESS) {
	sess_fail(stun_sock, PJ_STUN_SOCK_DNS_OP, status);
	pj_grp_lock_release(stun_sock->grp_lock);
	return;
    }

    pj_assert(rec->count);
    pj_assert(rec->entry[0].server.addr_count);
    pj_assert(rec->entry[0].server.addr[0].af == stun_sock->af);

    /* Set the address */
    pj_sockaddr_init(stun_sock->af, &stun_sock->srv_addr, NULL,
		     rec->entry[0].port);
    if (stun_sock->af == pj_AF_INET6()) {
	stun_sock->srv_addr.ipv6.sin6_addr = 
				    rec->entry[0].server.addr[0].ip.v6;
    } else {
	stun_sock->srv_addr.ipv4.sin_addr = 
				    rec->entry[0].server.addr[0].ip.v4;
    }

    /* Start sending Binding request */
    get_mapped_addr(stun_sock);

    pj_grp_lock_release(stun_sock->grp_lock);
}


/* Start sending STUN Binding request */
static pj_status_t get_mapped_addr(pj_stun_sock *stun_sock)
{
    pj_stun_tx_data *tdata;
    pj_status_t status;

    /* Increment request counter and create STUN Binding request */
    ++stun_sock->tsx_id[5];
    status = pj_stun_session_create_req(stun_sock->stun_sess,
					PJ_STUN_BINDING_REQUEST,
					PJ_STUN_MAGIC, 
					(const pj_uint8_t*)stun_sock->tsx_id, 
					&tdata);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Send request */
    status = pj_stun_session_send_msg(
        stun_sock->stun_sess, INTERNAL_MSG_TOKEN, PJ_FALSE,
        (stun_sock->conn_type == PJ_STUN_TP_UDP), &stun_sock->srv_addr,
        pj_sockaddr_get_len(&stun_sock->srv_addr), tdata);
    if (status != PJ_SUCCESS && status != PJ_EPENDING)
	goto on_error;

    return PJ_SUCCESS;

on_error:
    sess_fail(stun_sock, PJ_STUN_SOCK_BINDING_OP, status);
    return status;
}

/* Get info */
PJ_DEF(pj_status_t) pj_stun_sock_get_info( pj_stun_sock *stun_sock,
                                           pj_stun_sock_info *info)
{
    int addr_len;
    pj_status_t status;

    PJ_ASSERT_RETURN(stun_sock && info, PJ_EINVAL);

    pj_grp_lock_acquire(stun_sock->grp_lock);

    info->conn_type = stun_sock->conn_type;

    /* Copy STUN server address and mapped address */
    pj_memcpy(&info->srv_addr, &stun_sock->srv_addr,
              sizeof(pj_sockaddr));
    pj_memcpy(&info->mapped_addr, &stun_sock->mapped_addr,
              sizeof(pj_sockaddr));

    /* Retrieve bound address */
    addr_len = sizeof(info->bound_addr);
    status = pj_sock_getsockname(stun_sock->main_sock_fd, &info->bound_addr,
                                 &addr_len);
    if (status != PJ_SUCCESS) {
        pj_grp_lock_release(stun_sock->grp_lock);
        return status;
    }

    /* Query all the interfaces in the host, because STUN is compatible with TCP
     */
    if (pj_sockaddr_has_addr(&info->bound_addr)) {
        info->alias_cnt = 1;
        pj_sockaddr_cp(&info->aliases[0], &info->bound_addr);
    } else {
        pj_sockaddr def_addr;
        pj_uint16_t port = pj_sockaddr_get_port(&info->bound_addr); 
        unsigned i;

        /* Get the default address */
        status = pj_gethostip(stun_sock->af, &def_addr);
        if (status != PJ_SUCCESS) {
            PJ_PERROR(4,(stun_sock->obj_name, status,
                "Failed in getting default address for STUN info"));
            pj_grp_lock_release(stun_sock->grp_lock);
            return status;
        }
        
        pj_sockaddr_set_port(&def_addr, port);
        
        /* Enum all IP interfaces in the host */
        info->alias_cnt = PJ_ARRAY_SIZE(info->aliases);
        status = pj_enum_ip_interface(stun_sock->af, &info->alias_cnt, 
                        info->aliases);
        if (status != PJ_SUCCESS) {
            /* If enumeration fails, just return the default address */
            PJ_PERROR(4,(stun_sock->obj_name, status,
                "Failed in enumerating interfaces for STUN info, "
                "returning default address only"));
            info->alias_cnt = 1;
            pj_sockaddr_cp(&info->aliases[0], &def_addr);
        }

        /* Set the port number for each address.
        */
        for (i=0; i<info->alias_cnt; ++i) {
            pj_sockaddr_set_port(&info->aliases[i], port);
        }

        /* Put the default IP in the first slot */
        for (i=0; i<info->alias_cnt; ++i) {
            if (pj_sockaddr_cmp(&info->aliases[i], &def_addr)==0) {
                if (i!=0) {
                    pj_sockaddr_cp(&info->aliases[i], &info->aliases[0]);
                    pj_sockaddr_cp(&info->aliases[0], &def_addr);
                }
                break;
            }
        }
    }

    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_SUCCESS;
}

/* Send application data */
PJ_DEF(pj_status_t) pj_stun_sock_sendto( pj_stun_sock *stun_sock,
					 pj_ioqueue_op_key_t *send_key,
					 const void *pkt,
					 unsigned pkt_len,
					 unsigned flag,
					 const pj_sockaddr_t *dst_addr,
					 unsigned addr_len,
                     pj_ssize_t* size)
{
    pj_status_t status;

    PJ_ASSERT_RETURN(stun_sock && pkt && dst_addr && addr_len, PJ_EINVAL);

    pj_grp_lock_acquire(stun_sock->grp_lock);

    if (!stun_sock->main_sock) {
        /* We have been shutdown, but this callback may still get called
         * by retransmit timer.
         */
        pj_grp_lock_release(stun_sock->grp_lock);
        return PJ_EINVALIDOP;
    }

    if (send_key==NULL)
        send_key = &stun_sock->send_key;

    *size = pkt_len;
    if (stun_sock->conn_type == PJ_STUN_TP_UDP) {
        status = pj_activesock_sendto(stun_sock->main_sock, send_key,
                                      pkt, size, flag, dst_addr, addr_len);
    } else {
#if PJ_HAS_TCP
        pj_bool_t is_outgoing = PJ_FALSE;
        pj_bool_t is_incoming = PJ_FALSE;
        for (int i = 0; i <= stun_sock->outgoing_nb; ++i) {
            if (pj_sockaddr_cmp(stun_sock->outgoing_socks[i].addr, dst_addr) == 0) {
                is_outgoing = PJ_TRUE;
                status = pj_activesock_send(stun_sock->outgoing_socks[i].sock,
                                            send_key, pkt, size, flag);
                break;
            }
        }
        if (is_outgoing == PJ_FALSE) {
            for (int i = 0 ; i <= stun_sock->incoming_nb; ++i) {
                if (pj_sockaddr_cmp(&stun_sock->incoming_socks[i].addr,
                                    dst_addr) == 0) {
                    status = pj_activesock_send(stun_sock->incoming_socks[i].sock,
                                                send_key, pkt, size, flag);
                    is_incoming = PJ_TRUE;
                    break;
                }
            }
        }
        if (is_outgoing == PJ_FALSE && is_incoming == PJ_FALSE) {
            status = pj_activesock_send(stun_sock->main_sock, send_key, pkt,
                                        size, flag);
        }

#endif
    }

    pj_grp_lock_release(stun_sock->grp_lock);
	return status;
}

#if PJ_HAS_TCP

PJ_DECL(pj_status_t)
pj_stun_sock_connect(pj_stun_sock *stun_sock, const pj_sockaddr_t *remote_addr, int af, int nb_check) {

  pj_grp_lock_acquire(stun_sock->grp_lock);
  int sock_type = pj_SOCK_STREAM();

  pj_sock_t *fd = &stun_sock->outgoing_socks[nb_check].fd;
  pj_activesock_t **asock = &stun_sock->outgoing_socks[nb_check].sock;
  pj_sockaddr_t **addr = &stun_sock->outgoing_socks[nb_check].addr;

  pj_status_t status = pj_sock_socket(af, sock_type, 0, fd);
  if (status != PJ_SUCCESS) {
    pj_stun_sock_destroy(stun_sock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
  }

  /* Apply QoS, if specified */
  status = pj_sock_apply_qos2(*fd, stun_sock->setting.qos_type,
                            &stun_sock->setting.qos_params, 2, stun_sock->obj_name, NULL);
  if (status != PJ_SUCCESS && !stun_sock->setting.qos_ignore_error) {
    pj_stun_sock_destroy(stun_sock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
  }

  /* Apply socket buffer size */
  if (stun_sock->setting.so_rcvbuf_size > 0) {
    unsigned sobuf_size = stun_sock->setting.so_rcvbuf_size;
    status = pj_sock_setsockopt_sobuf(*fd, pj_SO_RCVBUF(), PJ_TRUE, &sobuf_size);
    if (status != PJ_SUCCESS) {
      pj_perror(3, stun_sock->obj_name, status, "Failed setting SO_RCVBUF");
    } else {
      if (sobuf_size < stun_sock->setting.so_rcvbuf_size) {
        PJ_LOG(4, (stun_sock->obj_name,
                   "Warning! Cannot set SO_RCVBUF as configured, "
                   "now=%d, configured=%d",
                   sobuf_size, stun_sock->setting.so_rcvbuf_size));
      } else {
        PJ_LOG(5, (stun_sock->obj_name, "SO_RCVBUF set to %d", sobuf_size));
      }
    }
  }

  if (stun_sock->setting.so_sndbuf_size > 0) {
    unsigned sobuf_size = stun_sock->setting.so_sndbuf_size;
    status = pj_sock_setsockopt_sobuf(*fd, pj_SO_SNDBUF(), PJ_TRUE, &sobuf_size);
    if (status != PJ_SUCCESS) {
      pj_perror(3, stun_sock->obj_name, status, "Failed setting SO_SNDBUF");
    } else {
      if (sobuf_size < stun_sock->setting.so_sndbuf_size) {
        PJ_LOG(4, (stun_sock->obj_name,
                   "Warning! Cannot set SO_SNDBUF as configured, "
                   "now=%d, configured=%d",
                   sobuf_size, stun_sock->setting.so_sndbuf_size));
      } else {
        PJ_LOG(5, (stun_sock->obj_name, "SO_SNDBUF set to %d", sobuf_size));
      }
    }
  }

  /* Init active socket configuration */
  {
    pj_activesock_cfg activesock_cfg;
    pj_activesock_cb activesock_cb;

    pj_activesock_cfg_default(&activesock_cfg);
    activesock_cfg.grp_lock = stun_sock->grp_lock;
    activesock_cfg.async_cnt = stun_sock->setting.async_cnt;
    activesock_cfg.concurrency = 0;

    /* Create the active socket */
    pj_bzero(&activesock_cb, sizeof(activesock_cb));
    activesock_cb.on_data_read = &on_data_read;
    activesock_cb.on_data_sent = &on_data_sent;
    activesock_cb.on_connect_complete = &on_connect_complete;

    status = pj_activesock_create(stun_sock->pool, *fd,
                                  sock_type, &activesock_cfg,
                                  stun_sock->cfg.ioqueue, &activesock_cb,
                                  stun_sock, asock);

    if (status != PJ_SUCCESS) {
      pj_grp_lock_release(stun_sock->grp_lock);
      return status;
    }

    *addr = remote_addr;

    status = pj_activesock_start_connect(
            *asock, stun_sock->pool, *addr,
            pj_sockaddr_get_len(*addr));
    if (status == PJ_SUCCESS) {
      on_connect_complete(*asock, status);
    } else if (status != PJ_EPENDING) {
      char addrinfo[PJ_INET6_ADDRSTRLEN+8];
      pj_perror(3, stun_sock->pool->obj_name, status, "Failed to connect to %s",
                pj_sockaddr_print(*addr, addrinfo, sizeof(addrinfo), 3));
      pj_grp_lock_release(stun_sock->grp_lock);
      return status;
    }
  }

  pj_grp_lock_release(stun_sock->grp_lock);
  return status;
}

PJ_DECL(pj_status_t)
pj_stun_sock_connect_active(pj_stun_sock *stun_sock, const pj_sockaddr_t *remote_addr, int af) {

  if (stun_sock->incoming_nb != -1) {
      // Check if not incoming, if so, already connected (mainly for PRFLX candidates)
      for (int i = 0 ; i <= stun_sock->incoming_nb; ++i) {
          if (pj_sockaddr_cmp(&stun_sock->incoming_socks[i].addr, remote_addr) == 0) {
              pj_stun_session_cb *cb = pj_stun_session_callback(stun_sock->stun_sess);
              (cb->on_peer_connection)(stun_sock->stun_sess, PJ_SUCCESS, remote_addr);
              return PJ_SUCCESS;
          }
      }
  }

  /* Create socket and bind socket */
  stun_sock->outgoing_nb += 1;
  int nb_check = stun_sock->outgoing_nb;
  return pj_stun_sock_connect(stun_sock, remote_addr, af, nb_check);

}

PJ_DECL(pj_status_t)
pj_stun_sock_reconnect_active(pj_stun_sock *stun_sock, const pj_sockaddr_t *remote_addr, int af) {
    for (int i = 0; i <= stun_sock->outgoing_nb; ++i) {
        if (pj_sockaddr_cmp(stun_sock->outgoing_socks[i].addr, remote_addr) == 0) {
            pj_activesock_close(stun_sock->outgoing_socks[i].sock);
            return pj_stun_sock_connect(stun_sock, remote_addr, af, i);
        }
    }
    return PJ_EINVAL;
}

PJ_DECL(pj_status_t)
pj_stun_sock_close(pj_stun_sock *stun_sock, const pj_sockaddr_t *remote_addr) {
    for (int i = 0; i <= stun_sock->outgoing_nb; ++i) {
        if (pj_sockaddr_cmp(stun_sock->outgoing_socks[i].addr, remote_addr) == 0) {
            return pj_activesock_close(stun_sock->outgoing_socks[i].sock);
        }
    }

    for (int i = 0; i <= stun_sock->incoming_nb; ++i) {
        if (pj_sockaddr_cmp(&stun_sock->incoming_socks[i].addr, remote_addr) == 0) {
            return pj_activesock_close(stun_sock->incoming_socks[i].sock);
        }
    }
    return PJ_EINVAL;
}

pj_bool_t on_connect_complete(pj_activesock_t *asock, pj_status_t status) {
  pj_stun_sock *stun_sock;
  stun_sock = (pj_stun_sock *)pj_activesock_get_user_data(asock);

  pj_status_t result = pj_activesock_start_read(
      asock, stun_sock->pool, stun_sock->setting.max_pkt_size, 0);
  if (result != PJ_SUCCESS) {
    return PJ_FALSE;
  };

  pj_stun_session_cb *cb = pj_stun_session_callback(stun_sock->stun_sess);
  if (!cb->on_peer_connection) {
    return PJ_FALSE;
  }

  // Get remote connected address
  pj_sockaddr_t* remote_addr = NULL;
  for (int i = 0 ; i <= stun_sock->outgoing_nb ; ++i) {
      if (stun_sock->outgoing_socks[i].sock == asock) {
          remote_addr = stun_sock->outgoing_socks[i].addr;
      }
  }
  if (!remote_addr) return PJ_FALSE;
  (cb->on_peer_connection)(stun_sock->stun_sess, status, remote_addr);
  return PJ_TRUE;
}

#endif

/* This callback is called by the STUN session to send packet */
pj_status_t sess_on_send_msg(pj_stun_session *sess,
				    void *token,
				    const void *pkt,
				    pj_size_t pkt_size,
				    const pj_sockaddr_t *dst_addr,
				    unsigned addr_len)
{
    pj_stun_sock *stun_sock;
    pj_ssize_t size;

    stun_sock = (pj_stun_sock *) pj_stun_session_get_user_data(sess);
    if (!stun_sock || !stun_sock->main_sock) {
	/* We have been shutdown, but this callback may still get called
	 * by retransmit timer.
	 */
	return PJ_EINVALIDOP;
    }

    pj_assert(token==INTERNAL_MSG_TOKEN);
    PJ_UNUSED_ARG(token);

    size = pkt_size;
    if (stun_sock->conn_type == PJ_STUN_TP_UDP) {
        return pj_activesock_sendto(stun_sock->main_sock,
                                    &stun_sock->int_send_key,
                                    pkt, &size, 0, dst_addr, addr_len);
    }
#if PJ_HAS_TCP
    else {
        for (int i = 0 ; i <= stun_sock->incoming_nb; ++i) {
            if (pj_sockaddr_cmp(&stun_sock->incoming_socks[i].addr, dst_addr) == 0) {
                pj_status_t status = pj_activesock_send(stun_sock->incoming_socks[i].sock,
                                            &stun_sock->int_send_key, pkt, &size, 0);
            }
        }
        return pj_activesock_send(stun_sock->main_sock, &stun_sock->int_send_key,
                        pkt, &size, 0);
    }
#else
    return PJ_EINVAL;
#endif
}

/* This callback is called by the STUN session when outgoing transaction 
 * is complete
 */
void sess_on_request_complete(pj_stun_session *sess,
				     pj_status_t status,
				     void *token,
				     pj_stun_tx_data *tdata,
				     const pj_stun_msg *response,
				     const pj_sockaddr_t *src_addr,
				     unsigned src_addr_len)
{
    pj_stun_sock *stun_sock;
    const pj_stun_sockaddr_attr *mapped_attr;
    pj_stun_sock_op op;
    pj_bool_t mapped_changed;
    pj_bool_t resched = PJ_TRUE;

    stun_sock = (pj_stun_sock *) pj_stun_session_get_user_data(sess);
    if (!stun_sock)
	return;

    PJ_UNUSED_ARG(tdata);
    PJ_UNUSED_ARG(token);
    PJ_UNUSED_ARG(src_addr);
    PJ_UNUSED_ARG(src_addr_len);

    /* Check if this is a keep-alive or the first Binding request */
    if (pj_sockaddr_has_addr(&stun_sock->mapped_addr))
	op = PJ_STUN_SOCK_KEEP_ALIVE_OP;
    else
	op = PJ_STUN_SOCK_BINDING_OP;

    /* Handle failure */
    if (status != PJ_SUCCESS) {
	resched = sess_fail(stun_sock, op, status);
	goto on_return;
    }

    /* Get XOR-MAPPED-ADDRESS, or MAPPED-ADDRESS when XOR-MAPPED-ADDRESS
     * doesn't exist.
     */
    mapped_attr = (const pj_stun_sockaddr_attr*)
		  pj_stun_msg_find_attr(response, PJ_STUN_ATTR_XOR_MAPPED_ADDR,
					0);
    if (mapped_attr==NULL) {
	mapped_attr = (const pj_stun_sockaddr_attr*)
		      pj_stun_msg_find_attr(response, PJ_STUN_ATTR_MAPPED_ADDR,
					0);
    }

    if (mapped_attr == NULL) {
	resched = sess_fail(stun_sock, op, PJNATH_ESTUNNOMAPPEDADDR);
	goto on_return;
    }

    /* Determine if mapped address has changed, and save the new mapped
     * address and call callback if so 
     */
    mapped_changed = !pj_sockaddr_has_addr(&stun_sock->mapped_addr) ||
		     pj_sockaddr_cmp(&stun_sock->mapped_addr, 
				     &mapped_attr->sockaddr) != 0;
    if (mapped_changed) {
	/* Print mapped adress */
	{
	    char addrinfo[PJ_INET6_ADDRSTRLEN+10];
	    PJ_LOG(4,(stun_sock->obj_name, 
		      "STUN mapped address found/changed: %s",
		      pj_sockaddr_print(&mapped_attr->sockaddr,
					addrinfo, sizeof(addrinfo), 3)));
	}

	pj_sockaddr_cp(&stun_sock->mapped_addr, &mapped_attr->sockaddr);

	if (op==PJ_STUN_SOCK_KEEP_ALIVE_OP)
	    op = PJ_STUN_SOCK_MAPPED_ADDR_CHANGE;
    }

    /* Notify user */
    resched = (*stun_sock->cb.on_status)(stun_sock, op, PJ_SUCCESS);

on_return:
    /* Start/restart keep-alive timer */
    if (resched)
	start_ka_timer(stun_sock);
}

/* Schedule keep-alive timer */
void start_ka_timer(pj_stun_sock *stun_sock)
{
    pj_timer_heap_cancel_if_active(stun_sock->cfg.timer_heap,
                                   &stun_sock->ka_timer, 0);

    pj_assert(stun_sock->ka_interval != 0);
    if (stun_sock->ka_interval > 0 && !stun_sock->is_destroying) {
	pj_time_val delay;

	delay.sec = stun_sock->ka_interval;
	delay.msec = 0;

	pj_timer_heap_schedule_w_grp_lock(stun_sock->cfg.timer_heap,
	                                  &stun_sock->ka_timer,
	                                  &delay, PJ_TRUE,
	                                  stun_sock->grp_lock);
    }
}

/* Keep-alive timer callback */
void ka_timer_cb(pj_timer_heap_t *th, pj_timer_entry *te)
{
    pj_stun_sock *stun_sock;

    stun_sock = (pj_stun_sock *) te->user_data;

    PJ_UNUSED_ARG(th);
    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Time to send STUN Binding request */
    if (get_mapped_addr(stun_sock) != PJ_SUCCESS) {
	pj_grp_lock_release(stun_sock->grp_lock);
	return;
    }

    /* Next keep-alive timer will be scheduled once the request
     * is complete.
     */
    pj_grp_lock_release(stun_sock->grp_lock);
}

/* Callback from active socket when incoming packet is received */
pj_bool_t on_data_recvfrom(pj_activesock_t *asock,
				  void *data,
				  pj_size_t size,
				  const pj_sockaddr_t *src_addr,
				  int addr_len,
				  pj_status_t status)
{
    pj_stun_sock *stun_sock;

    stun_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
    if (!stun_sock)
	return PJ_FALSE;

    /* Log socket error */
    if (status != PJ_SUCCESS) {
	PJ_PERROR(2,(stun_sock->obj_name, status, "recvfrom() error"));
	return PJ_TRUE;
    }

    return parse_rx_packet(stun_sock, data, size, src_addr, addr_len);
}

/* Callback from active socket about send status */
pj_bool_t on_data_sent(pj_activesock_t *asock,
			      pj_ioqueue_op_key_t *send_key,
			      pj_ssize_t sent)
{
    pj_stun_sock *stun_sock;

    stun_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
    if (!stun_sock)
	return PJ_FALSE;

    /* Don't report to callback if this is internal message */
    if (send_key == &stun_sock->int_send_key) {
	return PJ_TRUE;
    }

    /* Report to callback */
    if (stun_sock->cb.on_data_sent) {
	pj_bool_t ret;

	pj_grp_lock_acquire(stun_sock->grp_lock);

	/* If app gives NULL send_key in sendto() function, then give
	 * NULL in the callback too 
	 */
	if (send_key == &stun_sock->send_key)
	    send_key = NULL;

	/* Call callback */
	ret = (*stun_sock->cb.on_data_sent)(stun_sock, send_key, sent);

	pj_grp_lock_release(stun_sock->grp_lock);
	return ret;
    }

    return PJ_TRUE;
}

pj_stun_session* pj_stun_sock_get_session(pj_stun_sock *stun_sock)
{
  return stun_sock ? stun_sock->stun_sess : NULL;
}
