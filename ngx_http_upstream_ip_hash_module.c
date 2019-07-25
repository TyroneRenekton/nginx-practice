
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_uint_t                         hash;

    u_char                             addrlen;
    u_char                            *addr;

    u_char                             tries;

    ngx_event_get_peer_pt              get_rr_peer;
    
    int userid;
} ngx_http_upstream_ip_hash_peer_data_t;


static ngx_int_t ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_ip_hash_commands[] = {

    { ngx_string("gray_chain"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_ip_hash,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_ip_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ip_hash_module_ctx, /* module context */
    ngx_http_upstream_ip_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char ngx_http_upstream_ip_hash_pseudo_addr[3];

int string2int(char *str)//字符串转数字 
{
	char flag = '+';//指示结果是否带符号 
	long res = 0;
	
	if(*str=='-')//字符串带负号 
	{
		++str;//指向下一个字符 
		flag = '-';//将标志设为负号 
	} 
	//逐个字符转换，并累加到结果res 
	while(*str>=48 && *str<=57)//如果是数字才进行转换，数字0~9的ASCII码：48~57
	{
		res = 10*res+  *str++-48;//字符'0'的ASCII码为48,48-48=0刚好转化为数字0 
	} 
 
    if(flag == '-')//处理是负数的情况
	{
		res = -res;
	}
 
	return (int)res;
}

void int2string(int x,char *Str)
{
    int t;
    char *Ptr,Buf[5];
    int i = 0;
    Ptr = Str;
    if(x < 10)
    {
        *Ptr ++ = '0';
        *Ptr ++ = x+0x30;
    }
    else
    {
        while(x > 0)
        {
            t = x % 10;
            x = x / 10;
            Buf[i++] = t+0x30;    // 通过计算把数字编成ASCII码形式
        }
        i -- ;
        for(;i >= 0;i --)         // 将得到的字符串倒序
        {
            *(Ptr++) = Buf[i];
        }
    }
    *Ptr = '\0';
}

static ngx_int_t
ngx_http_upstream_init_ip_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_ip_hash_peer;

    return NGX_OK;
}

static int get_user_id(ngx_http_request_t *r)
{
	 ngx_list_part_t           *part = &r->headers_in.headers.part;
     ngx_table_elt_t           *header = part->elts;
	 int i = 0;
	 for (i = 0; /* void */; i++) {
    	    if (i >= (int)part->nelts) {
       	    	 if (part->next == NULL) {
       	       	    break;
       	     	 }
       	     	 part = part->next;
       	     	 header = part->elts;
            }
            if (strcmp("userid", (char *)ngx_pstrdup(r->pool, &header[i].key)) == 0) {
                return string2int((char *)ngx_pstrdup(r->pool, &header[i].value));
            }
     }
	return 0;
}


static ngx_int_t
ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    ngx_http_upstream_ip_hash_peer_data_t  *iphp;

    iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }
    
    iphp->userid=get_user_id(r);

    r->upstream->peer.data = &iphp->rrp;
 
    char userid_buf[20] = {0};
    int2string(iphp->userid, userid_buf);
    
    ngx_log_error(4 , r->upstream->peer.log,0,userid_buf);

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_ip_hash_peer;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = ngx_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;

    return NGX_OK;
}

void long2ip(long ip, char buf[])
{
    int i = 0;
    unsigned long tmp[4] = {0};
    for (i = 0;  i < 4; ++i)
    {
        tmp[i] = ip & 255;
        ip = ip >>8;
    }
    sprintf(buf, "%lu.%lu.%lu.%lu", tmp[0], tmp[1], tmp[2], tmp[3]);
}

int find_last(char* buf)
{
    int i = 0;
    int value = -1;
    for (i = 0; i < 16; ++i)
    {
        if (buf[i] == '\0')
        {
            return value;
        }
        value = buf[i] - '0';
    }
    return value;
}

static ngx_int_t
ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ip_hash_peer_data_t  *iphp = data;
    
    time_t                        now;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    i, n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer;
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);
    
    /* TODO: cached */
    
    ngx_http_upstream_rr_peers_rlock(iphp->rrp.peers);
    
    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }
    
    now = ngx_time();
    
    pc->cached = 0;
    pc->connection = NULL;
    
    hash = iphp->hash;
    
    for ( ;; ) {
        
        for (i = 0; i < (ngx_uint_t) iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }
        
        w = hash % iphp->rrp.peers->total_weight;
        peer = iphp->rrp.peers->peer;
        p = 0;
        
        while (peer->next) {
            struct sockaddr_in                     *sin;
            sin = (struct sockaddr_in *)peer->sockaddr;
            char buf[16] = {0};
            long2ip((long)sin->sin_addr.s_addr, buf);
            
            // userid 最后一位
            int userid_last = iphp->userid % 10;
            // ip最后一位
            int ip_last = find_last(buf);
            
            char u_last_arr[10] = {0};
            char ip_last_arr[10] = {0};
            
            int2string(userid_last, u_last_arr);
            int2string(ip_last,ip_last_arr);
            
            ngx_log_error(4 , pc->log,0, u_last_arr);
            
            ngx_log_error(4 , pc->log,0, ip_last_arr);
            
            if (userid_last == ip_last) {
                ngx_log_error(4 , pc->log,0, "equal last");
                break;
            }
            peer = peer->next;
            p++;
        }
        
        struct sockaddr_in                     *sin;
        sin = (struct sockaddr_in *)peer->sockaddr;
        
        char buf[16] = {0};
        long2ip((long)sin->sin_addr.s_addr, buf);
        
        ngx_log_error(4 , pc->log,0, buf);
        
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
        
        if (iphp->rrp.tried[n] & m) {
            goto next;
        }
        
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);
        
        ngx_http_upstream_rr_peer_lock(iphp->rrp.peers, peer);
        
        if (peer->down) {
            ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }
        
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }
        
        if (peer->max_conns && peer->conns >= peer->max_conns) {
            ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }
        
        break;
        
    next:
        
        if (++iphp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }
    
    iphp->rrp.current = peer;
    
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;
    
    peer->conns++;
    
    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }
    
    ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
    ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
    
    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;
    
    return NGX_OK;
}

static char *
ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_ip_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_CONNS
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}
