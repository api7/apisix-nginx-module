/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_META_LUA_SHDICT_H_INCLUDED_
#define _NGX_META_LUA_SHDICT_H_INCLUDED_


#include "ngx_meta_lua_module.h"


typedef struct {
    u_char                       color;
    uint8_t                      value_type;
    u_short                      key_len;
    uint32_t                     value_len;
    uint64_t                     expires;
    ngx_queue_t                  queue;
    uint32_t                     user_flags;
    u_char                       data[1];
} ngx_meta_lua_shdict_node_t;


typedef struct {
    ngx_queue_t                  queue;
    uint32_t                     value_len;
    uint8_t                      value_type;
    u_char                       data[1];
} ngx_meta_lua_shdict_list_node_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  lru_queue;
} ngx_meta_lua_shdict_shctx_t;


typedef struct {
#if (NGX_DEBUG)
    ngx_int_t                    isold;
    ngx_int_t                    isinit;
#endif
    ngx_str_t                    name;
    ngx_meta_lua_shdict_shctx_t *sh;
    ngx_slab_pool_t             *shpool;
    ngx_meta_lua_conf_t         *mcf;
    ngx_log_t                   *log;
} ngx_meta_lua_shdict_ctx_t;


typedef struct {
    ngx_shm_zone_t               zone;
    ngx_cycle_t                 *cycle;
    ngx_meta_lua_conf_t         *mcf;
    ngx_log_t                   *log;
} ngx_meta_lua_shm_zone_ctx_t;


#if (NGX_DARWIN)
typedef struct {
    void                  *zone;
    const unsigned char   *key;
    size_t                 key_len;
    int                   *value_type;
    unsigned char        **str_value_buf;
    size_t                *str_value_len;
    double                *num_value;
    int                   *user_flags;
    int                    get_stale;
    int                   *is_stale;
    char                 **errmsg;
} ngx_meta_lua_shdict_get_params_t;


typedef struct {
    void                  *zone;
    int                    op;
    const unsigned char   *key;
    size_t                 key_len;
    int                    value_type;
    const unsigned char   *str_value_buf;
    size_t                 str_value_len;
    double                 num_value;
    long                   exptime;
    int                    user_flags;
    char                 **errmsg;
    int                   *forcible;
} ngx_meta_lua_shdict_store_params_t;


typedef struct {
    void                  *zone;
    const unsigned char   *key;
    size_t                 key_len;
    double                *num_value;
    char                 **errmsg;
    int                    has_init;
    double                 init;
    long                   init_ttl;
    int                   *forcible;
} ngx_meta_lua_shdict_incr_params_t;
#endif


char *ngx_meta_lua_shdict_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


#endif /* _NGX_META_LUA_SHDICT_H_INCLUDED_ */


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
