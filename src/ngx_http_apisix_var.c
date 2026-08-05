#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_apisix_module.h"


/*
 * ngx_http_variables_init_vars() copies get_handler into cmcf->variables but
 * leaves set_handler alone, so writing a variable needs the entry that lives
 * in cmcf->variables_hash. Resolve that mapping once per cycle instead of
 * hashing the name on every write.
 */
static ngx_http_variable_t **ngx_http_apisix_vars;
static ngx_uint_t            ngx_http_apisix_nvars;


ngx_int_t
ngx_http_apisix_var_init_module(ngx_cycle_t *cycle)
{
    ngx_uint_t                  i, n, key;
    ngx_http_variable_t        *v, **vars;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_apisix_vars = NULL;
    ngx_http_apisix_nvars = 0;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    n = cmcf->variables.nelts;
    if (n == 0) {
        return NGX_OK;
    }

    vars = ngx_pcalloc(cycle->pool, n * sizeof(ngx_http_variable_t *));
    if (vars == NULL) {
        return NGX_ERROR;
    }

    v = cmcf->variables.elts;

    for (i = 0; i < n; i++) {
        /* ngx_http_get_variable_index() stores the name lower cased already */
        key = ngx_hash_key(v[i].name.data, v[i].name.len);

        /* NULL for a prefix variable such as $http_foo: it has no entry of
         * its own in variables_hash and therefore is not writable */
        vars[i] = ngx_hash_find(&cmcf->variables_hash, key,
                                v[i].name.data, v[i].name.len);
    }

    ngx_http_apisix_vars = vars;
    ngx_http_apisix_nvars = n;

    return NGX_OK;
}


char *
ngx_http_apisix_var_index(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value, name;
    ngx_uint_t   i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        name = value[i];

        if (name.len < 2 || name.data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &name);
            return NGX_CONF_ERROR;
        }

        name.len--;
        name.data++;

        if (ngx_http_get_variable_index(cf, &name) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


ngx_uint_t
ngx_http_apisix_ffi_var_load_indexes(ngx_str_t *names, ngx_uint_t max)
{
    ngx_uint_t                  i, n;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    /*
     * only safe from the init_worker phase on: until ngx_init_cycle()
     * commits, the ngx_cycle global still points at the previous cycle
     */
    cmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_core_module);
    if (cmcf == NULL) {
        return 0;
    }

    n = cmcf->variables.nelts;

    if (names == NULL) {
        return n;
    }

    if (n > max) {
        n = max;
    }

    v = cmcf->variables.elts;

    for (i = 0; i < n; i++) {
        names[i] = v[i].name;
    }

    return n;
}


int
ngx_http_apisix_ffi_var_get_by_index(ngx_http_request_t *r, ngx_uint_t index,
    u_char **value, size_t *value_len)
{
    ngx_http_variable_value_t  *vv;

    /* ngx_http_get_indexed_variable() rejects an out of range index itself */
    vv = ngx_http_get_indexed_variable(r, index);
    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    *value = vv->data;
    *value_len = vv->len;

    return NGX_OK;
}


int
ngx_http_apisix_ffi_var_set_by_index(ngx_http_request_t *r, ngx_uint_t index,
    u_char *value, size_t value_len, char **err)
{
    u_char                     *p;
    ngx_http_variable_t        *v;
    ngx_http_variable_value_t  *vv;

    if (index >= ngx_http_apisix_nvars) {
        *err = "bad variable index";
        return NGX_ERROR;
    }

    v = ngx_http_apisix_vars[index];
    if (v == NULL) {
        *err = "variable not found for writing";
        return NGX_ERROR;
    }

    if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
        *err = "variable not changeable";
        return NGX_ERROR;
    }

    if (v->set_handler != NULL) {
        if (value == NULL) {
            *err = "variable cannot be assigned a nil value";
            return NGX_ERROR;
        }

        vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
        if (vv == NULL) {
            *err = "no memory";
            return NGX_ERROR;
        }

        p = ngx_pnalloc(r->pool, value_len);
        if (p == NULL) {
            *err = "no memory";
            return NGX_ERROR;
        }

        ngx_memcpy(p, value, value_len);

        vv->valid = 1;
        vv->not_found = 0;
        vv->no_cacheable = 0;
        vv->data = p;
        vv->len = value_len;

        v->set_handler(r, vv, v->data);

        return NGX_OK;
    }

    if (!(v->flags & NGX_HTTP_VAR_INDEXED)) {
        *err = "variable cannot be assigned a value";
        return NGX_ERROR;
    }

    vv = &r->variables[index];

    if (value == NULL) {
        vv->valid = 0;
        vv->not_found = 1;
        vv->no_cacheable = 0;
        vv->data = NULL;
        vv->len = 0;

        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, value_len);
    if (p == NULL) {
        *err = "no memory";
        return NGX_ERROR;
    }

    ngx_memcpy(p, value, value_len);

    vv->valid = 1;
    vv->not_found = 0;
    vv->no_cacheable = 0;
    vv->data = p;
    vv->len = value_len;

    return NGX_OK;
}
