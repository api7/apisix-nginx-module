#include "ngx_http_apisix_module.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/*
 * This function contains the logic to append the Request ID to
 * the error log line when being called.
 * Get the location configuration from helper function. Find indexed variable with the loc_conf->request_id_var_index. and add that to buffer.
 */
static u_char*
ngx_http_apisix_error_log_handler(ngx_http_request_t *r, u_char *buf, size_t len)
{
		ngx_http_variable_value_t *request_id_var;
		ngx_http_apisix_loc_conf_t *loc_conf;

		loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_apisix_module);
		if (loc_conf->request_id_var_index == NGX_CONF_UNSET) {
				return buf;
		}

		request_id_var = ngx_http_get_indexed_variable(r, loc_conf->request_id_var_index);
		if (request_id_var == NULL || request_id_var->not_found) {
				return buf;
		}
		buf = ngx_snprintf(buf, len, ", request_id: \"%v\"", request_id_var);
		return buf;
}


/*
 * This function replaces the original HTTP error
 * log handler (r->log_handler). It executes the original logic
 * and then our error log handler: ngx_http_apisix_error_log_handler
 * This function returns the final message.
 */
static u_char*
ngx_http_apisix_combined_error_log_handler(ngx_http_request_t *r, ngx_http_request_t *sr, u_char *buf, size_t len)
{
		u_char *p;
		ngx_http_apisix_ctx_t *ctx;

		ctx = ngx_http_apisix_get_module_ctx(r);
		if (ctx == NULL || ctx->orig_log_handler == NULL) {
				return buf;
		}

		//Get the original log message
		p = ctx->orig_log_handler(r, sr, buf, len);
		//p - buf calculates the number of bytes written by the original log handler into the buffer.
		//len -= (p - buf) reduces the remaining buffer length by the amount already used.
		len -= p-buf;

		//Apisix log handler
		buf = ngx_http_apisix_error_log_handler(r, buf, len);
		return buf;
}


//It replaces the r->log_handler which is the log handler of the request with the combined log handler.
// Creates the apisix context we need from the request to act on it.
static ngx_int_t
ngx_http_apisix_replace_error_log_handler(ngx_http_request_t *r)
{
		ngx_http_apisix_ctx_t *ctx;

		ctx = ngx_http_apisix_get_module_ctx(r);
		if (ctx == NULL) {
				return NGX_OK;
		}

		if (r->log_handler == NULL){
				return NGX_DECLINED;
		}

    /*
     * Store the original log handler in ctx->orig_log_handler, replace
     * it with the combined log handler, which will execute the original
     * handler's logic in addition to our own.
     */
		ctx->orig_log_handler = r->log_handler;
		r->log_handler = ngx_http_apisix_combined_error_log_handler;

		return NGX_DECLINED;
}

//This function is part of postconfiguration passed to module context and will override the post_read_phase with custom log handler.
// It extracts the pointer to log handler from the post read phase handlers and then override that with new function address.
char *
ngx_http_apisix_error_log_init(ngx_conf_t *cf)
{
		ngx_http_handler_pt *h;
		ngx_http_core_main_conf_t *cmcf;

		cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
		if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed setting error log handler");
        return NGX_CONF_ERROR;
    }

		*h = ngx_http_apisix_replace_error_log_handler;

		return NGX_CONF_OK;
}

// This function does the translation of the configuration file to the internal representation.
// So this will just set the value in loc_conf that it gets by reference.
char * 
ngx_http_apisix_error_log_request_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
		ngx_http_apisix_loc_conf_t *loc_conf = conf;

		value = cf->args->elts;
		if (value[1].data[0] != '$') {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]);
				return NGX_CONF_ERROR;
		}

		value[1].len--;
		value[1].data++;

		loc_conf->request_id_var_index = ngx_http_get_variable_index(cf, &value[1]);
		if (loc_conf->request_id_var_index == NGX_ERROR) {
				return NGX_CONF_ERROR;
		}

		return NGX_CONF_OK;
}
