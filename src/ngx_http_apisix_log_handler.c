#include "ngx_http_apisix_module.h"

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
}
