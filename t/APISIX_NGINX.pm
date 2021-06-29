package t::APISIX_NGINX;

use Test::Nginx::Socket::Lua;
use Test::Nginx::Socket::Lua::Stream -Base;
use Cwd qw(cwd);

log_level('debug');
no_long_string();
no_shuffle();
worker_connections(128);


$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_CERT_DIR} = cwd() . "/t/certs";
$ENV{TEST_NGINX_SERVER_SSL_PORT} = 23456;


add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->request) {
        $block->set_value("request", "GET /t");
    }

    if (!$block->no_error_log && !$block->error_log) {
        $block->set_value("no_error_log", "[error]\n[alert]");
    }

    my $http_config = $block->http_config // '';
    $http_config .= <<_EOC_;
    lua_package_path "lib/?.lua;;";
_EOC_

    $block->set_value("http_config", $http_config);
});


1;
