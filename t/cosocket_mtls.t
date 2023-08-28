use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;
        ssl_client_certificate ../../certs/mtls_server.crt;
        ssl_verify_client on;

        location / {
            return 200 'ok\n';
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests;

__DATA__

=== TEST 1: avoid using stale openssl error code
--- config
    location /t {
        access_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            for i = 1, 2 do
                local ok, err = sock:tlshandshake({
                    verify = true,
                    client_cert_path = "t/certs/mtls_client.crt",
                    client_priv_key_path = "t/certs/mtls_client.key",
                })
                if not ok then
                    ngx.say(err)
                end
            end
        }
    }
--- response_body
20: unable to get local issuer certificate
closed
--- error_log
[error]



=== TEST 2: avoid using stale openssl error code with cert content
--- config
    location /t {
        access_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            for i = 1, 2 do
                local ok, err = sock:tlshandshake({
                    verify = true,
                    client_cert = [[-----BEGIN CERTIFICATE-----
MIIDOjCCAiICAwD6zzANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJjbjESMBAG
A1UECAwJR3VhbmdEb25nMQ8wDQYDVQQHDAZaaHVIYWkxDTALBgNVBAoMBGFwaTcx
DDAKBgNVBAsMA29wczEWMBQGA1UEAwwNY2EuYXBpc2l4LmRldjAeFw0yMDA2MjAx
MzE1MDBaFw0zMDA3MDgxMzE1MDBaMF0xCzAJBgNVBAYTAmNuMRIwEAYDVQQIDAlH
dWFuZ0RvbmcxDTALBgNVBAoMBGFwaTcxDzANBgNVBAcMBlpodUhhaTEaMBgGA1UE
AwwRY2xpZW50LmFwaXNpeC5kZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCfKI8uiEH/ifZikSnRa3/E2B4ohVWRwjo/IxyDEWomgR4tLk1pSJhP/4SC
LWuMQTFWTbSqt1IFYy4ZbVSHHyGoNPmJGrHRJCGE+sgpfzn0GjV4lXQPJD0k6GR1
CX2Mo1TWdFqSJ/Hc5AQwcQFnPfoLAwsBy4yqrlmf96ZAUytl/7Zkjf4P7mJkJHtM
/WgSR0pGhjZTAGRf5DJWoO51ki3i3JI+15mOhmnnCpnksnGVPfl92q92Hz/4v3iq
E+UThPYRpcGbnddzMvPaCXiavg8B/u2LVbn4l0adamqQGepOAjD/1xraOVP2W22W
0PztDXJ4rLe+capNS4oGuSUfkIENAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHKn
HxUhuk/nL2Sg5UB84OoJe5XPgNBvVMKN0c/NAPKVIPninvUcG/mHeKexPzE0sMga
RNos75N2199EXydqUcsJ8jL0cNtQ2k5JQXXg0ntNC4tuCgIKAOnO879y5hSG36e5
7wmAoVKnabgjej09zG1kkXvAmpgqoxeVCu7h7fK+AurLbsGCTaHoA5pG1tcHDxJQ
fpVcbBfwQDSBW3SQjiRqX453/01nw6kbOeLKYraJysaG8ZU2K8+WpW6JDubciHjw
fQnpU2U16XKivhxeuKYrV/INL0sxj/fZraNYErvJWzh5llvIdNLmeSPmvb50JUIs
+lDqn1MobTXzDpuCFXA=
-----END CERTIFICATE-----]],
                    client_priv_key = [[-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAnyiPLohB/4n2YpEp0Wt/xNgeKIVVkcI6PyMcgxFqJoEeLS5N
aUiYT/+Egi1rjEExVk20qrdSBWMuGW1Uhx8hqDT5iRqx0SQhhPrIKX859Bo1eJV0
DyQ9JOhkdQl9jKNU1nRakifx3OQEMHEBZz36CwMLAcuMqq5Zn/emQFMrZf+2ZI3+
D+5iZCR7TP1oEkdKRoY2UwBkX+QyVqDudZIt4tySPteZjoZp5wqZ5LJxlT35fdqv
dh8/+L94qhPlE4T2EaXBm53XczLz2gl4mr4PAf7ti1W5+JdGnWpqkBnqTgIw/9ca
2jlT9lttltD87Q1yeKy3vnGqTUuKBrklH5CBDQIDAQABAoIBAHDe5bPdQ9jCcW3z
fpGax/DER5b6//UvpfkSoGy/E+Wcmdb2yEVLC2FoVwOuzF+Z+DA5SU/sVAmoDZBQ
vapZxJeygejeeo5ULkVNSFhNdr8LOzJ54uW+EHK1MFDj2xq61jaEK5sNIvRA7Eui
SJl8FXBrxwmN3gNJRBwzF770fImHUfZt0YU3rWKw5Qin7QnlUzW2KPUltnSEq/xB
kIzyWpuj7iAm9wTjH9Vy06sWCmxj1lzTTXlanjPb1jOTaOhbQMpyaAzRgQN8PZiE
YKCarzVj7BJr7/vZYpnQtQDY12UL5n33BEqMP0VNHVqv+ZO3bktfvlwBru5ZJ7Cf
URLsSc0CgYEAyz7FzV7cZYgjfUFD67MIS1HtVk7SX0UiYCsrGy8zA19tkhe3XVpc
CZSwkjzjdEk0zEwiNAtawrDlR1m2kverbhhCHqXUOHwEpujMBjeJCNUVEh3OABr8
vf2WJ6D1IRh8FA5CYLZP7aZ41fcxAnvIPAEThemLQL3C4H5H5NG2WFsCgYEAyHhP
onpS/Eo/OXKYFLR/mvjizRVSomz1lVVL+GWMUYQsmgsPyBJgyAOX3Pqt9catgxhM
DbEr7EWTxth3YeVzamiJPNVK0HvCax9gQ0KkOmtbrfN54zBHOJ+ieYhsieZLMgjx
iu7Ieo6LDGV39HkvekzutZpypiCpKlMaFlCFiLcCgYEAmAgRsEj4Nh665VPvuZzH
ZIgZMAlwBgHR7/v6l7AbybcVYEXLTNJtrGEEH6/aOL8V9ogwwZuIvb/TEidCkfcf
zg/pTcGf2My0MiJLk47xO6EgzNdso9mMG5ZYPraBBsuo7NupvWxCp7NyCiOJDqGH
K5NmhjInjzsjTghIQRq5+qcCgYEAxnm/NjjvslL8F69p/I3cDJ2/RpaG0sMXvbrO
VWaMryQyWGz9OfNgGIbeMu2Jj90dar6ChcfUmb8lGOi2AZl/VGmc/jqaMKFnElHl
J5JyMFicUzPMiG8DBH+gB71W4Iy+BBKwugHBQP2hkytewQ++PtKuP+RjADEz6vCN
0mv0WS8CgYBnbMRP8wIOLJPRMw/iL9BdMf606X4xbmNn9HWVp2mH9D3D51kDFvls
7y2vEaYkFv3XoYgVN9ZHDUbM/YTUozKjcAcvz0syLQb8wRwKeo+XSmo09+360r18
zRugoE7bPl39WdGWaW3td0qf1r9z3sE2iWUTJPRQ3DYpsLOYIgyKmw==
-----END RSA PRIVATE KEY-----]],
                })
                if not ok then
                    ngx.say(err)
                end
            end
        }
    }
--- response_body
20: unable to get local issuer certificate
closed
--- error_log
[error]
