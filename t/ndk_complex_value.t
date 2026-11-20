use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: NDK directive with a complex value
--- config
    location /t {
        set_encode_base64 $out "$arg_x-$arg_y";
        return 200 "[$out]\n";
    }
--- request
GET /t?x=hello&y=world
--- response_body
[aGVsbG8td29ybGQ=]



=== TEST 2: NDK directive with a complex value, repeated on a kept-alive connection
--- config
    location /t {
        set_escape_uri $out "$arg_x $arg_y";
        return 200 "[$out]\n";
    }
--- pipelined_requests eval
["GET /t?x=a%20b&y=c", "GET /t?x=d&y=e%2Ff"]
--- response_body eval
["[a%2520b%20c]\n", "[d%20e%252Ff]\n"]



=== TEST 3: NDK directive with a single variable and with a constant
--- config
    location /t {
        set_encode_base64 $var "$arg_x";
        set_encode_base64 $const "constant";
        return 200 "[$var] [$const]\n";
    }
--- request
GET /t?x=abc
--- response_body
[YWJj] [Y29uc3RhbnQ=]
