#!/usr/bin/env perl

# Sanity check for roadmap steps 1-5 (hash lookup -> directives -> Redis
# round trip -> $apikey_* variables -> enabled/require enforcement).
# Requires a redis/valkey reachable on TEST_NGINX_REDIS_PORT (default 6379).

use strict;
use warnings;

use Test::Nginx::Socket 'no_plan';
use Digest::SHA qw(sha256_hex);

$ENV{TEST_NGINX_REDIS_PORT} ||= 6379;
$ENV{TEST_NGINX_BACKEND_PORT} ||= 18099;

our $REDIS_CLI = "redis-cli -p $ENV{TEST_NGINX_REDIS_PORT}";

our $HttpConfig = qq{
    upstream apikey_redis {
        server 127.0.0.1:$ENV{TEST_NGINX_REDIS_PORT};
        keepalive 16;
    }

    map \$apikey_scope \$apikey_has_admin_scope {
        default                 0;
        "~\\badmin\\b"          1;
    }

    server {
        listen $ENV{TEST_NGINX_BACKEND_PORT};
        location = /authorized {
            return 200 "OK\\n";
        }
    }
};

no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: enabled key returns 200 and exposes \$apikey_* variables
--- http_config eval: $::HttpConfig
--- init
my $h = Digest::SHA::sha256_hex("sanity-key-1");
my $rc = system("$::REDIS_CLI HSET apikey:cred:$h user_id u01 scope 'read write' quota 100 enabled 1");
die "redis-cli HSET failed (status $rc); is redis reachable?\n" if $rc != 0;
--- config
    location /t {
        auth_apikey "test-realm";
        auth_apikey_pass apikey_redis;

        add_header X-Apikey-User-Id $apikey_user_id;
        add_header X-Apikey-Scope $apikey_scope;
        add_header X-Apikey-Quota $apikey_quota;
        add_header X-Apikey-Enabled $apikey_enabled;

        proxy_pass http://127.0.0.1:$TEST_NGINX_BACKEND_PORT/authorized;
    }
--- request
GET /t
--- more_headers
Authorization: ApiKey sanity-key-1
--- error_code: 200
--- response_headers
X-Apikey-User-Id: u01
X-Apikey-Scope: read write
X-Apikey-Quota: 100
X-Apikey-Enabled: 1

=== TEST 2: unregistered key returns 401
--- http_config eval: $::HttpConfig
--- config
    location /t {
        auth_apikey "test-realm";
        auth_apikey_pass apikey_redis;

        proxy_pass http://127.0.0.1:$TEST_NGINX_BACKEND_PORT/authorized;
    }
--- request
GET /t
--- more_headers
Authorization: ApiKey sanity-key-unknown
--- error_code: 401
--- response_headers
WWW-Authenticate: ApiKey realm="test-realm"

=== TEST 3: missing Authorization header returns 401 without a Redis round trip
--- http_config eval: $::HttpConfig
--- config
    location /t {
        auth_apikey "test-realm";
        auth_apikey_pass apikey_redis;

        proxy_pass http://127.0.0.1:$TEST_NGINX_BACKEND_PORT/authorized;
    }
--- request
GET /t
--- error_code: 401
--- response_headers
WWW-Authenticate: ApiKey realm="test-realm"

=== TEST 4: disabled key returns 401, identical to not-found
--- http_config eval: $::HttpConfig
--- init
my $h = Digest::SHA::sha256_hex("sanity-key-4");
my $rc = system("$::REDIS_CLI HSET apikey:cred:$h user_id u04 scope read quota 10 enabled 0");
die "redis-cli HSET failed (status $rc); is redis reachable?\n" if $rc != 0;
--- config
    location /t {
        auth_apikey "test-realm";
        auth_apikey_pass apikey_redis;

        proxy_pass http://127.0.0.1:$TEST_NGINX_BACKEND_PORT/authorized;
    }
--- request
GET /t
--- more_headers
Authorization: ApiKey sanity-key-4
--- error_code: 401
--- response_headers
WWW-Authenticate: ApiKey realm="test-realm"

=== TEST 5: auth_apikey off skips authentication and leaves variables not found
--- http_config eval: $::HttpConfig
--- config
    location /t {
        auth_apikey off;

        add_header X-Apikey-User-Id $apikey_user_id;

        proxy_pass http://127.0.0.1:$TEST_NGINX_BACKEND_PORT/authorized;
    }
--- request
GET /t
--- error_code: 200
--- response_headers
X-Apikey-User-Id:

=== TEST 6: auth_apikey_require rejects insufficient scope with the configured error
--- http_config eval: $::HttpConfig
--- init
my $h = Digest::SHA::sha256_hex("sanity-key-6");
my $rc = system("$::REDIS_CLI HSET apikey:cred:$h user_id u06 scope read quota 10 enabled 1");
die "redis-cli HSET failed (status $rc); is redis reachable?\n" if $rc != 0;
--- config
    location /t {
        auth_apikey "test-realm";
        auth_apikey_pass apikey_redis;
        auth_apikey_require $apikey_has_admin_scope error=403;

        proxy_pass http://127.0.0.1:$TEST_NGINX_BACKEND_PORT/authorized;
    }
--- request
GET /t
--- more_headers
Authorization: ApiKey sanity-key-6
--- error_code: 403
