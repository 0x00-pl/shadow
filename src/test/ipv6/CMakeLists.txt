# NOTE: ipv6-shadow is an intentional, expected failure ("not yet implemented"
# marker): all IPv6 functionality tests run under shadow and fail until IPv6
# support is added. See the header comment in test_ipv6.rs.
add_linux_tests(BASENAME ipv6 COMMAND sh -c "../../target/debug/test_ipv6 --libc-passing")

add_shadow_tests(BASENAME ipv6 LOGLEVEL debug ARGS --strace-logging-mode off)
