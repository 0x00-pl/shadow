# NOTE: ipv6-shadow has one intentional, expected failure
# (test_dual_stack_bind_v6_connect_v4): dual-stack sockets are not yet
# implemented. See the header comment in test_ipv6.rs.
add_linux_tests(BASENAME ipv6 COMMAND sh -c "../../target/debug/test_ipv6 --libc-passing")

add_shadow_tests(BASENAME ipv6 LOGLEVEL debug ARGS --strace-logging-mode off)
