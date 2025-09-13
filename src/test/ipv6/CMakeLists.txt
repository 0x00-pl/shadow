add_linux_tests(BASENAME ipv6 COMMAND sh -c "../../target/debug/test_ipv6 --libc-passing")

# use the new TCP stack for both address families; the legacy C TCP stack
# does not interoperate with the new stack
add_shadow_tests(
    BASENAME ipv6
    LOGLEVEL debug
    ARGS --strace-logging-mode off --use-new-tcp true)

# two-host tests: cross-host IPv6 packet forwarding, explicit IPv6 config
# addresses, and DNS resolution via getaddrinfo()
add_shadow_tests(
    BASENAME ipv6-udp-two-hosts
    SHADOW_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/udp-two-hosts.yaml"
    ARGS --strace-logging-mode off)
add_shadow_tests(
    BASENAME ipv6-tcp-two-hosts
    SHADOW_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/tcp-two-hosts.yaml"
    ARGS --strace-logging-mode off)
