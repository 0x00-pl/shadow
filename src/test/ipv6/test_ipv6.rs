/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

//! Tests for IPv6-related socket operations.
//!
//! Shadow does not yet implement IPv6 (see docs/limitations.md). This suite
//! serves as a pre-provided test-driven-development marker for the future
//! IPv6 implementation:
//!
//! - Under native Linux (the "--libc-passing" environment) the full IPv6
//!   socket API is exercised and must pass, validating the tests themselves
//!   against real kernel behavior.
//! - Under Shadow (no filter, run with "--summarize") *all* functionality
//!   tests run and are expected to explicitly FAIL with EAFNOSUPPORT until
//!   IPv6 support is implemented. These failures are intentional "todo"
//!   markers. When implementing IPv6 support:
//!   - make the functionality tests pass,
//!   - update or remove `test_socket_af_inet6_eafnosupport` (it asserts the
//!     current rejection behavior),
//!   - check `test_bind_inet6_addr_on_inet_socket`, where Shadow's EINVAL
//!     differs from Linux's EAFNOSUPPORT.

use std::thread;

use test_utils::TestEnvironment as TestEnv;
use test_utils::{get_errno, run_and_close_fds, set};

// Ports used by the tests. Each test binds a distinct port to avoid
// interference; the tests run sequentially within one process.
const PORT_BIND_LOOPBACK: u16 = 22101;
const PORT_BIND_ANY: u16 = 22102;
const PORT_BIND_EADDRINUSE: u16 = 22103;
const PORT_TCP_LOOPBACK: u16 = 22105;
const PORT_DUAL_STACK: u16 = 22106;

fn main() -> Result<(), String> {
    // should we restrict the tests we run?
    let filter_shadow_passing = std::env::args().any(|x| x == "--shadow-passing");
    let filter_libc_passing = std::env::args().any(|x| x == "--libc-passing");
    // should we summarize the results rather than exit on a failed test
    let summarize = std::env::args().any(|x| x == "--summarize");

    let mut tests = get_tests();
    if filter_shadow_passing {
        tests.retain(|x| x.passing(TestEnv::Shadow));
    }

    if filter_libc_passing {
        tests.retain(|x| x.passing(TestEnv::Libc));
    }

    let results = test_utils::run_tests(&tests, summarize)?;

    // in summarize mode, run_tests() runs every test but reports success even
    // when some failed; exit non-zero so that the failures are visible to
    // ctest (this is the "ipv6 support not yet implemented" marker)
    if summarize {
        let failed = tests.len() - results.len();
        if failed > 0 {
            return Err(format!(
                "{failed} of {} IPv6 tests failed: the functionality is not \
                 yet implemented in Shadow (see the ✗ markers above)",
                tests.len()
            ));
        }
    }

    println!("Success.");
    Ok(())
}

fn get_tests() -> Vec<test_utils::ShadowTest<(), String>> {
    let mut tests: Vec<test_utils::ShadowTest<_, _>> = vec![];

    // control: AF_INET sockets must keep working everywhere
    tests.extend(vec![test_utils::ShadowTest::new(
        "test_socket_af_inet_control",
        test_socket_af_inet_control,
        set![TestEnv::Libc, TestEnv::Shadow],
    )]);

    // in Shadow, IPv6 is not yet implemented and socket(AF_INET6) must fail;
    // this assertion must be updated/removed when IPv6 support is added
    tests.extend(vec![test_utils::ShadowTest::new(
        "test_socket_af_inet6_eafnosupport",
        test_socket_af_inet6_eafnosupport,
        set![TestEnv::Shadow],
    )]);

    // the full IPv6 socket API works on native Linux; under Shadow these
    // tests are expected to fail (a "not yet implemented" marker) until
    // IPv6 support is added
    tests.extend(vec![
        test_utils::ShadowTest::new(
            "test_socket_af_inet6",
            test_socket_af_inet6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_socketpair_af_inet6_eopnotsupp",
            test_socketpair_af_inet6_eopnotsupp,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_bind_loopback_v6",
            test_bind_loopback_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_bind_any_v6",
            test_bind_any_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_bind_eaddrinuse_v6",
            test_bind_eaddrinuse_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_bind_inet6_addr_on_inet_socket",
            test_bind_inet6_addr_on_inet_socket,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_udp_loopback_v6",
            test_udp_loopback_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_tcp_loopback_v6",
            test_tcp_loopback_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_sockopt_v6only",
            test_sockopt_v6only,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_dual_stack_bind_v6_connect_v4",
            test_dual_stack_bind_v6_connect_v4,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
    ]);

    tests
}

// build a sockaddr_in6 for the given ipv6 address and (host-order) port
fn sockaddr_in6(addr: [u8; 16], port: u16) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: addr },
        sin6_scope_id: 0,
    }
}

fn ipv6_loopback() -> [u8; 16] {
    let mut addr = [0; 16];
    addr[15] = 1; // ::1
    addr
}

fn ipv6_unspecified() -> [u8; 16] {
    [0; 16] // ::
}

fn errno_is(rv: i32, expected_errno: Option<i32>) -> Result<(), String> {
    match (rv, expected_errno) {
        (-1, Some(errno)) if get_errno() == errno => Ok(()),
        (-1, Some(expected)) => Err(format!(
            "expected errno {} ({}), got {} ({})",
            expected,
            test_utils::get_errno_message(expected),
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        )),
        (-1, None) => Err(format!(
            "unexpected error: {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        )),
        (_, Some(expected)) => Err(format!(
            "expected error {} ({}), but call unexpectedly succeeded",
            expected,
            test_utils::get_errno_message(expected),
        )),
        (_, None) => Ok(()),
    }
}

fn test_socket_af_inet_control() -> Result<(), String> {
    for sock_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        let rv = unsafe { libc::socket(libc::AF_INET, sock_type, 0) };
        if rv < 0 {
            return Err(format!(
                "socket(AF_INET, {sock_type}): unexpected error {} ({})",
                get_errno(),
                test_utils::get_errno_message(get_errno()),
            ));
        }
        unsafe { libc::close(rv) };
    }
    Ok(())
}

// Shadow does not support IPv6, and must reject the socket at creation time
fn test_socket_af_inet6_eafnosupport() -> Result<(), String> {
    for sock_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        let rv = unsafe { libc::socket(libc::AF_INET6, sock_type, 0) };
        errno_is(rv, Some(libc::EAFNOSUPPORT))
            .map_err(|e| format!("socket(AF_INET6, {sock_type}): {e}"))?;
    }
    Ok(())
}

fn test_socket_af_inet6() -> Result<(), String> {
    for sock_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        for flag in [0, libc::SOCK_NONBLOCK, libc::SOCK_CLOEXEC] {
            let fd = unsafe { libc::socket(libc::AF_INET6, sock_type | flag, 0) };
            if fd < 0 {
                return Err(format!(
                    "socket(AF_INET6, {} | {flag}): unexpected error {} ({})",
                    sock_type,
                    get_errno(),
                    test_utils::get_errno_message(get_errno()),
                ));
            }

            // the socket type should be reported back to us
            let mut sock_type_opt: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rv = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    &mut sock_type_opt as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if rv != 0 {
                return Err(format!("getsockopt(SO_TYPE): {}", test_utils::get_errno()));
            }
            if sock_type_opt != sock_type {
                return Err(format!(
                    "getsockopt(SO_TYPE) returned {sock_type_opt}, expected {sock_type}"
                ));
            }

            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

// socketpair() is only defined for AF_UNIX
fn test_socketpair_af_inet6_eopnotsupp() -> Result<(), String> {
    let mut fds = [0 as libc::c_int; 2];
    let rv = unsafe {
        libc::socketpair(
            libc::AF_INET6,
            libc::SOCK_STREAM,
            0,
            fds.as_mut_ptr(),
        )
    };
    errno_is(rv, Some(libc::EOPNOTSUPP))
        .map_err(|e| format!("socketpair(AF_INET6, SOCK_STREAM): {e}"))
}

// bind() an inet socket to an inet6 address must fail; note that Linux
// validates the family against the socket (EAFNOSUPPORT) while shadow
// currently parses the family first (EINVAL) -- revisit once shadow
// implements IPv6
fn test_bind_inet6_addr_on_inet_socket() -> Result<(), String> {
    let expected_errno = if test_utils::running_in_shadow() {
        libc::EINVAL
    } else {
        libc::EAFNOSUPPORT
    };

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    let addr = sockaddr_in6(ipv6_loopback(), 0);
    run_and_close_fds(&[fd], || {
        let rv = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        errno_is(rv, Some(expected_errno))
            .map_err(|e| format!("bind(inet socket, inet6 addr): {e}"))
    })
}

// bind() an ipv6 socket to the loopback address and verify with getsockname()
fn test_bind_loopback_v6() -> Result<(), String> {
    for sock_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        let fd = unsafe { libc::socket(libc::AF_INET6, sock_type, 0) };
        if fd < 0 {
            return Err(format!(
                "socket(AF_INET6, {sock_type}): {} ({})",
                get_errno(),
                test_utils::get_errno_message(get_errno()),
            ));
        }

        let addr = sockaddr_in6(ipv6_loopback(), PORT_BIND_LOOPBACK);
        run_and_close_fds(&[fd], move || {
            let rv = unsafe {
                libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&addr) as libc::socklen_t,
                )
            };
            if rv != 0 {
                return Err(format!(
                    "bind(::1:{PORT_BIND_LOOPBACK}, {sock_type}): {} ({})",
                    get_errno(),
                    test_utils::get_errno_message(get_errno()),
                ));
            }

            // getsockname() should report back the bound address and port
            let mut sock_name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&sock_name) as libc::socklen_t;
            let rv = unsafe {
                libc::getsockname(
                    fd,
                    &mut sock_name as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            if rv != 0 {
                return Err(format!("getsockname(): {}", test_utils::get_errno()));
            }
            if sock_name.ss_family != libc::AF_INET6 as u16 {
                return Err(format!(
                    "getsockname() family is {}, expected AF_INET6",
                    sock_name.ss_family
                ));
            }
            let name = unsafe { *((&raw const sock_name) as *const libc::sockaddr_in6) };
            if name.sin6_port != PORT_BIND_LOOPBACK.to_be() {
                return Err(format!(
                    "getsockname() port is {}, expected {PORT_BIND_LOOPBACK}",
                    u16::from_be(name.sin6_port)
                ));
            }
            if name.sin6_addr.s6_addr != ipv6_loopback() {
                return Err("getsockname() address is not ::1".to_string());
            }
            Ok(())
        })?;
    }
    Ok(())
}

// bind() an ipv6 socket to in6addr_any (::)
fn test_bind_any_v6() -> Result<(), String> {
    for sock_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        let fd = unsafe { libc::socket(libc::AF_INET6, sock_type, 0) };
        if fd < 0 {
            return Err(format!(
                "socket(AF_INET6, {sock_type}): {} ({})",
                get_errno(),
                test_utils::get_errno_message(get_errno()),
            ));
        }

        let addr = sockaddr_in6(ipv6_unspecified(), PORT_BIND_ANY);
        run_and_close_fds(&[fd], move || {
            let rv = unsafe {
                libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&addr) as libc::socklen_t,
                )
            };
            if rv != 0 {
                return Err(format!(
                    "bind(::{PORT_BIND_ANY}, {sock_type}): {} ({})",
                    get_errno(),
                    test_utils::get_errno_message(get_errno()),
                ));
            }
            Ok(())
        })?;
    }
    Ok(())
}

// binding two sockets to the same ipv6 address and port must fail
fn test_bind_eaddrinuse_v6() -> Result<(), String> {
    let fd_1 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    let fd_2 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd_1 < 0 || fd_2 < 0 {
        return Err(format!(
            "socket(AF_INET6, SOCK_DGRAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    let addr = sockaddr_in6(ipv6_loopback(), PORT_BIND_EADDRINUSE);
    run_and_close_fds(&[fd_1, fd_2], || {
        let rv = unsafe {
            libc::bind(
                fd_1,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        if rv != 0 {
            return Err(format!("bind() first socket: {}", test_utils::get_errno()));
        }

        let rv = unsafe {
            libc::bind(
                fd_2,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        errno_is(rv, Some(libc::EADDRINUSE))
            .map_err(|e| format!("bind() second socket to same port: {e}"))
    })
}

// send and receive a datagram between two ipv6 udp sockets on ::1
fn test_udp_loopback_v6() -> Result<(), String> {
    let fd_a = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    let fd_b = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd_a < 0 || fd_b < 0 {
        return Err(format!(
            "socket(AF_INET6, SOCK_DGRAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    // let the kernel assign ephemeral ports and learn them via getsockname()
    let addr_any = sockaddr_in6(ipv6_loopback(), 0);
    run_and_close_fds(&[fd_a, fd_b], || {
        for &fd in &[fd_a, fd_b] {
            let rv = unsafe {
                libc::bind(
                    fd,
                    &addr_any as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&addr_any) as libc::socklen_t,
                )
            };
            if rv != 0 {
                return Err(format!("bind() fd {fd}: {}", test_utils::get_errno()));
            }
        }

        let mut addr_b: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&addr_b) as libc::socklen_t;
        let rv = unsafe {
            libc::getsockname(fd_b, &mut addr_b as *mut _ as *mut libc::sockaddr, &mut len)
        };
        if rv != 0 {
            return Err(format!("getsockname(): {}", test_utils::get_errno()));
        }
        if addr_b.sin6_port == 0 {
            return Err("getsockname() returned an ephemeral port of 0".to_string());
        }

        let payload = b"ipv6 udp loopback";
        let n = unsafe {
            libc::sendto(
                fd_a,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &addr_b as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr_b) as libc::socklen_t,
            )
        };
        if n as usize != payload.len() {
            return Err(format!("sendto() sent {n} of {} bytes", payload.len()));
        }

        let mut buf = [0 as u8; 64];
        let mut src: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut src_len = std::mem::size_of_val(&src) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd_b,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut src as *mut _ as *mut libc::sockaddr,
                &mut src_len,
            )
        };
        if n as usize != payload.len() {
            return Err(format!("recvfrom() received {n} of {} bytes", payload.len()));
        }
        if &buf[..n as usize] != payload {
            return Err("recvfrom() data mismatch".to_string());
        }
        if src.sin6_addr.s6_addr != ipv6_loopback() {
            return Err("recvfrom() source address is not ::1".to_string());
        }
        Ok(())
    })
}

// full TCP connection over ipv6 loopback: listen, connect, accept, send, recv
fn test_tcp_loopback_v6() -> Result<(), String> {
    let listen_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if listen_fd < 0 {
        return Err(format!(
            "socket(AF_INET6, SOCK_STREAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    let addr = sockaddr_in6(ipv6_loopback(), PORT_TCP_LOOPBACK);

    // set SO_REUSEADDR so a re-run of the test in a time-wait state still binds
    let reuse: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            listen_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &reuse as *const _ as *const libc::c_void,
            std::mem::size_of_val(&reuse) as libc::socklen_t,
        )
    };

    let rv = unsafe {
        libc::bind(
            listen_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    if rv != 0 {
        return Err(format!("bind(): {} ({})", get_errno(), test_utils::get_errno_message(get_errno())));
    }
    let rv = unsafe { libc::listen(listen_fd, 1) };
    if rv != 0 {
        return Err(format!("listen(): {}", test_utils::get_errno()));
    }

    let payload = b"ipv6 tcp loopback";

    // connect from a separate thread, as accept() blocks
    let client = thread::spawn(move || {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        if rv != 0 {
            panic!("connect(): {}", test_utils::get_errno());
        }

        let n = unsafe {
            libc::send(fd, payload.as_ptr() as *const libc::c_void, payload.len(), 0)
        };
        if n as usize != payload.len() {
            panic!("send() sent {n} of {} bytes", payload.len());
        }

        unsafe { libc::close(fd) };
    });

    let conn_fd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if conn_fd < 0 {
        return Err(format!("accept(): {}", test_utils::get_errno()));
    }

    // the accepted connection should be from the ipv6 loopback address
    let mut peer: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    let rv = unsafe { libc::getpeername(conn_fd, &mut peer as *mut _ as *mut libc::sockaddr, &mut len) };
    if rv != 0 {
        return Err(format!("getpeername(): {}", test_utils::get_errno()));
    }
    if peer.sin6_addr.s6_addr != ipv6_loopback() {
        return Err("getpeername() address is not ::1".to_string());
    }
    if peer.sin6_family != libc::AF_INET6 as u16 {
        return Err("getpeername() family is not AF_INET6".to_string());
    }

    let mut buf = [0 as u8; 64];
    let n = unsafe { libc::recv(conn_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n as usize != payload.len() {
        return Err(format!("recv() received {n} of {} bytes", payload.len()));
    }
    if &buf[..n as usize] != payload {
        return Err("recv() data mismatch".to_string());
    }

    unsafe { libc::close(conn_fd) };
    unsafe { libc::close(listen_fd) };
    client.join().map_err(|_| "client thread panicked".to_string())?;

    Ok(())
}

// the IPV6_V6ONLY socket option must round-trip through set/getsockopt()
fn test_sockopt_v6only() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_INET6, SOCK_DGRAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    run_and_close_fds(&[fd], || {
        let mut v6only: libc::c_int = -1;
        let mut len = std::mem::size_of_val(&v6only) as libc::socklen_t;
        let rv = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &mut v6only as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rv != 0 {
            return Err(format!(
                "getsockopt(IPV6_V6ONLY): {} ({})",
                get_errno(),
                test_utils::get_errno_message(get_errno()),
            ));
        }
        // the default is system-dependent (net.ipv6.bindv6only), so only
        // check that it is a valid boolean
        if v6only != 0 && v6only != 1 {
            return Err(format!("getsockopt(IPV6_V6ONLY) returned {v6only}, expected 0 or 1"));
        }

        for &val in &[1, 0] {
            let rv = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                )
            };
            if rv != 0 {
                return Err(format!("setsockopt(IPV6_V6ONLY, {val}): {}", test_utils::get_errno()));
            }

            let mut readback: libc::c_int = -1;
            let mut len = std::mem::size_of_val(&readback) as libc::socklen_t;
            let rv = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &mut readback as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if rv != 0 || readback != val {
                return Err(format!(
                    "setsockopt(IPV6_V6ONLY, {val}) did not round-trip (rv={rv}, readback={readback})"
                ));
            }
        }
        Ok(())
    })
}

// a dual-stack socket (:: with IPV6_V6ONLY=0) must conflict with an ipv4
// bind to the same port
fn test_dual_stack_bind_v6_connect_v4() -> Result<(), String> {
    let fd_v6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    let fd_v4 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd_v6 < 0 || fd_v4 < 0 {
        return Err(format!(
            "socket(): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    run_and_close_fds(&[fd_v6, fd_v4], || {
        // explicitly disable V6ONLY to enable the ipv4-mapped address family
        let v6only: libc::c_int = 0;
        let rv = unsafe {
            libc::setsockopt(
                fd_v6,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &v6only as *const _ as *const libc::c_void,
                std::mem::size_of_val(&v6only) as libc::socklen_t,
            )
        };
        if rv != 0 {
            return Err(format!("setsockopt(IPV6_V6ONLY, 0): {}", test_utils::get_errno()));
        }

        let addr_v6 = sockaddr_in6(ipv6_unspecified(), PORT_DUAL_STACK);
        let rv = unsafe {
            libc::bind(
                fd_v6,
                &addr_v6 as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr_v6) as libc::socklen_t,
            )
        };
        if rv != 0 {
            return Err(format!(
                "bind(::{PORT_DUAL_STACK}): {} ({})",
                get_errno(),
                test_utils::get_errno_message(get_errno()),
            ));
        }

        // the ipv4 wildcard address is served by the dual-stack socket, so
        // the ipv4 bind must conflict with it
        let addr_v4 = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: PORT_DUAL_STACK.to_be(),
            sin_addr: libc::in_addr {
                s_addr: libc::INADDR_ANY.to_be(),
            },
            sin_zero: [0; 8],
        };
        let rv = unsafe {
            libc::bind(
                fd_v4,
                &addr_v4 as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr_v4) as libc::socklen_t,
            )
        };
        errno_is(rv, Some(libc::EADDRINUSE))
            .map_err(|e| format!("bind(0.0.0.0:{PORT_DUAL_STACK}) while :: is bound: {e}"))
    })
}
