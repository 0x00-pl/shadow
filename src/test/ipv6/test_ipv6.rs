/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

//! Tests for IPv6-related socket operations.
//!
//! Shadow supports IPv6, but not dual-stack sockets: a socket bound to `::`
//! with `IPV6_V6ONLY=0` does not conflict with (or receive traffic for) IPv4
//! addresses on the same port like it would on Linux.
//! `test_dual_stack_bind_v6_connect_v4` is an intentional "not yet
//! implemented" marker for that behavior.
//!
//! Under native Linux (the "--libc-passing" environment) the full IPv6 socket
//! API is exercised and must pass, validating the tests themselves against
//! real kernel behavior.

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
const PORT_TCP_REFUSED: u16 = 22107;
const PORT_UDP_SENDMSG: u16 = 22108;
const PORT_DNS: u16 = 22109;

fn main() -> Result<(), String> {
    // two-host simulation tests run this binary with a role argument; the
    // client and server run as separate managed processes on separate hosts
    let args: Vec<String> = std::env::args().collect();
    if let Some(role) = args
        .iter()
        .find(|x| matches!(x.as_str(), "udp-server" | "udp-client" | "tcp-server" | "tcp-client"))
    {
        let port: u16 = args
            .iter()
            .position(|x| x == role)
            .and_then(|i| args.get(i + 1))
            .and_then(|x| x.parse().ok())
            .ok_or_else(|| format!("missing port argument for role {role}"))?;
        return run_role(role, port);
    }

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
        test_utils::ShadowTest::new(
            "test_tcp_connect_refused_v6",
            test_tcp_connect_refused_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_udp_sendmsg_recvmsg_v6",
            test_udp_sendmsg_recvmsg_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_getaddrinfo_localhost_v6",
            test_getaddrinfo_localhost_v6,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
    ]);

    tests
}

/// Runs one side of a two-host simulation test. The client and server run as
/// separate managed processes on separate hosts, exercising cross-host IPv6
/// packet forwarding, DNS resolution via `getaddrinfo()`, and explicit IPv6
/// addresses from the simulation config.
fn run_role(role: &str, port: u16) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    const PAYLOAD: &[u8] = b"ipv6 two-host test payload";
    const TIMEOUT: Duration = Duration::from_secs(8);

    // resolves the "server" hostname to an IPv6 address using getaddrinfo()
    let resolve_server_v6 = || -> Result<SocketAddr, String> {
        ("server", port)
            .to_socket_addrs()
            .map_err(|e| format!("getaddrinfo(server): {e}"))?
            .find(|a| a.is_ipv6())
            .ok_or_else(|| "getaddrinfo(server) returned no IPv6 address".to_string())
    };

    match role {
        "udp-server" => {
            let sock = UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))
                .map_err(|e| format!("bind: {e}"))?;
            sock.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;

            let mut buf = [0u8; 256];
            let (n, peer) = sock
                .recv_from(&mut buf)
                .map_err(|e| format!("recv_from: {e}"))?;
            if &buf[..n] != PAYLOAD {
                return Err(format!("unexpected payload {:#?}", &buf[..n]));
            }

            sock.send_to(&buf[..n], peer)
                .map_err(|e| format!("send_to: {e}"))?;
            println!("udp-server: ok (peer {peer})");
            Ok(())
        }
        "udp-client" => {
            let addr = resolve_server_v6()?;

            let sock = UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))
                .map_err(|e| format!("bind: {e}"))?;
            sock.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;

            sock.send_to(PAYLOAD, addr)
                .map_err(|e| format!("send_to: {e}"))?;

            let mut buf = [0u8; 256];
            let (n, src) = sock
                .recv_from(&mut buf)
                .map_err(|e| format!("recv_from: {e}"))?;
            if src != addr {
                return Err(format!("reply from {src}, expected {addr}"));
            }
            if &buf[..n] != PAYLOAD {
                return Err(format!("unexpected reply payload {:#?}", &buf[..n]));
            }
            println!("udp-client: ok ({addr})");
            Ok(())
        }
        "tcp-server" => {
            let listener = TcpListener::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))
                .map_err(|e| format!("bind: {e}"))?;

            let (mut stream, peer) = listener
                .accept()
                .map_err(|e| format!("accept: {e}"))?;
            stream
                .set_read_timeout(Some(TIMEOUT))
                .map_err(|e| e.to_string())?;

            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if &buf[..n] != PAYLOAD {
                return Err(format!("unexpected payload {:#?}", &buf[..n]));
            }

            stream.write_all(&buf[..n]).map_err(|e| format!("write: {e}"))?;
            println!("tcp-server: ok (peer {peer})");
            Ok(())
        }
        "tcp-client" => {
            let addr = resolve_server_v6()?;

            let mut stream =
                TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
            stream
                .set_read_timeout(Some(TIMEOUT))
                .map_err(|e| e.to_string())?;

            stream.write_all(PAYLOAD).map_err(|e| format!("write: {e}"))?;
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|e| format!("shutdown: {e}"))?;

            let mut buf = Vec::new();
            stream
                .read_to_end(&mut buf)
                .map_err(|e| format!("read: {e}"))?;
            if buf != PAYLOAD {
                return Err(format!("unexpected echo payload {:#?}", &buf[..]));
            }
            println!("tcp-client: ok ({addr})");
            Ok(())
        }
        _ => unreachable!(),
    }
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

// a TCP connect to a loopback port with no listener must be refused
fn test_tcp_connect_refused_v6() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_INET6, SOCK_STREAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    let addr = sockaddr_in6(ipv6_loopback(), PORT_TCP_REFUSED);
    run_and_close_fds(&[fd], || {
        let rv = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        errno_is(rv, Some(libc::ECONNREFUSED))
            .map_err(|e| format!("connect(::1:{PORT_TCP_REFUSED}): {e}"))
    })
}

// sendmsg()/recvmsg() with IPv6 addresses
fn test_udp_sendmsg_recvmsg_v6() -> Result<(), String> {
    let fd_send = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    let fd_recv = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd_send < 0 || fd_recv < 0 {
        return Err(format!(
            "socket(AF_INET6, SOCK_DGRAM): {} ({})",
            get_errno(),
            test_utils::get_errno_message(get_errno()),
        ));
    }

    let recv_addr = sockaddr_in6(ipv6_loopback(), PORT_UDP_SENDMSG);
    run_and_close_fds(&[fd_send, fd_recv], || {
        let rv = unsafe {
            libc::bind(
                fd_recv,
                &recv_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&recv_addr) as libc::socklen_t,
            )
        };
        if rv != 0 {
            return Err(format!("bind: {} ({})", get_errno(), test_utils::get_errno_message(get_errno())));
        }

        let payload = b"ipv6 sendmsg";
        let iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let msg = libc::msghdr {
            msg_name: &recv_addr as *const _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of_val(&recv_addr) as libc::socklen_t,
            msg_iov: &iov as *const _ as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let n = unsafe { libc::sendmsg(fd_send, &msg, 0) };
        if n as usize != payload.len() {
            return Err(format!("sendmsg sent {n} of {} bytes", payload.len()));
        }

        let mut buf = [0u8; 64];
        let mut src: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg = libc::msghdr {
            msg_name: &mut src as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of_val(&src) as libc::socklen_t,
            msg_iov: &mut iov as *mut _ as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let n = unsafe { libc::recvmsg(fd_recv, &mut msg, 0) };
        if n as usize != payload.len() {
            return Err(format!("recvmsg received {n} of {} bytes", payload.len()));
        }
        if &buf[..n as usize] != payload {
            return Err("recvmsg data mismatch".to_string());
        }
        if src.sin6_addr.s6_addr != ipv6_loopback() {
            return Err("recvmsg source address is not ::1".to_string());
        }
        Ok(())
    })
}

// getaddrinfo("localhost") must include the IPv6 loopback address
fn test_getaddrinfo_localhost_v6() -> Result<(), String> {
    use std::net::ToSocketAddrs;

    let addrs: Vec<std::net::SocketAddr> = ("localhost", PORT_DNS)
        .to_socket_addrs()
        .map_err(|e| format!("getaddrinfo(localhost): {e}"))?
        .collect();

    let has_v6_loopback = addrs.iter().any(|a| {
        a.is_ipv6() && a.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    });
    if !has_v6_loopback {
        return Err(format!(
            "getaddrinfo(localhost) returned {addrs:?}, expected it to include [::1]"
        ));
    }
    Ok(())
}
