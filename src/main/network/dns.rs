use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

// The memfd syscall is not supported in our miri test environment.
#[cfg(not(miri))]
use rustix::fs::MemfdFlags;
use shadow_shim_helper_rs::HostId;

#[derive(Debug)]
struct Database {
    // We can use `String` here because [`crate::core::configuration::HostName`] limits the
    // configured host names to a subset of ascii, which are always valid utf-8.
    name_index: HashMap<String, Vec<Arc<Record>>>,
    addr_index: HashMap<IpAddr, Arc<Record>>,
}

#[derive(Debug)]
struct Record {
    id: HostId,
    addr: IpAddr,
    name: String,
}

#[derive(Debug, PartialEq)]
pub enum RegistrationError {
    BroadcastAddrInvalid,
    LoopbackAddrInvalid(IpAddr),
    MulticastAddrInvalid(IpAddr),
    UnspecifiedAddrInvalid,
    NameInvalid(String),
    AddrExists(IpAddr),
    NameExists(String),
}

impl Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrationError::BroadcastAddrInvalid => write!(
                f,
                "broadcast address '{}' is invalid in DNS",
                std::net::Ipv4Addr::BROADCAST
            ),
            RegistrationError::LoopbackAddrInvalid(addr) => {
                write!(f, "loopback address '{addr}' is invalid in DNS",)
            }
            RegistrationError::MulticastAddrInvalid(addr) => {
                write!(f, "multicast address '{addr}' is invalid in DNS")
            }
            RegistrationError::UnspecifiedAddrInvalid => write!(
                f,
                "unspecified address '{}' is invalid in DNS",
                std::net::Ipv4Addr::UNSPECIFIED
            ),
            RegistrationError::NameInvalid(name) => write!(f, "name '{name}' is invalid in DNS"),
            RegistrationError::NameExists(name) => {
                write!(
                    f,
                    "a DNS registration record already exists for name '{name}'"
                )
            }
            RegistrationError::AddrExists(addr) => {
                write!(
                    f,
                    "a DNS registration record already exists for address '{addr}'"
                )
            }
        }
    }
}

impl std::error::Error for RegistrationError {}

#[derive(Debug)]
pub struct DnsBuilder {
    db: Database,
}

impl DnsBuilder {
    pub fn new() -> Self {
        Self {
            db: Database {
                name_index: HashMap::new(),
                addr_index: HashMap::new(),
            },
        }
    }

    pub fn register(
        &mut self,
        id: HostId,
        addr: IpAddr,
        name: String,
    ) -> Result<(), RegistrationError> {
        // Make sure we don't register reserved addresses or names.
        if addr.is_unspecified() {
            return Err(RegistrationError::UnspecifiedAddrInvalid);
        } else if addr.is_loopback() {
            return Err(RegistrationError::LoopbackAddrInvalid(addr));
        } else if matches!(addr, IpAddr::V4(addr) if addr.is_broadcast()) {
            return Err(RegistrationError::BroadcastAddrInvalid);
        } else if addr.is_multicast() {
            return Err(RegistrationError::MulticastAddrInvalid(addr));
        } else if name.eq_ignore_ascii_case("localhost") {
            return Err(RegistrationError::NameInvalid(name));
        }

        // A single HostId is allowed to register multiple name/addr mappings,
        // but only vacant addresses and names are allowed. Registering a
        // second address for an existing name (for example the IPv6 address of
        // a host that already has an IPv4 address) is allowed.
        match self.db.addr_index.entry(addr) {
            Entry::Occupied(_) => Err(RegistrationError::AddrExists(addr)),
            Entry::Vacant(addr_entry) => match self.db.name_index.entry(name.clone()) {
                Entry::Occupied(mut records) => {
                    if records.get().iter().all(|record| record.id == id) {
                        let record = Arc::new(Record { id, addr, name });
                        records.get_mut().push(record.clone());
                        addr_entry.insert(record);
                        Ok(())
                    } else {
                        Err(RegistrationError::NameExists(
                            records.get().first().unwrap().name.clone(),
                        ))
                    }
                }
                Entry::Vacant(name_entry) => {
                    let record = Arc::new(Record { id, addr, name });
                    name_entry.insert(vec![record.clone()]);
                    addr_entry.insert(record);
                    Ok(())
                }
            },
        }
    }

    pub fn into_dns(self) -> std::io::Result<Dns> {
        // The memfd syscall is not supported in our miri test environment.
        #[cfg(miri)]
        let mut file = tempfile::tempfile()?;
        #[cfg(not(miri))]
        let mut file = {
            let name = format!("shadow_dns_hosts_file_{}", std::process::id());
            File::from(rustix::fs::memfd_create(name, MemfdFlags::CLOEXEC)?)
        };

        // Sort the records to produce deterministic ordering in the hosts file.
        let mut records: Vec<Arc<Record>> = self.db.addr_index.values().cloned().collect();
        records.sort_by(|a, b| a.addr.cmp(&b.addr));

        writeln!(file, "127.0.0.1 localhost")?;
        writeln!(file, "::1 localhost")?;
        for record in records.iter() {
            // Make it easier to debug if somehow we ever got a name with whitespace.
            assert!(!record.name.as_bytes().iter().any(u8::is_ascii_whitespace));
            writeln!(file, "{} {}", record.addr, record.name)?;
        }

        Ok(Dns {
            db: self.db,
            hosts_file: file,
        })
    }
}

impl Default for DnsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Dns {
    db: Database,
    // Keep this handle while Dns is valid to prevent closing the file
    // containing the hosts database in /etc/hosts format.
    hosts_file: File,
}

impl Dns {
    pub fn addr_to_host_id(&self, addr: IpAddr) -> Option<HostId> {
        self.db.addr_index.get(&addr).map(|record| record.id)
    }

    #[cfg(test)]
    fn addr_to_name(&self, addr: IpAddr) -> Option<&str> {
        self.db
            .addr_index
            .get(&addr)
            .map(|record| record.name.as_str())
    }

    /// Returns the first IPv4 address registered for the name, if any.
    pub fn name_to_addr_v4(&self, name: &str) -> Option<std::net::Ipv4Addr> {
        self.name_to_addrs(name).into_iter().find_map(|addr| match addr {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        })
    }

    /// Returns the first IPv6 address registered for the name, if any.
    pub fn name_to_addr_v6(&self, name: &str) -> Option<std::net::Ipv6Addr> {
        self.name_to_addrs(name).into_iter().find_map(|addr| match addr {
            IpAddr::V6(addr) => Some(addr),
            IpAddr::V4(_) => None,
        })
    }

    /// Returns all addresses registered for the name.
    pub fn name_to_addrs(&self, name: &str) -> Vec<IpAddr> {
        self.db
            .name_index
            .get(name)
            .map(|records| records.iter().map(|record| record.addr).collect())
            .unwrap_or_default()
    }

    pub fn hosts_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.hosts_file.as_raw_fd()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host_a() -> (HostId, IpAddr, String) {
        let id = HostId::from(0);
        let addr = IpAddr::V4(std::net::Ipv4Addr::new(100, 1, 2, 3));
        let name = String::from("myhost");
        (id, addr, name)
    }

    fn host_b() -> (HostId, IpAddr, String) {
        let id = HostId::from(1);
        let addr = IpAddr::V4(std::net::Ipv4Addr::new(200, 3, 2, 1));
        let name = String::from("theirhost");
        (id, addr, name)
    }

    #[test]
    fn register() {
        let (id_a, addr_a, name_a) = host_a();
        let (id_b, addr_b, name_b) = host_b();

        let mut builder = DnsBuilder::new();

        assert!(builder.register(id_a, addr_a, name_a.clone()).is_ok());

        assert_eq!(
            builder.register(id_b, IpAddr::V4(Ipv4Addr::UNSPECIFIED), name_b.clone()),
            Err(RegistrationError::UnspecifiedAddrInvalid)
        );
        assert_eq!(
            builder.register(id_b, IpAddr::V4(Ipv4Addr::BROADCAST), name_b.clone()),
            Err(RegistrationError::BroadcastAddrInvalid)
        );
        let multicast_example_addr = Ipv4Addr::new(224, 0, 0, 1);
        assert_eq!(
            // Multicast addresses not allowed.
            builder.register(id_b, IpAddr::V4(multicast_example_addr), name_b.clone()),
            Err(RegistrationError::MulticastAddrInvalid(
                IpAddr::V4(multicast_example_addr)
            ))
        );
        assert_eq!(
            builder.register(id_b, IpAddr::V4(Ipv4Addr::LOCALHOST), name_b.clone()),
            Err(RegistrationError::LoopbackAddrInvalid(IpAddr::V4(
                Ipv4Addr::LOCALHOST
            )))
        );
        let localhost_string = String::from("localhost");
        assert_eq!(
            builder.register(id_b, addr_b, localhost_string.clone()),
            Err(RegistrationError::NameInvalid(localhost_string))
        );
        assert_eq!(
            builder.register(id_b, addr_a, name_b.clone()),
            Err(RegistrationError::AddrExists(addr_a))
        );
        assert_eq!(
            builder.register(id_b, addr_b, name_a.clone()),
            Err(RegistrationError::NameExists(name_a))
        );

        assert!(builder.register(id_b, addr_b, name_b.clone()).is_ok());
    }

    #[test]
    fn lookups() {
        let (id_a, addr_a, name_a) = host_a();
        let (id_b, addr_b, name_b) = host_b();

        let mut builder = DnsBuilder::new();
        builder.register(id_a, addr_a, name_a.clone()).unwrap();
        builder.register(id_b, addr_b, name_b.clone()).unwrap();
        let dns = builder.into_dns().unwrap();

        assert_eq!(dns.addr_to_host_id(addr_a), Some(id_a));
        assert_eq!(dns.addr_to_host_id(addr_b), Some(id_b));
        assert_eq!(
            dns.addr_to_host_id(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            None
        );

        assert_eq!(dns.addr_to_name(addr_a), Some(name_a.as_str()));
        assert_eq!(dns.addr_to_name(addr_b), Some(name_b.as_str()));
        assert_eq!(
            dns.addr_to_name(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            None
        );

        assert_eq!(dns.name_to_addr_v4(&name_a), Some(Ipv4Addr::new(100, 1, 2, 3)));
        assert_eq!(dns.name_to_addr_v4(&name_b), Some(Ipv4Addr::new(200, 3, 2, 1)));
        assert_eq!(dns.name_to_addr_v4("empty"), None);
        assert_eq!(dns.name_to_addr_v4("localhost"), None);

        assert_eq!(dns.name_to_addrs(&name_a), vec![addr_a]);
        assert_eq!(dns.name_to_addrs(&name_b), vec![addr_b]);
        assert!(dns.name_to_addrs("empty").is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hosts_file() {
        let (id_a, addr_a, name_a) = host_a();
        let (id_b, addr_b, name_b) = host_b();

        let mut builder = DnsBuilder::new();
        builder.register(id_a, addr_a, name_a.clone()).unwrap();
        builder.register(id_b, addr_b, name_b.clone()).unwrap();
        let dns = builder.into_dns().unwrap();

        let contents = std::fs::read_to_string(dns.hosts_path()).unwrap();

        let expected = "127.0.0.1 localhost\n::1 localhost\n100.1.2.3 myhost\n200.3.2.1 theirhost\n";
        assert_eq!(contents.as_str(), expected);
        let unexpected = "127.0.0.1 localhost\n::1 localhost\n200.3.2.1 theirhost\n100.1.2.3 myhost\n";
        assert_ne!(contents.as_str(), unexpected);
    }

    #[test]
    fn dual_stack_registration() {
        let (id, addr_v4, name) = host_a();
        let addr_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let mut builder = DnsBuilder::new();
        builder.register(id, addr_v4, name.clone()).unwrap();
        // a second address for the same host and name is allowed
        builder.register(id, addr_v6, name.clone()).unwrap();

        let dns = builder.into_dns().unwrap();

        assert_eq!(
            dns.name_to_addrs(&name),
            vec![addr_v4, addr_v6]
        );
        assert_eq!(
            dns.name_to_addr_v4(&name),
            Some(std::net::Ipv4Addr::new(100, 1, 2, 3))
        );
        assert_eq!(
            dns.name_to_addr_v6(&name),
            Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(dns.addr_to_host_id(addr_v4), Some(id));
        assert_eq!(dns.addr_to_host_id(addr_v6), Some(id));

        // a different host may not register an additional address under the
        // same name
        let mut builder = DnsBuilder::new();
        builder.register(id, addr_v4, name.clone()).unwrap();
        let (id_b, addr_b, _) = host_b();
        assert_eq!(
            builder.register(id_b, addr_v6, name.clone()),
            Err(RegistrationError::NameExists(name))
        );
        let _ = addr_b;
    }
}
