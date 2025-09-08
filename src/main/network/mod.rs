//! The network simulation.
//!
//! This contains code that simulates the Internet and upstream routers. It does not contain any
//! emulation of Linux networking behaviour, which exists in the [`crate::host`] module.

use std::net::IpAddr;

use crate::network::packet::PacketRc;

pub mod dns;
pub mod graph;
pub mod packet;
pub mod relay;
pub mod router;

pub trait PacketDevice {
    /// The device's primary address. Devices that support multiple addresses
    /// (for example IPv4 and IPv6) should also override [`Self::has_address`].
    fn get_address(&self) -> IpAddr;

    /// Returns whether this device handles packets addressed to `addr`.
    fn has_address(&self, addr: IpAddr) -> bool {
        self.get_address() == addr
    }

    fn pop(&self) -> Option<PacketRc>;
    fn push(&self, packet: PacketRc);
}

#[cfg(test)]
mod tests {
    use shadow_shim_helper_rs::{emulated_time::EmulatedTime, simulation_time::SimulationTime};

    pub fn mock_time_millis(millis_since_sim_start: u64) -> EmulatedTime {
        let simtime = SimulationTime::from_millis(millis_since_sim_start);
        EmulatedTime::from_abs_simtime(simtime)
    }
}
