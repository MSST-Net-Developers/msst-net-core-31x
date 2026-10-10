//! `msst-net-core` — the desktop Core daemon.  All logic lives in the library.

fn main() -> anyhow::Result<()> {
    msst_net_core::main_entry()
}
