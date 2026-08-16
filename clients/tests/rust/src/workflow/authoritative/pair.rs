use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::super::model::{PortMap, Project};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::workflow) struct PairSpec {
    primary: Project,
    primary_ports: PortMap,
    control: Project,
    control_ports: PortMap,
}

impl PairSpec {
    pub(in crate::workflow) fn new(
        primary: Project,
        primary_base: u16,
        control: Option<Project>,
        control_base: Option<u16>,
    ) -> Result<Self, String> {
        let primary_ports = PortMap::from_base(primary_base)?;
        let control = match control {
            Some(control) => control,
            None => Project::parse(&derived_control_project(primary.as_str()))?,
        };
        let control_base = control_base.unwrap_or_else(|| default_control_base(primary_base));
        let control_ports = PortMap::from_base(control_base)
            .map_err(|error| format!("invalid control port range: {error}"))?;
        if control == primary {
            return Err("primary and control projects must be unequal".into());
        }
        let primary_set = primary_ports
            .ordered()
            .into_iter()
            .map(|(_, port)| port)
            .collect::<BTreeSet<_>>();
        let control_set = control_ports
            .ordered()
            .into_iter()
            .map(|(_, port)| port)
            .collect::<BTreeSet<_>>();
        if !primary_set.is_disjoint(&control_set) {
            return Err("primary and control eight-port ranges must not overlap".into());
        }
        Ok(Self {
            primary,
            primary_ports,
            control,
            control_ports,
        })
    }

    pub(in crate::workflow) fn primary(&self) -> &Project {
        &self.primary
    }

    pub(in crate::workflow) fn primary_ports(&self) -> PortMap {
        self.primary_ports
    }

    pub(in crate::workflow) fn control(&self) -> &Project {
        &self.control
    }

    pub(in crate::workflow) fn control_ports(&self) -> PortMap {
        self.control_ports
    }

    pub(super) fn all_ports(&self) -> Vec<u16> {
        self.primary_ports
            .ordered()
            .into_iter()
            .chain(self.control_ports.ordered())
            .map(|(_, port)| port)
            .collect()
    }
}

fn derived_control_project(primary: &str) -> String {
    let digest = hex::encode(Sha256::digest(primary.as_bytes()));
    format!("b448ctl-{}", &digest[..12])
}

fn default_control_base(primary_base: u16) -> u16 {
    if primary_base <= 65_520 {
        primary_base + 8
    } else {
        primary_base - 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charter_defaults_are_exact_and_boundary_safe() {
        let primary = Project::parse("b448-rust-authoritative").unwrap();
        let pair = PairSpec::new(primary, 25_600, None, None).unwrap();
        assert_eq!(pair.control().as_str(), "b448ctl-c4379c5197a0");
        assert_eq!(pair.primary_ports().base(), 25_600);
        assert_eq!(pair.control_ports().base(), 25_608);

        let high = PairSpec::new(Project::parse("high").unwrap(), 65_521, None, None).unwrap();
        assert_eq!(high.control_ports().base(), 65_513);
    }

    #[test]
    fn validated_overrides_pass_and_equal_or_overlapping_pairs_fail() {
        let primary = Project::parse("primary").unwrap();
        let pair = PairSpec::new(
            primary.clone(),
            25_600,
            Some(Project::parse("control").unwrap()),
            Some(26_000),
        )
        .unwrap();
        assert_eq!(pair.control().as_str(), "control");
        assert_eq!(pair.control_ports().base(), 26_000);
        assert!(
            PairSpec::new(primary.clone(), 25_600, Some(primary.clone()), Some(26_000)).is_err()
        );
        assert!(PairSpec::new(
            primary,
            25_600,
            Some(Project::parse("control").unwrap()),
            Some(25_607),
        )
        .is_err());
    }
}
