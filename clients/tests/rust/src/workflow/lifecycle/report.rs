use std::collections::BTreeMap;

use serde::Serialize;

use super::super::model::StackMetadata;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workflow) struct StatusReport {
    pub(super) configured: StackMetadata,
    pub(super) runtime: RuntimeReport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeReport {
    pub(super) resources_absent: bool,
    pub(super) all_services_ready: bool,
    pub(super) containers: BTreeMap<String, ContainerReport>,
    pub(super) networks: Vec<NetworkReport>,
    pub(super) volumes: VolumeSetReport,
    pub(super) assigned_ports: Vec<AssignedPortReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContainerReport {
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    pub(super) state: String,
    pub(super) running: bool,
    pub(super) restarting: bool,
    pub(super) dead: bool,
    pub(super) started_at: Option<String>,
    pub(super) health: Option<String>,
    pub(super) image: ImageReport,
    pub(super) listeners: Vec<ListenerReport>,
    pub(super) readiness: ReadinessReport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageReport {
    pub(super) configured_tag: Option<String>,
    pub(super) expected_id: Option<String>,
    pub(super) actual_id: Option<String>,
    pub(super) matches_expected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListenerReport {
    pub(super) container_port: String,
    pub(super) host_addresses: Vec<String>,
    pub(super) host_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadinessReport {
    pub(super) ready: bool,
    pub(super) detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NetworkReport {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) driver: String,
    pub(super) project_label: Option<String>,
    pub(super) network_label: Option<String>,
    pub(super) container_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VolumeSetReport {
    pub(super) declared: Vec<VolumeReport>,
    pub(super) anonymous_vault: Vec<VolumeReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VolumeReport {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) driver: String,
    pub(super) project_label: Option<String>,
    pub(super) volume_label: Option<String>,
    pub(super) destination: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssignedPortReport {
    pub(super) role: String,
    pub(super) port: u16,
    pub(super) listener_service: Option<String>,
    pub(super) free: bool,
}
