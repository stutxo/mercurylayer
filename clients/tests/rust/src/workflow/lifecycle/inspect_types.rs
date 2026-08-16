use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct ContainerInspect {
    #[serde(rename = "Id")]
    pub(super) id: String,
    #[serde(rename = "Name")]
    pub(super) name: String,
    #[serde(rename = "Image")]
    pub(super) image: String,
    #[serde(rename = "Config")]
    pub(super) config: ContainerConfig,
    #[serde(rename = "State")]
    pub(super) state: ContainerState,
    #[serde(rename = "NetworkSettings")]
    pub(super) network_settings: NetworkSettings,
    #[serde(rename = "Mounts", default)]
    pub(super) mounts: Vec<MountInspect>,
}

#[derive(Deserialize)]
pub(super) struct ContainerConfig {
    #[serde(rename = "Image")]
    pub(super) image: String,
    #[serde(rename = "Labels")]
    pub(super) labels: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
pub(super) struct ContainerState {
    #[serde(rename = "Status")]
    pub(super) status: String,
    #[serde(rename = "Running")]
    pub(super) running: bool,
    #[serde(rename = "Restarting")]
    pub(super) restarting: bool,
    #[serde(rename = "Dead")]
    pub(super) dead: bool,
    #[serde(rename = "StartedAt")]
    pub(super) started_at: String,
    #[serde(rename = "Health")]
    pub(super) health: Option<ContainerHealth>,
}

#[derive(Deserialize)]
pub(super) struct ContainerHealth {
    #[serde(rename = "Status")]
    pub(super) status: String,
}

#[derive(Deserialize)]
pub(super) struct NetworkSettings {
    #[serde(rename = "Networks", default)]
    pub(super) networks: BTreeMap<String, NetworkAttachment>,
    #[serde(rename = "Ports", default)]
    pub(super) ports: BTreeMap<String, Option<Vec<PortBinding>>>,
}

#[derive(Deserialize)]
pub(super) struct NetworkAttachment {
    #[serde(rename = "NetworkID")]
    pub(super) network_id: String,
}

#[derive(Deserialize)]
pub(super) struct PortBinding {
    #[serde(rename = "HostIp")]
    pub(super) host_ip: String,
    #[serde(rename = "HostPort")]
    pub(super) host_port: String,
}

#[derive(Deserialize)]
pub(super) struct MountInspect {
    #[serde(rename = "Type")]
    pub(super) kind: String,
    #[serde(rename = "Name", default)]
    pub(super) name: String,
    #[serde(rename = "Destination")]
    pub(super) destination: String,
    #[serde(rename = "RW")]
    pub(super) read_write: bool,
}

#[derive(Deserialize)]
pub(super) struct NetworkInspect {
    #[serde(rename = "Id")]
    pub(super) id: String,
    #[serde(rename = "Name")]
    pub(super) name: String,
    #[serde(rename = "Driver")]
    pub(super) driver: String,
    #[serde(rename = "Labels", default)]
    pub(super) labels: BTreeMap<String, String>,
    #[serde(rename = "Containers", default)]
    pub(super) containers: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct VolumeInspect {
    #[serde(rename = "Name")]
    pub(super) name: String,
    #[serde(rename = "Driver")]
    pub(super) driver: String,
    #[serde(rename = "Labels", default, deserialize_with = "null_map")]
    pub(super) labels: BTreeMap<String, String>,
}

fn null_map<'de, D>(deserializer: D) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<BTreeMap<String, String>>::deserialize(deserializer).map(Option::unwrap_or_default)
}
