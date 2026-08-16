use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::{json, Value};

use super::super::argv::{ArgvCommand, CommandOutput, CommandRunner};
use super::super::build::{VerifiedBuild, VerifiedImage};
use super::super::model::{
    BuildFingerprints, BuildResolution, BuildSource, ComposeHashes, PortMap, Project,
    ResolvedImage, ResolvedImages, ResolvedLockboxImages, StackMetadata, INQUISITION_IMAGE,
    LOCKBOX_IMAGE_PREFIX, MERCURY_IMAGE_PREFIX, TOKEN_IMAGE_PREFIX,
};
use super::contract::{
    declared_volume_name, expected_from_verified, expected_ports, network_name, SERVICES,
};
use super::readiness::{HostProbe, HttpAttempt, HttpResponse};
use super::BuildVerifier;

pub(super) const PROJECT: &str = "life_test";

pub(super) fn image_id(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

pub(super) fn build() -> VerifiedBuild {
    VerifiedBuild {
        mercury: VerifiedImage {
            tag: format!("{MERCURY_IMAGE_PREFIX}{}", "a".repeat(16)),
            image_id: image_id('1'),
        },
        token: VerifiedImage {
            tag: format!("{TOKEN_IMAGE_PREFIX}{}", "b".repeat(16)),
            image_id: image_id('2'),
        },
        lockbox: VerifiedImage {
            tag: format!("{LOCKBOX_IMAGE_PREFIX}{}", "c".repeat(16)),
            image_id: image_id('3'),
        },
        lockbox_rng: VerifiedImage {
            tag: format!("{LOCKBOX_IMAGE_PREFIX}{}-rng-{PROJECT}", "c".repeat(16)),
            image_id: image_id('8'),
        },
        inquisition: VerifiedImage {
            tag: INQUISITION_IMAGE.into(),
            image_id: image_id('4'),
        },
    }
}

pub(super) fn metadata(root: &Path) -> StackMetadata {
    let project = Project::parse(PROJECT).unwrap();
    let mut metadata = StackMetadata::new(root, project, PortMap::from_base(24000).unwrap());
    let build = build();
    let mut images = ResolvedImages::default();
    images.set_mercury(resolved('a', &build.mercury));
    images.set_token(resolved('b', &build.token));
    images.set_lockbox(ResolvedLockboxImages::new(
        resolved('c', &build.lockbox),
        resolved('c', &build.lockbox_rng),
    ));
    images.set_inquisition(resolved('d', &build.inquisition));
    metadata.set_build_resolution(BuildResolution::new(
        BuildSource::new(
            "0".repeat(40),
            "1".repeat(64),
            ComposeHashes::new("2".repeat(64), "3".repeat(64)),
        ),
        BuildFingerprints::new(
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
        ),
        images,
    ));
    metadata
}

fn resolved(fingerprint: char, image: &VerifiedImage) -> ResolvedImage {
    ResolvedImage::new(
        fingerprint.to_string().repeat(64),
        image.tag.clone(),
        image.image_id.clone(),
    )
}

#[derive(Clone)]
pub(super) struct StubVerifier {
    pub(super) build: VerifiedBuild,
    pub(super) calls: usize,
}

impl StubVerifier {
    pub(super) fn new() -> Self {
        Self {
            build: build(),
            calls: 0,
        }
    }
}

impl<R: CommandRunner> BuildVerifier<R> for StubVerifier {
    fn verify(
        &mut self,
        _repo_root: &Path,
        _metadata: &StackMetadata,
        _runner: &mut R,
    ) -> Result<VerifiedBuild> {
        self.calls += 1;
        Ok(self.build.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StackShape {
    Absent,
    Exact,
    Missing(&'static str),
}

pub(super) struct MockDocker {
    pub(super) shape: StackShape,
    pub(super) health: String,
    pub(super) state: String,
    pub(super) running: bool,
    pub(super) restarting: bool,
    pub(super) dead: bool,
    pub(super) seen: Vec<ArgvCommand>,
    pub(super) postgres_misses: usize,
    pub(super) postgres_failure: bool,
    pub(super) down_leaves_resources: bool,
    pub(super) absence_daemon_error: bool,
    pub(super) duplicate_list_id: bool,
    pub(super) wrong_image_service: Option<&'static str>,
}

impl MockDocker {
    pub(super) fn absent() -> Self {
        Self {
            shape: StackShape::Absent,
            health: "healthy".into(),
            state: "running".into(),
            running: true,
            restarting: false,
            dead: false,
            seen: Vec::new(),
            postgres_misses: 0,
            postgres_failure: false,
            down_leaves_resources: false,
            absence_daemon_error: false,
            duplicate_list_id: false,
            wrong_image_service: None,
        }
    }

    pub(super) fn exact() -> Self {
        Self {
            shape: StackShape::Exact,
            ..Self::absent()
        }
    }

    pub(super) fn compose_calls(&self, action: &str) -> usize {
        self.seen
            .iter()
            .filter(|command| strings(&command.args).get(5).map(String::as_str) == Some(action))
            .count()
    }

    fn service_names(&self) -> Vec<&'static str> {
        match self.shape {
            StackShape::Absent => Vec::new(),
            StackShape::Exact => SERVICES.to_vec(),
            StackShape::Missing(missing) => SERVICES
                .into_iter()
                .filter(|service| *service != missing)
                .collect(),
        }
    }

    fn container_id(service: &str) -> String {
        let index = SERVICES.iter().position(|value| *value == service).unwrap() + 1;
        format!("{index:064x}")
    }

    fn network_id() -> String {
        "a".repeat(64)
    }

    fn anonymous_names() -> [String; 2] {
        ["b".repeat(64), "c".repeat(64)]
    }

    fn image_ids() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("postgres:16.2", image_id('5')),
            ("hashicorp/vault", image_id('6')),
            ("curlimages/curl", image_id('7')),
        ])
    }

    fn expected(metadata: &StackMetadata) -> super::contract::ExpectedImages {
        let mut expected = expected_from_verified(&build());
        for image in expected.values_mut() {
            if image.image_id.is_none() {
                image.image_id = Some(Self::image_ids()[image.tag.as_str()].clone());
            }
        }
        debug_assert_eq!(metadata.project().as_str(), PROJECT);
        expected
    }

    fn containers_json(&self, metadata: &StackMetadata) -> Value {
        let expected = Self::expected(metadata);
        let ports = expected_ports(metadata.ports());
        let network = network_name(metadata);
        Value::Array(
            self.service_names()
                .into_iter()
                .map(|service| {
                    let id = Self::container_id(service);
                    let health = matches!(service, "vault-init" | "inquisition")
                        .then(|| json!({"Status": self.health}));
                    let listeners = ports[service]
                        .iter()
                        .map(|(container, host)| {
                            (
                                (*container).to_owned(),
                                json!([
                                    {"HostIp":"0.0.0.0", "HostPort":host.to_string()},
                                    {"HostIp":"::", "HostPort":host.to_string()}
                                ]),
                            )
                        })
                        .collect::<serde_json::Map<_, _>>();
                    let mounts = match service {
                        "vault" => {
                            let names = Self::anonymous_names();
                            json!([
                                {"Type":"volume","Name":names[0],"Destination":"/vault/file","RW":true},
                                {"Type":"volume","Name":names[1],"Destination":"/vault/logs","RW":true}
                            ])
                        }
                        "inquisition" => declared_mount(metadata, "bitcoin_inquisition_data", "/data"),
                        "db_lockbox" => declared_mount(metadata, "postgres_lockbox_data", "/var/lib/postgresql/data"),
                        "db_server" => declared_mount(metadata, "postgres_server_data", "/var/lib/postgresql/data"),
                        _ => json!([]),
                    };
                    let actual_image = if self.wrong_image_service == Some(service) {
                        image_id('f')
                    } else {
                        expected[service].image_id.clone().unwrap()
                    };
                    json!({
                        "Id": id,
                        "Name": format!("/{PROJECT}-{service}-1"),
                        "Image": actual_image,
                        "Config": {"Image":expected[service].tag,"Labels":{
                            "com.docker.compose.project":PROJECT,
                            "com.docker.compose.service":service
                        }},
                        "State":{"Status":self.state,"Running":self.running,"Restarting":self.restarting,"Dead":self.dead,"StartedAt":"2026-08-15T00:00:00.000000000Z","Health":health},
                        "NetworkSettings":{"Networks":{network.clone():{"NetworkID":Self::network_id()}},"Ports":listeners},
                        "Mounts": mounts
                    })
                })
                .collect(),
        )
    }

    fn network_json(&self, metadata: &StackMetadata) -> Value {
        let members = self
            .service_names()
            .into_iter()
            .map(|service| (Self::container_id(service), json!({})))
            .collect::<serde_json::Map<_, _>>();
        json!([{
            "Id":Self::network_id(),"Name":network_name(metadata),"Driver":"bridge",
            "Labels":{"com.docker.compose.project":PROJECT,"com.docker.compose.network":"default"},
            "Containers":members
        }])
    }

    fn volumes_json(&self, names: &[&str]) -> Value {
        Value::Array(
            names
                .iter()
                .map(|name| {
                    let key = name.strip_prefix(&format!("{PROJECT}_"));
                    match key {
                        Some(key) => json!({"Name":name,"Driver":"local","Labels":{
                            "com.docker.compose.project":PROJECT,"com.docker.compose.volume":key
                        }}),
                        None => json!({"Name":name,"Driver":"local","Labels":null}),
                    }
                })
                .collect(),
        )
    }
}

impl CommandRunner for MockDocker {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
        self.seen.push(command.clone());
        let args = strings(&command.args);
        match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["image", "inspect", "--format", "{{.Id}}", tag] => match Self::image_ids().get(tag) {
                Some(id) => Ok(CommandOutput::success(format!("{id}\n"))),
                None => bail!("unexpected external image inspection {tag}"),
            },
            ["ps", "--all", "--quiet", "--no-trunc", "--filter", _] => {
                let mut ids = self
                    .service_names()
                    .into_iter()
                    .map(Self::container_id)
                    .collect::<Vec<_>>();
                if self.duplicate_list_id && !ids.is_empty() {
                    ids.push(ids[0].clone());
                }
                Ok(CommandOutput::success(ids.join("\n")))
            }
            ["network", "ls", "--quiet", "--no-trunc", "--filter", _] => {
                Ok(CommandOutput::success(
                    (!matches!(self.shape, StackShape::Absent))
                        .then(Self::network_id)
                        .unwrap_or_default(),
                ))
            }
            ["volume", "ls", "--quiet", "--filter", _] => Ok(CommandOutput::success(
                if matches!(self.shape, StackShape::Absent) {
                    String::new()
                } else {
                    [
                        "bitcoin_inquisition_data",
                        "postgres_lockbox_data",
                        "postgres_server_data",
                    ]
                    .map(|key| format!("{PROJECT}_{key}"))
                    .join("\n")
                },
            )),
            ["container", "inspect", ..] => Ok(CommandOutput::success(serde_json::to_vec(
                &self.containers_json(&metadata(Path::new("/repo"))),
            )?)),
            ["network", "inspect", ..] => Ok(CommandOutput::success(serde_json::to_vec(
                &self.network_json(&metadata(Path::new("/repo"))),
            )?)),
            ["volume", "inspect", names @ ..] if !matches!(self.shape, StackShape::Absent) => Ok(
                CommandOutput::success(serde_json::to_vec(&self.volumes_json(names))?),
            ),
            ["volume", "inspect", _] if self.absence_daemon_error => {
                Ok(CommandOutput::failure(1, "permission denied\n"))
            }
            ["volume", "inspect", _] => Ok(CommandOutput::failure(1, "Error: No such volume\n")),
            ["exec", _, "pg_isready", ..] if self.postgres_failure => {
                Ok(CommandOutput::failure(3, "pg_isready internal failure\n"))
            }
            ["exec", _, "pg_isready", ..] if self.postgres_misses > 0 => {
                self.postgres_misses -= 1;
                Ok(CommandOutput {
                    success: false,
                    code: Some(2),
                    signal: None,
                    stdout: b"127.0.0.1:5432 - no response\n".to_vec(),
                    stderr: Vec::new(),
                })
            }
            ["exec", _, "pg_isready", ..] => Ok(CommandOutput::success(
                "127.0.0.1:5432 - accepting connections\n",
            )),
            ["compose", "-p", PROJECT, "-f", _, "up", "-d", "--no-build", "--pull", "never"] => {
                self.shape = StackShape::Exact;
                Ok(CommandOutput::success(Vec::new()))
            }
            ["compose", "-p", PROJECT, "-f", _, "down", "-v"] => {
                if !self.down_leaves_resources {
                    self.shape = StackShape::Absent;
                }
                Ok(CommandOutput::success(Vec::new()))
            }
            _ => bail!("unexpected mocked argv command: {args:?}"),
        }
    }
}

fn declared_mount(metadata: &StackMetadata, key: &str, destination: &str) -> Value {
    json!([{"Type":"volume","Name":declared_volume_name(metadata,key),"Destination":destination,"RW":true}])
}

pub(super) fn strings(values: &[std::ffi::OsString]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

pub(super) struct MockHost {
    pub(super) port_results: VecDeque<bool>,
    pub(super) default_port_free: bool,
    pub(super) now: u64,
    pub(super) sleep_advance: u64,
    pub(super) http_misses: BTreeMap<u16, usize>,
    pub(super) malformed_port: Option<u16>,
    pub(super) mercury_response: HttpResponse,
    pub(super) sleeps: usize,
    pub(super) requests: Vec<(u16, String)>,
}

impl MockHost {
    pub(super) fn new(default_port_free: bool) -> Self {
        Self {
            port_results: VecDeque::new(),
            default_port_free,
            now: 0,
            sleep_advance: 250,
            http_misses: BTreeMap::new(),
            malformed_port: None,
            mercury_response: HttpResponse {
                status: 200,
                body: json!({"batchtimeout": 20, "version": "0.2.1"}),
            },
            sleeps: 0,
            requests: Vec::new(),
        }
    }

    pub(super) fn push_port_round(&mut self, free: bool) {
        self.port_results.extend([free; 8]);
    }
}

impl HostProbe for MockHost {
    fn port_is_free(&mut self, _port: u16) -> Result<bool> {
        Ok(self
            .port_results
            .pop_front()
            .unwrap_or(self.default_port_free))
    }

    fn http_json(
        &mut self,
        _service: &str,
        port: u16,
        path: &str,
        _authorization: Option<&str>,
        _body: Option<&[u8]>,
    ) -> Result<HttpAttempt> {
        self.requests.push((port, path.to_owned()));
        if let Some(misses) = self.http_misses.get_mut(&port) {
            if *misses > 0 {
                *misses -= 1;
                return Ok(HttpAttempt::ConnectionMiss("refused".into()));
            }
        }
        if self.malformed_port == Some(port) {
            return Ok(HttpAttempt::Response(HttpResponse {
                status: 200,
                body: json!([]),
            }));
        }
        if port == 24000 {
            return Ok(HttpAttempt::Response(self.mercury_response.clone()));
        }
        let body = match port {
            24007 => json!({"initialized":true,"sealed":false}),
            24005 => json!({"error":null,"result":{"chain":"regtest"}}),
            24001 => Value::String("not found".into()),
            24002 => Value::String("Hello, Crow!".into()),
            _ => json!({"batchtimeout":20,"version":"0.2.1"}),
        };
        let status = if port == 24001 { 404 } else { 200 };
        Ok(HttpAttempt::Response(HttpResponse { status, body }))
    }

    fn now_millis(&self) -> u64 {
        self.now
    }

    fn sleep(&mut self, _duration: Duration) {
        self.sleeps += 1;
        self.now = self.now.saturating_add(self.sleep_advance);
    }
}
