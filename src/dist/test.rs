use super::*;

/// The JSON shape emitted by `sccache --dist-status` is a contract consumed by
/// the bakar cluster-info preflight (`_parse_cluster_status`): a top-level
/// `servers` array of `{id, num_cpus, in_progress}` objects alongside the
/// aggregate counts.
#[test]
fn scheduler_status_serializes_per_server_breakdown() {
    let status = SchedulerStatusResult {
        num_servers: 2,
        num_cpus: 64,
        in_progress: 3,
        servers: vec![
            ServerStatusResult {
                id: "10.42.0.1:10501".to_string(),
                num_cpus: 32,
                in_progress: 2,
            },
            ServerStatusResult {
                id: "10.42.0.2:10501".to_string(),
                num_cpus: 32,
                in_progress: 1,
            },
        ],
    };

    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["num_servers"], 2);
    assert_eq!(json["num_cpus"], 64);
    assert_eq!(json["in_progress"], 3);
    let servers = json["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["id"], "10.42.0.1:10501");
    assert_eq!(servers[0]["num_cpus"], 32);
    assert_eq!(servers[0]["in_progress"], 2);
    assert_eq!(servers[1]["id"], "10.42.0.2:10501");
    assert_eq!(servers[1]["in_progress"], 1);

    // The aggregate in_progress is independent of the per-server sum: a job
    // can be queued at the scheduler before assignment to any server.
    let round: SchedulerStatusResult = serde_json::from_value(json).unwrap();
    assert_eq!(round.servers.len(), 2);
    assert_eq!(round.servers[0].id, "10.42.0.1:10501");
}
