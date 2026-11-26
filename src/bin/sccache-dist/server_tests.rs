use super::*;
use sccache::dist::{BuildResult, ProcessOutput};
use std::io::{Read, Write};
use std::sync::mpsc;

const JOB_ID: JobId = JobId(1);

struct TestBuilder<F>(Mutex<Option<F>>);

impl<F> BuilderIncoming for TestBuilder<F>
where
    F: FnOnce(InputsReader) -> Result<BuildResult> + Send,
{
    fn run_build(
        &self,
        _toolchain: Toolchain,
        _command: CompileCommand,
        _outputs: Vec<String>,
        inputs: InputsReader,
        _cache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        let build = self.0.lock().unwrap().take().unwrap();
        build(inputs)
    }
}

#[derive(Default)]
struct TestRequester(Mutex<Vec<(JobId, JobState)>>);

#[async_trait]
impl ServerOutgoing for TestRequester {
    async fn do_update_job_state(
        &self,
        job_id: JobId,
        state: JobState,
    ) -> Result<UpdateJobStateResult> {
        self.0.lock().unwrap().push((job_id, state));
        Ok(UpdateJobStateResult::Success)
    }
}

impl TestRequester {
    fn assert_complete(&self) {
        assert_eq!(
            *self.0.lock().unwrap(),
            [(JOB_ID, JobState::Started), (JOB_ID, JobState::Complete)]
        );
    }
}

async fn assigned_server<F>(build: F) -> (tempfile::TempDir, Server)
where
    F: FnOnce(InputsReader) -> Result<BuildResult> + Send + 'static,
{
    let cache_dir = tempfile::tempdir().unwrap();
    let builder = Box::new(TestBuilder(Mutex::new(Some(build))));
    let server = Server::new(builder, cache_dir.path(), 1024 * 1024).unwrap();
    server
        .handle_assign_job(
            JOB_ID,
            Toolchain {
                archive_id: "0".repeat(64),
            },
        )
        .await
        .unwrap();
    (cache_dir, server)
}

async fn run_job(
    server: &Server,
    requester: &TestRequester,
    inputs: InputsReader,
) -> Result<RunJobResult> {
    server
        .handle_run_job(
            requester,
            JOB_ID,
            CompileCommand {
                executable: "cc".into(),
                arguments: vec![],
                env_vars: vec![],
                cwd: "/".into(),
            },
            vec![],
            inputs,
        )
        .await
}

enum ToolchainCacheState {
    Missing,
    Cached,
}

/// A current-thread runtime must release the contended cache from another task.
/// The OS-thread timeout bounds failure even if assignment blocks the executor.
async fn assert_contended_assignment(cache_state: ToolchainCacheState) {
    let cache_dir = tempfile::tempdir().unwrap();
    let builder = TestBuilder(Mutex::new(Some(|_: InputsReader| -> Result<BuildResult> {
        panic!("assignment must not run a build")
    })));
    let server = Server::new(Box::new(builder), cache_dir.path(), 1024 * 1024).unwrap();
    let bytes = b"toolchain";
    let tc = Toolchain {
        archive_id: sccache::util::Digest::reader_sync(&bytes[..]).unwrap(),
    };
    let (need_toolchain, state) = match cache_state {
        ToolchainCacheState::Missing => (true, JobState::Pending),
        ToolchainCacheState::Cached => {
            server
                .cache
                .lock()
                .unwrap()
                .insert_with(&tc, |mut file| file.write_all(bytes))
                .unwrap();
            (false, JobState::Ready)
        }
    };
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let cache = Arc::clone(&server.cache);
    let holder = std::thread::spawn(move || {
        let _cache = cache.lock().unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5))
    });
    tokio::time::timeout(Duration::from_secs(5), locked_rx)
        .await
        .expect("cache holder did not start")
        .unwrap();

    let mut assignment = server.handle_assign_job(JOB_ID, tc.clone());
    assert!(
        futures::poll!(assignment.as_mut()).is_pending(),
        "assignment blocked the executor until the cache holder timed out"
    );
    assert!(server.job_toolchains.lock().await.is_empty());
    let release = tokio::spawn(async move {
        release_tx.send(()).unwrap();
    });
    let result = tokio::time::timeout(Duration::from_secs(5), assignment)
        .await
        .expect("assignment did not finish after releasing the cache")
        .unwrap();
    release.await.unwrap();
    holder
        .join()
        .unwrap()
        .expect("executor did not release the cache while assignment was pending");

    assert_eq!(result.need_toolchain, need_toolchain);
    assert_eq!(result.state, state);
    let job_toolchains = server.job_toolchains.lock().await;
    assert_eq!(job_toolchains.len(), 1);
    assert_eq!(job_toolchains.get(&JOB_ID), Some(&tc));
}

#[tokio::test(flavor = "current_thread")]
async fn missing_toolchain_assignment_keeps_runtime_responsive() {
    assert_contended_assignment(ToolchainCacheState::Missing).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cached_toolchain_assignment_keeps_runtime_responsive() {
    assert_contended_assignment(ToolchainCacheState::Cached).await;
}

#[tokio::test(flavor = "current_thread")]
async fn blocking_build_keeps_runtime_responsive() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (_cache_dir, server) = assigned_server(move |mut inputs| {
        started_tx.send(()).unwrap();
        release_rx
            .recv_timeout(Duration::from_secs(5))
            .context("runtime did not release blocking build")?;
        let mut bytes = Vec::new();
        inputs.read_to_end(&mut bytes)?;
        Ok(BuildResult {
            output: ProcessOutput {
                code: 0,
                stdout: bytes,
                stderr: b"build stderr".to_vec(),
            },
            outputs: vec![],
        })
    })
    .await;
    let release = tokio::spawn(async move {
        started_rx.await.unwrap();
        release_tx.send(()).unwrap();
    });
    let requester = TestRequester::default();
    let result = run_job(
        &server,
        &requester,
        InputsReader::new(io::Cursor::new(b"build inputs".to_vec())),
    )
    .await;
    release.await.unwrap();

    let RunJobResult::Complete(result) = result.unwrap() else {
        panic!("assigned job was not found");
    };
    assert_eq!(result.output.code, 0);
    assert_eq!(result.output.stdout, b"build inputs");
    assert_eq!(result.output.stderr, b"build stderr");
    assert!(result.outputs.is_empty());
    requester.assert_complete();
}

#[tokio::test(flavor = "current_thread")]
async fn builder_error_completes_job_and_preserves_error_chain() {
    let (_cache_dir, server) =
        assigned_server(|_| Err(io::Error::other("builder failure")).context("builder context"))
            .await;
    let requester = TestRequester::default();
    let error = run_job(&server, &requester, InputsReader::new(io::empty()))
        .await
        .err()
        .expect("builder failure should be returned");

    assert_eq!(
        error.chain().map(ToString::to_string).collect::<Vec<_>>(),
        ["run build failed", "builder context", "builder failure"]
    );
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().to_string(),
        "builder failure"
    );
    requester.assert_complete();
}

#[tokio::test(flavor = "current_thread")]
async fn builder_panic_completes_job_and_returns_join_error() {
    let (_cache_dir, server) = assigned_server(|_| panic!("builder panic")).await;
    let requester = TestRequester::default();
    let error = run_job(&server, &requester, InputsReader::new(io::empty()))
        .await
        .err()
        .expect("builder panic should be returned as an error");

    assert_eq!(error.to_string(), "build task failed");
    let join_error = error.downcast_ref::<tokio::task::JoinError>().unwrap();
    assert!(join_error.is_panic());
    assert!(join_error.to_string().contains("builder panic"));
    requester.assert_complete();
}
