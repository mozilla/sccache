// Copyright 2026 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tracing in the Chrome Trace Event format, which Perfetto
//! (<https://ui.perfetto.dev>) and `chrome://tracing` load directly.
//!
//! Async tasks hop between OS threads at every `.await`, so slices are not
//! placed on OS thread ids. Instead each unit of work leases a virtual `tid`
//! ([`TrackGuard`]) from a free-list, which keeps slices on one track properly
//! nested and keeps the number of tracks near the peak concurrency.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use crate::errors::*;

/// Counter tracks (cache hit rates, per-tier activity).
pub const PID_METRICS: u32 = 0;
/// One track per in-flight compilation.
pub const PID_WORKERS: u32 = 1;
/// Work not tied to a request, e.g. multi-level cache backfills.
pub const PID_BACKGROUND: u32 = 2;

static TRACER: OnceLock<Tracer> = OnceLock::new();

tokio::task_local! {
    static TRACE_CONTEXT: TraceContext;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Complete event: a slice with a start and a duration.
    #[serde(rename = "X")]
    Complete,
    #[serde(rename = "M")]
    Metadata,
    #[serde(rename = "C")]
    Counter,
}

/// A single entry of the Chrome Trace Event "JSON array format".
/// Timestamps and durations are in microseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub name: String,
    pub ph: Phase,
    pub ts: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur: Option<f64>,
    pub pid: u32,
    pub tid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Map<String, Value>>,
}

impl TraceEvent {
    fn metadata(name: &str, pid: u32, tid: u32, label: &str) -> Self {
        let mut args = Map::new();
        args.insert("name".to_owned(), label.into());
        TraceEvent {
            name: name.to_owned(),
            ph: Phase::Metadata,
            ts: 0.0,
            dur: None,
            pid,
            tid,
            args: Some(args),
        }
    }
}

/// The track (`pid`/`tid`) that spans created inside a task are drawn on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub pid: u32,
    pub tid: u32,
}

impl TraceContext {
    /// The context of the current task, if it runs inside [`TraceContext::scope`].
    pub fn current() -> Option<Self> {
        TRACE_CONTEXT.try_with(|ctx| *ctx).ok()
    }

    pub fn scope<F: Future>(self, fut: F) -> impl Future<Output = F::Output> {
        TRACE_CONTEXT.scope(self, fut)
    }
}

/// Like `tokio::spawn`, but the new task inherits the current [`TraceContext`].
/// Task-locals are otherwise not propagated to spawned tasks.
pub fn spawn<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match TraceContext::current() {
        Some(ctx) => tokio::spawn(ctx.scope(fut)),
        None => tokio::spawn(fut),
    }
}

#[derive(Default)]
struct TrackState {
    free: BinaryHeap<Reverse<u32>>,
    next: u32,
}

/// Hands out virtual thread ids, always preferring the lowest free one.
#[derive(Default)]
struct TrackAllocator {
    state: Mutex<TrackState>,
}

impl TrackAllocator {
    /// Returns the leased `tid` and whether it was never used before.
    fn lease(&self) -> (u32, bool) {
        let mut state = lock(&self.state);
        if let Some(Reverse(tid)) = state.free.pop() {
            (tid, false)
        } else {
            state.next += 1;
            (state.next, true)
        }
    }

    fn release(&self, tid: u32) {
        lock(&self.state).free.push(Reverse(tid));
    }
}

/// A leased worker track. Returned to the free-list on drop.
pub struct TrackGuard {
    tid: u32,
    tracks: Arc<TrackAllocator>,
}

impl TrackGuard {
    pub fn tid(&self) -> u32 {
        self.tid
    }

    pub fn context(&self) -> TraceContext {
        TraceContext {
            pid: PID_WORKERS,
            tid: self.tid,
        }
    }
}

impl Drop for TrackGuard {
    fn drop(&mut self) {
        self.tracks.release(self.tid);
    }
}

struct Output {
    writer: Box<dyn Write + Send>,
    wrote_event: bool,
    finished: bool,
}

struct Inner {
    out: Mutex<Output>,
    epoch: Instant,
    tracks: Arc<TrackAllocator>,
}

/// Writes trace events to a stream as a JSON array.
///
/// Perfetto accepts a file whose closing `]` is missing, so a daemon that is
/// killed still leaves a loadable trace behind. [`Tracer::finish`] terminates
/// the array on a clean shutdown.
#[derive(Clone)]
pub struct Tracer {
    inner: Arc<Inner>,
}

impl Tracer {
    pub fn new(writer: impl Write + Send + 'static) -> io::Result<Self> {
        let mut writer: Box<dyn Write + Send> = Box::new(writer);
        writer.write_all(b"[\n")?;
        let tracer = Tracer {
            inner: Arc::new(Inner {
                out: Mutex::new(Output {
                    writer,
                    wrote_event: false,
                    finished: false,
                }),
                epoch: Instant::now(),
                tracks: Arc::default(),
            }),
        };
        for (pid, label) in [
            (PID_METRICS, "sccache Metrics"),
            (PID_WORKERS, "sccache Workers"),
            (PID_BACKGROUND, "sccache Async Background & Backfill"),
        ] {
            tracer.emit(&TraceEvent::metadata("process_name", pid, 0, label));
        }
        Ok(tracer)
    }

    pub fn create(path: &Path) -> io::Result<Self> {
        Self::new(BufWriter::new(File::create(path)?))
    }

    /// Microseconds since this tracer was created.
    pub fn now_us(&self) -> f64 {
        self.inner.epoch.elapsed().as_secs_f64() * 1e6
    }

    /// Appends an event. Events emitted after [`Tracer::finish`] are dropped.
    pub fn emit(&self, event: &TraceEvent) {
        // Serialize outside the lock to keep the critical section short.
        let mut buf = Vec::with_capacity(160);
        if let Err(e) = serde_json::to_writer(&mut buf, event) {
            debug!("failed to serialize trace event: {e}");
            return;
        }
        let mut out = lock(&self.inner.out);
        if out.finished {
            return;
        }
        let sep: &[u8] = if out.wrote_event { b",\n" } else { b"" };
        let res = out
            .writer
            .write_all(sep)
            .and_then(|()| out.writer.write_all(&buf));
        match res {
            Ok(()) => out.wrote_event = true,
            Err(e) => debug!("failed to write trace event: {e}"),
        }
    }

    pub fn flush(&self) {
        if let Err(e) = lock(&self.inner.out).writer.flush() {
            debug!("failed to flush trace: {e}");
        }
    }

    /// Terminates the JSON array and flushes. Later events are dropped.
    pub fn finish(&self) {
        let mut out = lock(&self.inner.out);
        if out.finished {
            return;
        }
        out.finished = true;
        if let Err(e) = out
            .writer
            .write_all(b"\n]\n")
            .and_then(|()| out.writer.flush())
        {
            debug!("failed to finish trace: {e}");
        }
    }

    /// Leases a worker track, naming it in the trace the first time it is used.
    pub fn lease_track(&self) -> TrackGuard {
        let (tid, is_new) = self.inner.tracks.lease();
        if is_new {
            self.emit(&TraceEvent::metadata(
                "thread_name",
                PID_WORKERS,
                tid,
                &format!("worker {tid}"),
            ));
        }
        TrackGuard {
            tid,
            tracks: self.inner.tracks.clone(),
        }
    }

    /// Starts a span on the current [`TraceContext`] (or the background track
    /// if there is none). The slice is emitted when the guard is dropped.
    pub fn span(&self, name: impl Into<String>) -> SpanGuard {
        let ctx = TraceContext::current().unwrap_or(TraceContext {
            pid: PID_BACKGROUND,
            tid: 0,
        });
        SpanGuard {
            state: Some(SpanState {
                tracer: self.clone(),
                name: name.into(),
                ts: self.now_us(),
                ctx,
                args: Map::new(),
            }),
        }
    }
}

struct SpanState {
    tracer: Tracer,
    name: String,
    ts: f64,
    ctx: TraceContext,
    args: Map<String, Value>,
}

/// Emits a duration event (`ph: "X"`) when dropped. Does nothing when tracing
/// is disabled.
pub struct SpanGuard {
    state: Option<SpanState>,
}

impl SpanGuard {
    pub fn arg(&mut self, key: &str, value: impl Into<Value>) -> &mut Self {
        if let Some(state) = &mut self.state {
            state.args.insert(key.to_owned(), value.into());
        }
        self
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        let dur = state.tracer.now_us() - state.ts;
        state.tracer.emit(&TraceEvent {
            name: state.name,
            ph: Phase::Complete,
            ts: state.ts,
            dur: Some(dur),
            pid: state.ctx.pid,
            tid: state.ctx.tid,
            args: (!state.args.is_empty()).then_some(state.args),
        });
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock must not take tracing, or the server,
    // down with it; the guarded data stays consistent.
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Enables tracing to `path` for the lifetime of the process.
pub fn init(path: &Path) -> Result<()> {
    let tracer =
        Tracer::create(path).with_context(|| format!("failed to create trace file {path:?}"))?;
    if TRACER.set(tracer).is_err() {
        bail!("tracing is already initialized");
    }
    Ok(())
}

pub fn global() -> Option<&'static Tracer> {
    TRACER.get()
}

/// Starts a span on the global tracer; a no-op guard if tracing is disabled.
pub fn span(name: impl Into<String>) -> SpanGuard {
    match global() {
        Some(tracer) => tracer.span(name),
        None => SpanGuard { state: None },
    }
}

pub fn lease_track() -> Option<TrackGuard> {
    global().map(Tracer::lease_track)
}

pub fn flush() {
    if let Some(tracer) = global() {
        tracer.flush();
    }
}

pub fn finish() {
    if let Some(tracer) = global() {
        tracer.finish();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Barrier;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SharedBuf {
        fn contents(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    fn test_tracer() -> (Tracer, SharedBuf) {
        let buf = SharedBuf::default();
        (Tracer::new(buf.clone()).unwrap(), buf)
    }

    #[test]
    fn concurrent_leases_get_distinct_tids() {
        let tracks = Arc::new(TrackAllocator::default());
        let threads = 16;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let tracks = tracks.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let (tid, _) = tracks.lease();
                    // Hold the lease until every thread has one.
                    barrier.wait();
                    tracks.release(tid);
                    tid
                })
            })
            .collect();
        let tids: HashSet<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(tids.len(), threads);
        assert_eq!(tids.iter().max(), Some(&(threads as u32)));
    }

    #[test]
    fn released_tid_is_reused_lowest_first() {
        let (tracer, _) = test_tracer();
        let a = tracer.lease_track();
        let b = tracer.lease_track();
        let c = tracer.lease_track();
        assert_eq!((a.tid(), b.tid(), c.tid()), (1, 2, 3));
        let (a_tid, b_tid) = (a.tid(), b.tid());
        drop(b);
        drop(a);
        let first = tracer.lease_track();
        let second = tracer.lease_track();
        let third = tracer.lease_track();
        assert_eq!((first.tid(), second.tid(), third.tid()), (a_tid, b_tid, 4));
    }

    #[test]
    fn output_is_a_json_array_once_closed() {
        let (tracer, buf) = test_tracer();
        let track = tracer.lease_track();
        TRACE_CONTEXT.sync_scope(track.context(), || {
            let mut outer = tracer.span("outer");
            outer.arg("result", "Hit");
            {
                let _inner = tracer.span("inner");
            }
            drop(outer);
        });

        // Not finished yet: Perfetto still accepts this, serde needs the `]`.
        tracer.flush();
        let mut open = buf.contents();
        assert!(open.starts_with(b"[\n"));
        open.extend_from_slice(b"]");
        let events: Vec<TraceEvent> = serde_json::from_slice(&open).unwrap();

        tracer.finish();
        let closed = buf.contents();
        assert!(closed.ends_with(b"\n]\n"));
        let events_closed: Vec<TraceEvent> = serde_json::from_slice(&closed).unwrap();
        assert_eq!(events, events_closed);

        let meta: Vec<_> = events_closed
            .iter()
            .filter(|e| e.ph == Phase::Metadata)
            .collect();
        assert_eq!(
            meta.iter()
                .filter(|e| e.name == "process_name")
                .map(|e| e.pid)
                .collect::<Vec<_>>(),
            [PID_METRICS, PID_WORKERS, PID_BACKGROUND]
        );
        assert!(meta.iter().any(|e| e.name == "thread_name"
            && e.pid == PID_WORKERS
            && e.tid == track.tid()
            && e.args.as_ref().unwrap()["name"] == "worker 1"));

        // Children are emitted first and must nest inside the parent.
        let spans: Vec<_> = events_closed
            .iter()
            .filter(|e| e.ph == Phase::Complete)
            .collect();
        let [inner, outer] = spans[..] else {
            panic!("expected two spans, got {spans:?}");
        };
        assert_eq!(
            (inner.name.as_str(), outer.name.as_str()),
            ("inner", "outer")
        );
        assert_eq!((inner.pid, inner.tid), (PID_WORKERS, track.tid()));
        assert_eq!((outer.pid, outer.tid), (PID_WORKERS, track.tid()));
        assert!(inner.ts >= outer.ts);
        assert!(inner.ts + inner.dur.unwrap() <= outer.ts + outer.dur.unwrap());
        assert_eq!(outer.args.as_ref().unwrap()["result"], "Hit");
        assert!(inner.args.is_none());
    }

    #[test]
    fn span_without_context_goes_to_background_track() {
        let (tracer, buf) = test_tracer();
        drop(tracer.span("orphan"));
        tracer.finish();
        let events: Vec<TraceEvent> = serde_json::from_slice(&buf.contents()).unwrap();
        let orphan = events.iter().find(|e| e.name == "orphan").unwrap();
        assert_eq!((orphan.pid, orphan.tid), (PID_BACKGROUND, 0));
    }

    #[test]
    fn events_after_finish_are_dropped() {
        let (tracer, buf) = test_tracer();
        tracer.finish();
        let len = buf.contents().len();
        drop(tracer.span("late"));
        tracer.finish();
        assert_eq!(buf.contents().len(), len);
        serde_json::from_slice::<Vec<TraceEvent>>(&buf.contents()).unwrap();
    }

    #[test]
    fn disabled_span_is_noop() {
        let mut guard = SpanGuard { state: None };
        guard.arg("k", 1);
        drop(guard);
    }

    #[tokio::test]
    async fn context_propagates_to_spawned_tasks() {
        assert_eq!(TraceContext::current(), None);
        let ctx = TraceContext { pid: 1, tid: 7 };
        let seen = ctx
            .scope(async {
                let inherited = spawn(async { TraceContext::current() }).await.unwrap();
                // A plain tokio::spawn does not inherit.
                let plain = tokio::spawn(async { TraceContext::current() })
                    .await
                    .unwrap();
                (inherited, plain)
            })
            .await;
        assert_eq!(seen, (Some(ctx), None));
    }
}
