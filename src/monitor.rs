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

//! A live terminal dashboard that attaches to a running sccache server.
//!
//! The monitor is a plain client: it connects to the daemon over the usual
//! socket and polls `Request::GetStats` (and, on the dist tab,
//! `Request::DistStatus`). Counters are cumulative, so per-second rates are
//! derived by diffing consecutive snapshots. If the server goes away the
//! monitor keeps running and reconnects when it comes back.
//!
//! Note that every request resets the server's idle-shutdown timer, so a
//! server being watched won't shut down on its own. Press `p` to pause polling
//! if that matters.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use number_prefix::NumberPrefix;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Points};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, Gauge, LineGauge, Paragraph, Row, Sparkline, Table, Tabs, Wrap,
};
use ratatui::{DefaultTerminal, Frame};

use crate::client::{ServerConnection, connect_to_server};
use crate::errors::*;
use crate::protocol::{Request, Response};
use crate::server::{DistInfo, PerLanguageCount, ServerInfo, ServerStats};
use crate::util::fmt_duration_as_secs;

/// How many samples of history to keep for the sparklines.
const HISTORY: usize = 512;
/// Bounds on the poll interval, adjustable with `+`/`-`.
const MIN_INTERVAL: Duration = Duration::from_millis(200);
const MAX_INTERVAL: Duration = Duration::from_secs(60);
/// How long a transient status message stays on screen.
const MESSAGE_TTL: Duration = Duration::from_secs(4);
/// Longest the UI goes without a repaint when nothing has changed, so that the
/// elapsed times in the status bar keep moving.
const REDRAW_INTERVAL: Duration = Duration::from_millis(500);

const TABS: [&str; 5] = ["Overview", "Languages", "Reasons", "Cache", "Dist"];

/// Run the monitor until the user quits.
pub fn run(addr: crate::net::SocketAddr, interval: Duration) -> Result<()> {
    let interval = interval.clamp(MIN_INTERVAL, MAX_INTERVAL);
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (sample_tx, sample_rx) = mpsc::channel();

    let addr_display = addr.to_string();
    // The handle is dropped on purpose: the poller can be blocked in a request
    // against a server that accepted the connection and never answered, and
    // client sockets have no read timeout, so joining it could hang the exit
    // forever with the terminal already restored and no UI left to quit. The
    // thread owns nothing that needs unwinding, so let the process reap it.
    thread::Builder::new()
        .name("sccache-monitor-poll".into())
        .spawn(move || poll_loop(addr, interval, cmd_rx, sample_tx))?;

    let mut app = App::new(addr_display, interval);
    install_panic_hook();
    let terminal = ratatui::init();
    let result = app.main_loop(terminal, &cmd_tx, &sample_rx);
    ratatui::restore();

    let _ = cmd_tx.send(Cmd::Quit);
    result
}

// ---------------------------------------------------------------------------
// Polling thread
// ---------------------------------------------------------------------------

/// A message from the UI thread to the polling thread.
enum Cmd {
    /// Poll right now instead of waiting for the next tick.
    Refresh,
    /// Change the polling interval.
    SetInterval(Duration),
    /// Stop or resume polling.
    Pause(bool),
    /// Also fetch dist status on each poll (only while the Dist tab is shown).
    WantDist(bool),
    /// Zero the server's statistics.
    Zero,
    /// Shut the polling thread down.
    Quit,
}

/// A message from the polling thread to the UI thread.
enum Sample {
    Info(Box<ServerInfo>),
    Dist(Box<DistInfo>),
    /// Stats were zeroed successfully.
    Zeroed,
    /// The last request failed.
    Error(String),
}

fn poll_loop(
    addr: crate::net::SocketAddr,
    mut interval: Duration,
    rx: Receiver<Cmd>,
    tx: Sender<Sample>,
) {
    let mut want_dist = false;
    let mut paused = false;
    // Set by `Cmd::Refresh`, so that an explicit refresh polls once even while
    // polling is paused.
    let mut force = false;

    loop {
        if !paused || force {
            force = false;
            match request(&addr, Request::GetStats) {
                Ok(Response::Stats(info)) => {
                    if tx.send(Sample::Info(info)).is_err() {
                        return;
                    }
                    if want_dist {
                        match request(&addr, Request::DistStatus) {
                            Ok(Response::DistStatus(info)) => {
                                if tx.send(Sample::Dist(Box::new(info))).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                if tx.send(Sample::Error(format!("{e}"))).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
                Ok(other) => {
                    let msg = format!("unexpected response to GetStats: {other:?}");
                    if tx.send(Sample::Error(msg)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    if tx.send(Sample::Error(format!("{e:#}"))).is_err() {
                        return;
                    }
                }
            }
        }

        // Wait out the interval, reacting to commands as they arrive.
        let deadline = Instant::now() + interval;
        loop {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(timeout) {
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) | Ok(Cmd::Quit) => return,
                Ok(Cmd::Refresh) => {
                    force = true;
                    break;
                }
                Ok(Cmd::SetInterval(d)) => {
                    interval = d;
                    break;
                }
                Ok(Cmd::Pause(p)) => {
                    paused = p;
                    if !paused {
                        break;
                    }
                }
                Ok(Cmd::WantDist(w)) => {
                    want_dist = w;
                    if w {
                        break;
                    }
                }
                Ok(Cmd::Zero) => {
                    let sample = match request(&addr, Request::ZeroStats) {
                        Ok(Response::ZeroStats) => Sample::Zeroed,
                        Ok(other) => Sample::Error(format!("failed to zero stats: {other:?}")),
                        Err(e) => Sample::Error(format!("{e:#}")),
                    };
                    if tx.send(sample).is_err() {
                        return;
                    }
                    break;
                }
            }
        }
    }
}

/// Connect, send `req`, and hang up again.
///
/// The connection is deliberately not kept open between polls: the server
/// waits for connected clients to go away before shutting down, so a monitor
/// holding a socket open would stall `--stop-server` for its whole drain
/// timeout.
fn request(addr: &crate::net::SocketAddr, req: Request) -> Result<Response> {
    let mut conn: ServerConnection =
        connect_to_server(addr).map_err(|e| anyhow!("no server listening on {addr}: {e}"))?;
    conn.request(req)
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Per-second rates derived from two consecutive snapshots.
#[derive(Default, Clone, Copy)]
struct Rates {
    requests: f64,
    hits: f64,
    misses: f64,
    writes: f64,
    compilations: f64,
    errors: f64,
}

struct App {
    addr: String,
    interval: Duration,
    started: Instant,
    tab: usize,
    advanced: bool,
    paused: bool,
    help: bool,
    /// `z` was pressed once; a second `z` zeroes the statistics.
    confirm_zero: bool,
    /// Latest snapshot, and the previous one used for rate computation.
    info: Option<ServerInfo>,
    prev: Option<(Instant, ServerStats)>,
    dist: Option<DistInfo>,
    rates: Rates,
    hist_requests: VecDeque<u64>,
    hist_hits: VecDeque<u64>,
    hist_misses: VecDeque<u64>,
    /// Timestamped cache size in bytes, one entry per sample, used to work out
    /// how fast the cache is filling and when it will be full.
    hist_size: VecDeque<(Instant, u64)>,
    /// Bytes per second added to the cache, one entry per sample.
    hist_growth: VecDeque<u64>,
    /// How often the cache was seen to shrink, and by how much in total. The
    /// LRU trims the cache at its ceiling, so this is what "full" looks like.
    trims: u64,
    trimmed: u64,
    updates: u64,
    last_update: Option<Instant>,
    error: Option<String>,
    message: Option<(String, Instant)>,
}

impl App {
    fn new(addr: String, interval: Duration) -> Self {
        App {
            addr,
            interval,
            started: Instant::now(),
            tab: 0,
            advanced: false,
            paused: false,
            help: false,
            confirm_zero: false,
            info: None,
            prev: None,
            dist: None,
            rates: Rates::default(),
            hist_requests: VecDeque::with_capacity(HISTORY),
            hist_hits: VecDeque::with_capacity(HISTORY),
            hist_misses: VecDeque::with_capacity(HISTORY),
            hist_size: VecDeque::with_capacity(HISTORY),
            hist_growth: VecDeque::with_capacity(HISTORY),
            trims: 0,
            trimmed: 0,
            updates: 0,
            last_update: None,
            error: None,
            message: None,
        }
    }

    fn main_loop(
        &mut self,
        mut terminal: DefaultTerminal,
        cmds: &Sender<Cmd>,
        samples: &Receiver<Sample>,
    ) -> Result<()> {
        let mut dirty = true;
        let mut drawn = Instant::now();
        loop {
            // Redraw when something changed, and otherwise just often enough
            // to keep the clocks in the status bar ticking: a full repaint at
            // the input poll rate is wasteful, especially over ssh.
            if dirty || drawn.elapsed() >= REDRAW_INTERVAL {
                terminal.draw(|frame| self.draw(frame))?;
                dirty = false;
                drawn = Instant::now();
            }

            // Wait briefly for input so the UI stays responsive, then drain
            // whatever the poller produced in the meantime.
            if event::poll(Duration::from_millis(100))? {
                // Anything the terminal reports (a resize in particular) needs
                // a repaint, whether or not we act on it.
                dirty = true;
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press && !self.on_key(key, cmds)? {
                        return Ok(());
                    }
                }
            }
            while let Ok(sample) = samples.try_recv() {
                self.ingest(sample);
                dirty = true;
            }
            if let Some((_, at)) = self.message {
                if at.elapsed() > MESSAGE_TTL {
                    self.message = None;
                    dirty = true;
                }
            }
        }
    }

    /// Handle a key press. Returns `false` when the user asked to quit.
    fn on_key(&mut self, key: KeyEvent, cmds: &Sender<Cmd>) -> Result<bool> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Zeroing is irreversible, so it takes two presses of `z` in a row;
        // any other key cancels the pending confirmation.
        let confirming = std::mem::take(&mut self.confirm_zero);
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(false),
            KeyCode::Char('c' | 'd') if ctrl => return Ok(false),
            KeyCode::Char('?') | KeyCode::F(1) => self.help = !self.help,
            KeyCode::Char('a') => self.advanced = !self.advanced,
            KeyCode::Char('r') => {
                let _ = cmds.send(Cmd::Refresh);
                self.note("refreshing");
            }
            KeyCode::Char('z') => {
                if confirming {
                    let _ = cmds.send(Cmd::Zero);
                } else {
                    self.confirm_zero = true;
                    self.note("press z again to zero the server's statistics");
                }
            }
            KeyCode::Char('p') | KeyCode::Char(' ') => {
                self.paused = !self.paused;
                let _ = cmds.send(Cmd::Pause(self.paused));
                self.note(if self.paused {
                    "polling paused"
                } else {
                    "polling resumed"
                });
            }
            KeyCode::Char('+' | '=') => self.set_interval(self.interval * 2, cmds),
            KeyCode::Char('-' | '_') => self.set_interval(self.interval / 2, cmds),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.select_tab((self.tab + 1) % TABS.len(), cmds);
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.select_tab((self.tab + TABS.len() - 1) % TABS.len(), cmds);
            }
            KeyCode::Char(c @ '1'..='5') => {
                let idx = c as usize - '1' as usize;
                self.select_tab(idx, cmds);
            }
            _ => {}
        }
        Ok(true)
    }

    fn select_tab(&mut self, tab: usize, cmds: &Sender<Cmd>) {
        if tab == self.tab {
            return;
        }
        self.tab = tab;
        self.help = false;
        // Dist status can be an expensive round trip to the scheduler, so only
        // ask for it while its tab is visible.
        let _ = cmds.send(Cmd::WantDist(TABS[tab] == "Dist"));
    }

    fn set_interval(&mut self, interval: Duration, cmds: &Sender<Cmd>) {
        self.interval = interval.clamp(MIN_INTERVAL, MAX_INTERVAL);
        let _ = cmds.send(Cmd::SetInterval(self.interval));
        self.note(format!("interval {}", fmt_interval(self.interval)));
    }

    fn note<S: Into<String>>(&mut self, msg: S) {
        self.message = Some((msg.into(), Instant::now()));
    }

    fn ingest(&mut self, sample: Sample) {
        match sample {
            Sample::Info(info) => {
                let now = Instant::now();
                let stats = &info.stats;
                match self.prev.take() {
                    // A counter going backwards means the stats were zeroed or
                    // the server restarted: start the history over.
                    Some((_, prev)) if stats.compile_requests < prev.compile_requests => {
                        self.reset_history();
                    }
                    Some((at, prev)) => {
                        let dt = now.duration_since(at).as_secs_f64();
                        if dt > 0.0 {
                            let rate = |new: u64, old: u64| (new.saturating_sub(old)) as f64 / dt;
                            self.rates = Rates {
                                requests: rate(stats.compile_requests, prev.compile_requests),
                                hits: rate(stats.cache_hits.all(), prev.cache_hits.all()),
                                misses: rate(stats.cache_misses.all(), prev.cache_misses.all()),
                                writes: rate(stats.cache_writes, prev.cache_writes),
                                compilations: rate(stats.compilations, prev.compilations),
                                errors: rate(
                                    stats.cache_errors.all()
                                        + stats.cache_read_errors
                                        + stats.cache_write_errors,
                                    prev.cache_errors.all()
                                        + prev.cache_read_errors
                                        + prev.cache_write_errors,
                                ),
                            };
                            push(&mut self.hist_requests, self.rates.requests);
                            push(&mut self.hist_hits, self.rates.hits);
                            push(&mut self.hist_misses, self.rates.misses);
                        }
                    }
                    None => {}
                }
                self.prev = Some((now, stats.clone()));
                if let Some(size) = info.cache_size {
                    if let Some(&(at, previous)) = self.hist_size.back() {
                        let dt = now.duration_since(at).as_secs_f64();
                        if size < previous {
                            // The LRU trimmed the cache: it was at its ceiling.
                            self.trims += 1;
                            self.trimmed += previous - size;
                        }
                        if dt > 0.0 {
                            let growth = (size.saturating_sub(previous)) as f64 / dt;
                            if self.hist_growth.len() == HISTORY {
                                self.hist_growth.pop_front();
                            }
                            self.hist_growth.push_back(growth.round() as u64);
                        }
                    }
                    if self.hist_size.len() == HISTORY {
                        self.hist_size.pop_front();
                    }
                    self.hist_size.push_back((now, size));
                }
                self.info = Some(*info);
                self.updates += 1;
                self.last_update = Some(now);
                self.error = None;
            }
            Sample::Dist(info) => self.dist = Some(*info),
            Sample::Zeroed => {
                self.reset_history();
                // Drop the pre-zero snapshot too, otherwise the counters keep
                // showing the old totals until the next poll lands. The poller
                // re-polls immediately after zeroing, so this is one frame.
                self.info = None;
                self.note("statistics zeroed");
            }
            Sample::Error(e) => {
                self.prev = None;
                self.rates = Rates::default();
                self.error = Some(e);
            }
        }
    }

    fn reset_history(&mut self) {
        self.prev = None;
        self.rates = Rates::default();
        self.hist_requests.clear();
        self.hist_hits.clear();
        self.hist_misses.clear();
    }
}

fn push(hist: &mut VecDeque<u64>, value: f64) {
    // Sparklines take integers; keep two decimals of resolution.
    if hist.len() == HISTORY {
        hist.pop_front();
    }
    hist.push_back((value.max(0.0) * 100.0).round() as u64);
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

impl App {
    fn draw(&self, frame: &mut Frame<'_>) {
        let [tabs, status, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        self.draw_tabs(frame, tabs);
        self.draw_status(frame, status);
        match TABS[self.tab] {
            "Languages" => self.draw_languages(frame, body),
            "Reasons" => self.draw_reasons(frame, body),
            "Cache" => self.draw_cache(frame, body),
            "Dist" => self.draw_dist(frame, body),
            _ => self.draw_overview(frame, body),
        }
        self.draw_footer(frame, footer);
        if self.help {
            draw_help(frame, body);
        }
    }

    fn draw_tabs(&self, frame: &mut Frame<'_>, area: Rect) {
        let titles = TABS
            .iter()
            .enumerate()
            .map(|(i, t)| Line::from(format!(" {}:{t} ", i + 1)));
        frame.render_widget(
            Tabs::new(titles)
                .select(self.tab)
                .style(Style::default().fg(Color::Gray))
                .highlight_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .divider(""),
            area,
        );
    }

    fn draw_status(&self, frame: &mut Frame<'_>, area: Rect) {
        let (dot, state, colour) = if self.paused {
            ("◼", "paused".to_string(), Color::Yellow)
        } else if let Some(e) = &self.error {
            ("○", format!("disconnected — {e}"), Color::Red)
        } else if self.info.is_some() {
            ("●", "connected".to_string(), Color::Green)
        } else {
            ("◌", "connecting…".to_string(), Color::Yellow)
        };

        let version = self
            .info
            .as_ref()
            .map(|i| i.version.clone())
            .unwrap_or_else(|| "?".to_string());
        let age = self
            .last_update
            .map(|t| format!("{:.1}s ago", t.elapsed().as_secs_f64()))
            .unwrap_or_else(|| "never".to_string());

        let line = Line::from(vec![
            Span::styled(dot, Style::default().fg(colour)),
            Span::raw(" "),
            Span::styled(state, Style::default().fg(colour).bold()),
            sep(),
            Span::raw(self.addr.clone()),
            sep(),
            Span::raw(format!("server v{version}")),
            sep(),
            Span::raw(format!("every {}", fmt_interval(self.interval))),
            sep(),
            Span::raw(format!("last {age}")),
            sep(),
            Span::raw(format!("{} samples", self.updates)),
            sep(),
            Span::raw(format!("watching {}", fmt_uptime(self.started.elapsed()))),
        ]);

        frame.render_widget(Paragraph::new(line).block(titled("sccache monitor")), area);
    }

    fn draw_footer(&self, frame: &mut Frame<'_>, area: Rect) {
        let text = match &self.message {
            Some((msg, _)) => Line::from(vec![
                Span::styled(" ! ", Style::default().fg(Color::Black).bg(Color::Yellow)),
                Span::raw(format!(" {msg}")),
            ]),
            None => Line::from(
                " q quit · ?/F1 help · zz zero · p pause · a advanced · r refresh · +/- interval · 1-5/Tab panes",
            )
            .style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(Paragraph::new(text), area);
    }

    fn draw_overview(&self, frame: &mut Frame<'_>, area: Rect) {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)])
                .areas(area);
        let [rates_area, counters_area] =
            Layout::vertical([Constraint::Length(7), Constraint::Min(0)]).areas(left);
        let [req_area, hit_area, miss_area, timing_area] = Layout::vertical([
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .areas(right);

        self.draw_rates(frame, rates_area);
        self.draw_counters(frame, counters_area);
        self.draw_sparkline(
            frame,
            req_area,
            "compile requests/s",
            &self.hist_requests,
            self.rates.requests,
            Color::Cyan,
        );
        self.draw_sparkline(
            frame,
            hit_area,
            "cache hits/s",
            &self.hist_hits,
            self.rates.hits,
            Color::Green,
        );
        self.draw_sparkline(
            frame,
            miss_area,
            "cache misses/s",
            &self.hist_misses,
            self.rates.misses,
            Color::Magenta,
        );
        self.draw_timings(frame, timing_area);
    }

    fn draw_rates(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = titled("Live");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [hit_area, size_area, rate_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(inner);

        let (hits, misses) = self
            .info
            .as_ref()
            .map(|i| (i.stats.cache_hits.all(), i.stats.cache_misses.all()))
            .unwrap_or((0, 0));
        let total = hits + misses;
        let ratio = if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        };
        frame.render_widget(
            LineGauge::default()
                .label(format!("hit rate {:>6.2} %", ratio * 100.0))
                .ratio(ratio)
                .filled_style(Style::default().fg(hit_rate_colour(ratio, total)))
                .unfilled_style(Style::default().fg(Color::DarkGray)),
            hit_area,
        );

        let (size, max) = self
            .info
            .as_ref()
            .map(|i| (i.cache_size, i.max_cache_size))
            .unwrap_or((None, None));
        frame.render_widget(cache_gauge(size, max), size_area);

        let r = &self.rates;
        let lines = vec![
            Line::from(vec![
                kv("requests/s", format!("{:.2}", r.requests)),
                Span::raw("   "),
                kv("compiles/s", format!("{:.2}", r.compilations)),
            ]),
            Line::from(vec![
                kv("hits/s", format!("{:.2}", r.hits)),
                Span::raw("   "),
                kv("misses/s", format!("{:.2}", r.misses)),
            ]),
            Line::from(vec![
                kv("writes/s", format!("{:.2}", r.writes)),
                Span::raw("   "),
                Span::styled(
                    format!("errors/s {:.2}", r.errors),
                    Style::default().fg(if r.errors > 0.0 {
                        Color::Red
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]),
        ];
        frame.render_widget(Paragraph::new(lines), rate_area);
    }

    fn draw_sparkline(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        title: &str,
        hist: &VecDeque<u64>,
        current: f64,
        colour: Color,
    ) {
        // `Sparkline` draws the *first* `width` samples it is handed and drops
        // the rest, so give it only the most recent ones that fit; otherwise
        // the plot freezes as soon as the history outgrows the pane. The peak
        // is taken over the same window so that it matches what is on screen.
        let width = area.width.saturating_sub(2) as usize;
        let data: Vec<u64> = hist.iter().rev().take(width).rev().copied().collect();
        let peak = data.iter().copied().max().unwrap_or(0) as f64 / 100.0;
        let heading = format!("{title} — now {current:.2}, peak {peak:.2}");
        frame.render_widget(
            Sparkline::default()
                .block(titled(&heading))
                .data(data)
                .style(Style::default().fg(colour)),
            area,
        );
    }

    fn draw_counters(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = titled("Counters");
        let Some(info) = self.info.as_ref() else {
            frame.render_widget(
                placeholder("waiting for the first sample…").block(block),
                area,
            );
            return;
        };
        let s = &info.stats;
        let rows: Vec<(&str, u64, bool)> = vec![
            ("Compile requests", s.compile_requests, false),
            ("Requests executed", s.requests_executed, false),
            ("Cache hits", s.cache_hits.all(), false),
            ("Cache misses", s.cache_misses.all(), false),
            ("Cache writes", s.cache_writes, false),
            ("Compilations", s.compilations, false),
            ("Compilation failures", s.compile_fails, true),
            ("Cache timeouts", s.cache_timeouts, true),
            ("Cache read errors", s.cache_read_errors, true),
            ("Cache write errors", s.cache_write_errors, true),
            ("Cache errors", s.cache_errors.all(), true),
            ("Forced recaches", s.forced_recaches, false),
            (
                "Non-cacheable compilations",
                s.non_cacheable_compilations,
                false,
            ),
            ("Non-cacheable calls", s.requests_not_cacheable, false),
            ("Non-compilation calls", s.requests_not_compile, false),
            (
                "Unsupported compiler calls",
                s.requests_unsupported_compiler,
                false,
            ),
            ("Failed distributed compiles", s.dist_errors, true),
        ];
        let rows = rows.into_iter().map(|(name, value, bad)| {
            let style = if bad && value > 0 {
                Style::default().fg(Color::Red)
            } else if value == 0 {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![Cell::from(name), right(value.to_string())]).style(style)
        });
        frame.render_widget(
            Table::new(rows, [Constraint::Min(20), Constraint::Length(12)]).block(block),
            area,
        );
    }

    fn draw_timings(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = titled("Averages");
        let Some(info) = self.info.as_ref() else {
            frame.render_widget(placeholder("no data yet").block(block), area);
            return;
        };
        let s = &info.stats;
        let avg = |total: Duration, n: u64| {
            if n == 0 {
                "-".to_string()
            } else {
                fmt_duration_as_secs(&(total / n as u32))
            }
        };
        let rows = [
            (
                "Average cache write",
                avg(s.cache_write_duration, s.cache_writes),
            ),
            (
                "Average compiler",
                avg(s.compiler_write_duration, s.compilations),
            ),
            (
                "Average cache read hit",
                avg(s.cache_read_hit_duration, s.cache_hits.all()),
            ),
            (
                "Total time compiling",
                fmt_duration_as_secs(&s.compiler_write_duration),
            ),
        ]
        .into_iter()
        .map(|(name, value)| Row::new(vec![Cell::from(name), right(value)]));
        frame.render_widget(
            Table::new(rows, [Constraint::Min(18), Constraint::Length(12)]).block(block),
            area,
        );
    }

    fn draw_languages(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = titled(if self.advanced {
            "Per language and compiler (a: per language)"
        } else {
            "Per language (a: per compiler)"
        });
        let Some(info) = self.info.as_ref() else {
            frame.render_widget(
                placeholder("waiting for the first sample…").block(block),
                area,
            );
            return;
        };
        let langs = language_stats(&info.stats, self.advanced);
        if langs.is_empty() {
            frame.render_widget(
                placeholder("no compilations recorded yet").block(block),
                area,
            );
            return;
        }

        // Widest bar that fits in the last column, and the busiest language it
        // is scaled against. The column gets whatever is left of the pane once
        // the two borders, the 62 fixed columns of `LANGUAGE_COLUMNS` and the
        // five inter-column spaces are taken out.
        let bar_width = area.width.saturating_sub(69).clamp(0, 40) as usize;
        let busiest = langs.iter().map(LangStat::total).max().unwrap_or(0).max(1);

        let header = Row::new(vec![
            Cell::from("Language"),
            right("hits"),
            right("misses"),
            right("hit rate"),
            right("errors"),
            Cell::from("hits/misses"),
        ])
        .style(Style::default().fg(Color::Cyan).bold());

        frame.render_widget(
            Table::new(
                langs.iter().map(|l| l.row(busiest, bar_width)),
                LANGUAGE_COLUMNS,
            )
            .header(header)
            .block(block),
            area,
        );
    }

    fn draw_reasons(&self, frame: &mut Frame<'_>, area: Rect) {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
                .areas(area);
        let not_cached = titled("Non-cacheable reasons");
        let dist = titled("Successful distributed compiles");

        let Some(info) = self.info.as_ref() else {
            frame.render_widget(
                placeholder("waiting for the first sample…").block(not_cached),
                left,
            );
            frame.render_widget(placeholder("").block(dist), right);
            return;
        };

        frame.render_widget(
            counted_table(
                &info.stats.not_cached,
                "nothing was rejected",
                Color::Yellow,
            )
            .block(not_cached),
            left,
        );
        frame.render_widget(
            counted_table(
                &info.stats.dist_compiles,
                "no distributed compiles",
                Color::Blue,
            )
            .block(dist),
            right,
        );
    }

    /// Average bytes per second the cache has grown over the samples still in
    /// the window, and how long that window covers. Negative after a trim.
    fn cache_growth(&self) -> Option<(f64, Duration)> {
        let &(first_at, first) = self.hist_size.front()?;
        let &(last_at, last) = self.hist_size.back()?;
        let window = last_at.duration_since(first_at);
        if window.is_zero() {
            return None;
        }
        Some(((last as f64 - first as f64) / window.as_secs_f64(), window))
    }

    /// Plot how fast the cache is filling. The size itself only ever climbs
    /// until the LRU trims it, so its own plot is a staircase; the rate rises
    /// and falls with what the build is writing.
    fn draw_cache_trend(&self, frame: &mut Frame<'_>, area: Rect) {
        let width = area.width.saturating_sub(2) as usize;
        let data: Vec<u64> = self
            .hist_growth
            .iter()
            .rev()
            .take(width)
            .rev()
            .copied()
            .collect();
        let heading = match (data.last(), data.iter().max()) {
            (Some(&now), Some(&peak)) => format!(
                "cache growth — now {}/s, peak {}/s",
                fmt_bytes(Some(now)),
                fmt_bytes(Some(peak)),
            ),
            _ => "cache growth".to_string(),
        };
        frame.render_widget(
            Sparkline::default()
                .block(titled(&heading))
                .data(data)
                .style(Style::default().fg(Color::Blue)),
            area,
        );
    }

    fn draw_cache(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = titled("Cache");
        let Some(info) = self.info.as_ref() else {
            frame.render_widget(
                placeholder("waiting for the first sample…").block(block),
                area,
            );
            return;
        };

        let has_levels = info
            .stats
            .multi_level
            .as_ref()
            .is_some_and(|m| !m.0.is_empty());
        // A local cache has a size and a ceiling worth drawing; a remote one
        // usually reports neither, so it keeps the plain gauge.
        let usage = match (info.cache_size, info.max_cache_size) {
            (Some(size), Some(max)) if max > 0 && info.cache_location.starts_with("Local disk") => {
                Some((size, max))
            }
            _ => None,
        };
        let levels_height = match info.stats.multi_level.as_ref().filter(|_| has_levels) {
            // Border, header, and a line per level.
            Some(levels) => 3 + levels.0.len() as u16,
            None => 0,
        };
        let (top_height, trend_height) = match usage {
            // Enough for the pie plus its legend, and a plot of the fill.
            Some(_) => (Constraint::Length(12), Constraint::Min(0)),
            None => (Constraint::Min(0), Constraint::Length(0)),
        };
        let [top, trend, bottom] =
            Layout::vertical([top_height, trend_height, Constraint::Length(levels_height)])
                .areas(area);

        let inner = block.inner(top);
        frame.render_widget(block, top);

        let mut lines = vec![
            Line::from(vec![kv("location", info.cache_location.clone())]),
            Line::from(vec![
                kv("size", fmt_bytes(info.cache_size)),
                Span::raw("   "),
                kv("max", fmt_bytes(info.max_cache_size)),
            ]),
        ];
        if let Some((size, max)) = usage {
            lines.push(Line::from(vec![kv(
                "free",
                fmt_bytes(Some(max.saturating_sub(size))),
            )]));
            if let Some((rate, window)) = self.cache_growth() {
                lines.push(Line::from(vec![kv(
                    "growth",
                    format!(
                        "{}/s over the last {}",
                        fmt_bytes(Some(rate.max(0.0) as u64)),
                        fmt_eta(window.as_secs_f64()),
                    ),
                )]));
                // Once the LRU has started trimming, the cache is full and
                // stays there; the projection would only ever read "~0 s".
                if rate > 0.0 && self.trims == 0 && max > size {
                    lines.push(Line::from(vec![kv(
                        "full in",
                        format!("~{}", fmt_eta((max - size) as f64 / rate)),
                    )]));
                }
            }
            if self.trims > 0 {
                lines.push(Line::from(vec![
                    kv(
                        "trimmed",
                        format!(
                            "{} times, {} freed",
                            self.trims,
                            fmt_bytes(Some(self.trimmed))
                        ),
                    ),
                    Span::styled(" (at its ceiling)", Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
        lines.push(Line::from(vec![kv(
            "preprocessor cache mode",
            if info.use_preprocessor_cache_mode {
                "yes"
            } else {
                "no"
            },
        )]));
        lines.push(Line::from(vec![kv(
            "base directories",
            if info.basedirs.is_empty() {
                "(none)".to_string()
            } else {
                info.basedirs.join(", ")
            },
        )]));
        // `ServerInfo::version` is stamped by the server process, matching the
        // `server v…` shown in the status bar.
        lines.push(Line::from(vec![kv("server version", info.version.clone())]));

        match usage.and_then(|(size, max)| pie_width(inner).map(|w| (size, max, w))) {
            Some((size, max, width)) => {
                let [pie, _gap, text_area] = Layout::horizontal([
                    Constraint::Length(width),
                    Constraint::Length(2),
                    Constraint::Min(20),
                ])
                .areas(inner);
                draw_pie(frame, pie, size, max);
                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), text_area);
            }
            // Nothing to scale against, or too small for the pie: fall back to
            // the one-line gauge.
            None => {
                let [gauge_area, text_area] =
                    Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
                frame.render_widget(
                    cache_gauge(info.cache_size, info.max_cache_size),
                    gauge_area,
                );
                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), text_area);
            }
        }

        if usage.is_some() {
            self.draw_cache_trend(frame, trend);
        }

        if let Some(levels) = info.stats.multi_level.as_ref().filter(|_| has_levels) {
            let header = Row::new(
                [
                    "Level",
                    "hits",
                    "misses",
                    "hit rate",
                    "writes",
                    "fails",
                    "backfills",
                    "location",
                ]
                .into_iter()
                .enumerate()
                // Only the name and location columns are left-aligned.
                .map(|(i, h)| {
                    if i == 0 || i == 7 {
                        Cell::from(h)
                    } else {
                        right(h)
                    }
                }),
            )
            .style(Style::default().fg(Color::Cyan).bold());

            let rows = levels.0.iter().map(|l| {
                let total = l.hits + l.misses;
                let rate = if total == 0 {
                    "-".to_string()
                } else {
                    format!("{:.2} %", l.hits as f64 / total as f64 * 100.0)
                };
                Row::new(vec![
                    Cell::from(l.name.as_str()),
                    num(l.hits),
                    num(l.misses),
                    right(rate),
                    num(l.writes),
                    right(l.write_failures.to_string()).style(if l.write_failures > 0 {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    }),
                    right(format!("{}→/{}←", l.backfills_from, l.backfills_to)),
                    Cell::from(l.location.as_str()),
                ])
            });
            frame.render_widget(
                Table::new(
                    rows,
                    [
                        Constraint::Length(14),
                        Constraint::Length(10),
                        Constraint::Length(10),
                        Constraint::Length(10),
                        Constraint::Length(10),
                        Constraint::Length(7),
                        Constraint::Length(12),
                        Constraint::Min(10),
                    ],
                )
                .header(header)
                .block(titled("Cache levels")),
                bottom,
            );
        }
    }

    fn draw_dist(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = titled("Distributed compilation");
        let text = match &self.dist {
            None => "fetching dist status…".to_string(),
            Some(DistInfo::Disabled(reason)) => format!("Disabled: {reason}"),
            #[cfg(feature = "dist-client")]
            Some(DistInfo::NotConnected(url, reason)) => format!(
                "Not connected\nScheduler: {}\nReason: {reason}",
                url.as_ref()
                    .map(|u| u.to_url().to_string())
                    .unwrap_or_else(|| "(none configured)".to_string()),
            ),
            #[cfg(feature = "dist-client")]
            Some(DistInfo::SchedulerStatus(url, status)) => format!(
                "Connected\nScheduler: {}\n\n{}",
                url.as_ref()
                    .map(|u| u.to_url().to_string())
                    .unwrap_or_else(|| "(none configured)".to_string()),
                serde_json::to_string_pretty(status).unwrap_or_else(|e| e.to_string()),
            ),
        };
        let mut lines: Vec<Line<'_>> = text.lines().map(Line::from).collect();
        if let Some(info) = self.info.as_ref() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![kv(
                "failed distributed compiles",
                info.stats.dist_errors.to_string(),
            )]));
            for (server, count) in sorted_counts(&info.stats.dist_compiles) {
                lines.push(Line::from(vec![kv(server, count.to_string())]));
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block),
            area,
        );
    }
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from("Keys".to_string()).style(Style::default().fg(Color::Cyan).bold()),
        Line::from("  q, Esc, Ctrl-C/D      quit"),
        Line::from("  1-5, Tab, ←/→, h/l    switch pane"),
        Line::from("  a                     per-compiler instead of per-language counts"),
        Line::from("  r                     poll now, even while paused"),
        Line::from("  p, Space              pause/resume polling"),
        Line::from("  +/-                   double/halve the poll interval"),
        Line::from("  z z                   zero the server's statistics (twice to confirm)"),
        Line::from("  ?, F1                 close this help"),
        Line::from(""),
        Line::from("The monitor is an ordinary client of the running server. Each poll"),
        Line::from("resets the server's idle-shutdown timer, so a watched server will not"),
        Line::from("time out on its own — pause polling if you need it to."),
    ];
    let [area] = Layout::horizontal([Constraint::Length(74)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Length(16)])
        .flex(Flex::Center)
        .areas(area);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(lines).block(titled("Help")), area);
}

// ---------------------------------------------------------------------------
// Small rendering helpers
// ---------------------------------------------------------------------------

const LANGUAGE_COLUMNS: [Constraint; 6] = [
    Constraint::Length(24),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(8),
    Constraint::Min(10),
];

/// One line of the languages pane: the counts for a single language, or for a
/// single language and compiler pair in advanced mode.
struct LangStat {
    lang: String,
    hits: u64,
    misses: u64,
    errors: u64,
}

impl LangStat {
    fn total(&self) -> u64 {
        self.hits + self.misses
    }

    fn hit_ratio(&self) -> f64 {
        if self.total() == 0 {
            0.0
        } else {
            self.hits as f64 / self.total() as f64
        }
    }

    fn row(&self, busiest: u64, bar_width: usize) -> Row<'static> {
        let rate = if self.total() == 0 {
            "-".to_string()
        } else {
            format!("{:.2} %", self.hit_ratio() * 100.0)
        };
        let errors = if self.errors == 0 {
            right("-").style(Style::default().fg(Color::DarkGray))
        } else {
            right(self.errors.to_string()).style(Style::default().fg(Color::Red))
        };
        Row::new(vec![
            Cell::from(self.lang.clone()),
            num(self.hits),
            num(self.misses),
            right(rate),
            errors,
            Cell::from(self.bar(busiest, bar_width)),
        ])
    }

    /// A bar as long as this language's share of the `busiest` one, split
    /// green/magenta at its hit rate.
    fn bar(&self, busiest: u64, width: usize) -> Line<'static> {
        let scaled = (self.total() as f64 / busiest as f64 * width as f64).round() as usize;
        let hits = (self.hit_ratio() * scaled as f64).round() as usize;
        Line::from(vec![
            Span::styled("█".repeat(hits), Style::default().fg(Color::Green)),
            Span::styled(
                "█".repeat(scaled.saturating_sub(hits)),
                Style::default().fg(Color::Magenta),
            ),
        ])
    }
}

/// Collect the per-language counts, or the per-language-and-compiler counts
/// when `advanced`, for every language that appears in any of them.
fn language_stats(stats: &ServerStats, advanced: bool) -> Vec<LangStat> {
    fn pick(count: &PerLanguageCount, advanced: bool) -> &HashMap<String, u64> {
        if advanced {
            count.adv_counts()
        } else {
            count.counts()
        }
    }
    let hits = pick(&stats.cache_hits, advanced);
    let misses = pick(&stats.cache_misses, advanced);
    let errors = pick(&stats.cache_errors, advanced);

    let mut langs: Vec<&String> = hits
        .keys()
        .chain(misses.keys())
        .chain(errors.keys())
        .collect();
    langs.sort();
    langs.dedup();
    langs
        .into_iter()
        .map(|lang| LangStat {
            lang: lang.clone(),
            hits: hits.get(lang).copied().unwrap_or(0),
            misses: misses.get(lang).copied().unwrap_or(0),
            errors: errors.get(lang).copied().unwrap_or(0),
        })
        .collect()
}

fn titled(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(Color::Cyan),
        ))
}

fn placeholder(text: &str) -> Paragraph<'_> {
    Paragraph::new(text).style(Style::default().fg(Color::DarkGray))
}

fn sep() -> Span<'static> {
    Span::styled(" │ ", Style::default().fg(Color::DarkGray))
}

fn kv<S: Into<String>>(name: &str, value: S) -> Span<'static> {
    Span::raw(format!("{name} {}", value.into()))
}

/// A right-aligned cell, the shape every numeric column in here wants.
fn right<S: Into<String>>(text: S) -> Cell<'static> {
    Cell::from(Line::from(text.into()).alignment(Alignment::Right))
}

/// A right-aligned count, dimmed when it is zero.
fn num(value: u64) -> Cell<'static> {
    let cell = right(value.to_string());
    if value == 0 {
        cell.style(Style::default().fg(Color::DarkGray))
    } else {
        cell
    }
}

fn hit_rate_colour(ratio: f64, total: u64) -> Color {
    if total == 0 {
        Color::DarkGray
    } else if ratio >= 0.75 {
        Color::Green
    } else if ratio >= 0.4 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn cache_gauge(size: Option<u64>, max: Option<u64>) -> Gauge<'static> {
    let ratio = match (size, max) {
        (Some(s), Some(m)) if m > 0 => (s as f64 / m as f64).clamp(0.0, 1.0),
        _ => 0.0,
    };
    let label = match (size, max) {
        (Some(_), Some(_)) => format!(
            "cache {} / {} ({:.1} %)",
            fmt_bytes(size),
            fmt_bytes(max),
            ratio * 100.0
        ),
        (Some(_), None) => format!("cache {}", fmt_bytes(size)),
        _ => "cache size unknown".to_string(),
    };
    Gauge::default()
        .ratio(ratio)
        .label(label)
        .gauge_style(Style::default().fg(fill_colour(ratio)))
        .use_unicode(true)
}

/// How full is too full: the same scale for the gauge and the pie.
fn fill_colour(ratio: f64) -> Color {
    if ratio >= 0.9 {
        Color::Red
    } else if ratio >= 0.7 {
        Color::Yellow
    } else {
        Color::Blue
    }
}

/// Width to give the pie column, or `None` when the pane is too small for one.
///
/// Braille cells are twice as tall as they are wide, so a 2:1 area comes out
/// round; one line goes to the legend underneath.
fn pie_width(inner: Rect) -> Option<u16> {
    let plot_height = inner.height.checked_sub(1)?;
    if plot_height < 5 || inner.width < 46 {
        return None;
    }
    let width = (plot_height * 2).min(inner.width / 2).min(30);
    (width >= 10).then_some(width)
}

/// Draw the cache fill as a two-slice pie with a legend under it.
fn draw_pie(frame: &mut Frame<'_>, area: Rect, size: u64, max: u64) {
    let [plot, legend] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let ratio = (size as f64 / max as f64).clamp(0.0, 1.0);
    let colour = fill_colour(ratio);
    let (used, free) = pie_points(plot, ratio);
    frame.render_widget(
        Canvas::default()
            .marker(Marker::Braille)
            .x_bounds([-1.0, 1.0])
            .y_bounds([-1.0, 1.0])
            .paint(|ctx| {
                ctx.draw(&Points {
                    coords: &free,
                    color: Color::DarkGray,
                });
                ctx.draw(&Points {
                    coords: &used,
                    color: colour,
                });
            }),
        plot,
    );
    // Kept short: the column is only as wide as the pie, and the byte figures
    // are already spelled out beside it.
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("█", Style::default().fg(colour)),
            Span::raw(format!(" {:.2} % full", ratio * 100.0)),
        ]))
        .alignment(Alignment::Center),
        legend,
    );
}

/// Rasterise a two-slice pie: the used slice starts at twelve o'clock and runs
/// clockwise. One point per braille dot of `area`, in canvas coordinates.
fn pie_points(area: Rect, ratio: f64) -> (Vec<(f64, f64)>, Vec<(f64, f64)>) {
    let (nx, ny) = (area.width as usize * 2, area.height as usize * 4);
    let mut used = Vec::new();
    let mut free = Vec::new();
    for iy in 0..ny {
        let y = -1.0 + 2.0 * (iy as f64 + 0.5) / ny as f64;
        for ix in 0..nx {
            let x = -1.0 + 2.0 * (ix as f64 + 0.5) / nx as f64;
            if x * x + y * y > 1.0 {
                continue;
            }
            // `atan2(x, y)` is zero at twelve o'clock and grows clockwise.
            let mut angle = x.atan2(y);
            if angle < 0.0 {
                angle += std::f64::consts::TAU;
            }
            if angle / std::f64::consts::TAU < ratio {
                used.push((x, y));
            } else {
                free.push((x, y));
            }
        }
    }
    (used, free)
}

fn fmt_bytes(bytes: Option<u64>) -> String {
    match bytes {
        None => "?".to_string(),
        Some(b) => match NumberPrefix::binary(b as f64) {
            NumberPrefix::Standalone(n) => format!("{n} bytes"),
            NumberPrefix::Prefixed(prefix, n) => format!("{n:.1} {prefix}B"),
        },
    }
}

fn fmt_interval(interval: Duration) -> String {
    let secs = interval.as_secs_f64();
    if secs < 1.0 {
        format!("{}ms", interval.as_millis())
    } else {
        format!("{secs:.1}s")
    }
}

/// A coarse duration for projections, where minutes of precision on an
/// estimate measured in hours would be false confidence.
fn fmt_eta(secs: f64) -> String {
    if !secs.is_finite() || secs >= 99.0 * 86_400.0 {
        return "a very long time".to_string();
    }
    let s = secs as u64;
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 => format!("{} min", s / 60),
        3600..=86_399 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        _ => format!("{} d {} h", s / 86_400, (s % 86_400) / 3600),
    }
}

fn fmt_uptime(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// Sort counts by descending count, then by key for a stable order.
fn sorted_counts(counts: &HashMap<String, usize>) -> Vec<(&str, usize)> {
    let mut v: Vec<(&str, usize)> = counts.iter().map(|(k, &c)| (k.as_str(), c)).collect();
    v.sort_by(|(k1, c1), (k2, c2)| c2.cmp(c1).then_with(|| k1.cmp(k2)));
    v
}

fn counted_table<'a>(
    counts: &'a HashMap<String, usize>,
    empty: &'a str,
    colour: Color,
) -> Table<'a> {
    if counts.is_empty() {
        return Table::default().rows(vec![Row::new(vec![Cell::from(
            Line::from(empty).style(Style::default().fg(Color::DarkGray)),
        )])]);
    }
    let total: usize = counts.values().sum();
    let rows = sorted_counts(counts).into_iter().map(|(reason, count)| {
        let share = if total == 0 {
            0.0
        } else {
            count as f64 / total as f64
        };
        Row::new(vec![
            Cell::from(reason),
            right(count.to_string()),
            right(format!("{:.1} %", share * 100.0)),
            Cell::from(
                Line::from("█".repeat((share * 20.0).round() as usize))
                    .style(Style::default().fg(colour)),
            ),
        ])
    });
    Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(21),
        ],
    )
}

/// Ensure the terminal is restored even if the UI panics.
fn install_panic_hook() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = io::Write::flush(&mut io::stdout());
        ratatui::restore();
        hook(info);
    }));
}
