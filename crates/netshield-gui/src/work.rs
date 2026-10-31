//! One background thread for GUI work that must not run on the paint thread.
//!
//! The socket thread already has this shape -- a named `std::thread`, an `mpsc` queue in each
//! direction and a [`Waker`] that schedules the frame draining it -- and a derivation gets no
//! runtime of its own either: there is no async runtime in this crate, by design.
//!
//! The same thread also writes the daemon frames that a paint would otherwise write itself: a
//! `send` only locks the queue and notifies, so a wedged daemon cannot stall a frame. Frames are
//! served ahead of jobs so a prompt answer is not delayed by a queued derivation.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;

use crate::ipc::{Waker, Writer};
use crate::prefs::Prefs;
use crate::ui::connections::{LinesJob, LinesReady, derive};

/// How many daemon frames may wait for the socket. A full queue drops the newest frame and counts
/// it, exactly as `Writer` did for the pre-connect buffer: a wedged daemon must never block a paint.
pub const FRAME_CAP: usize = 64;

/// How many log records may wait for the file. A full queue drops the newest record and counts it:
/// a logger must never block the thread that logged, nor grow without bound.
pub const LOG_CAP: usize = 4096;

/// One unit of work handed to the thread.
#[derive(Debug)]
pub enum Job {
   /// Rebuild the Connections lines from an owned snapshot of the log and the rules.
   Lines(Box<LinesJob>),
   /// Write the preferences file. The UI has already applied these caps, so nothing comes
   /// back: the file is the output, and an `fsync` on the paint thread is exactly what this
   /// job exists to avoid.
   SavePrefs(Prefs),
}

/// One formatted record waiting for the file.
#[derive(Debug)]
pub struct LogRecord {
   /// The finished line, newline included.
   pub line: String,
   /// Whether a hand-started run should also see it on stderr: `warn` and above.
   pub mirror: bool,
}

/// One finished derivation, tagged with the inputs it was built from.
#[derive(Debug)]
pub enum Done {
   Lines(Box<LinesReady>),
}

/// One item for the work thread.
#[derive(Debug)]
enum Item {
   /// A frame for the daemon socket, served before every job.
   Frame(String),
   Job(Job),
   Log(LogRecord),
}

/// What the one thread drains, and what could not be queued.
///
/// Frames are served ahead of jobs because they are small and latency-critical, and they keep their
/// own order: consecutive frames are inserted before the first job, never reversed. Records sit in
/// their own lane, drained only when no frame or job is waiting. The accepted residual of one
/// thread serving all four lanes is that a log record waits behind an in-flight derivation or a
/// preferences `fsync`, while a burst of records never delays a frame or a derivation.
#[derive(Default)]
struct Queue {
   items: VecDeque<Item>,
   /// How many leading items are frames, so the cap can be checked without walking the queue.
   frames: usize,
   /// Formatted records, drained only when no frame or job is waiting.
   logs: VecDeque<LogRecord>,
   /// Frames that found the queue full since the last report.
   dropped_frames: u64,
   /// Records that found the queue full since the last report.
   dropped_log: u64,
   /// Set when the `Worker` is dropped; the thread returns once the queue is empty.
   closed: bool,
}

impl Queue {
   /// Adds a frame ahead of the queued jobs, keeping the order of earlier frames.
   ///
   /// `false` when the frame cap is reached: the incoming frame is dropped and counted rather than
   /// growing the queue or blocking the caller.
   fn push_frame(&mut self, line: String) -> bool {
      if self.frames >= FRAME_CAP {
         self.dropped_frames += 1;
         return false;
      }
      self.items.insert(self.frames, Item::Frame(line));
      self.frames += 1;
      true
   }

   fn push_job(&mut self, job: Job) {
      self.items.push_back(Item::Job(job));
   }

   /// Adds a record behind every frame and job; `false` when the record cap is reached.
   fn push_log(&mut self, record: LogRecord) -> bool {
      if self.logs.len() >= LOG_CAP {
         self.dropped_log += 1;
         return false;
      }
      self.logs.push_back(record);
      true
   }

   fn pop(&mut self) -> Option<Item> {
      if let Some(item) = self.items.pop_front() {
         if matches!(item, Item::Frame(_)) {
            self.frames -= 1;
         }
         return Some(item);
      }
      self.logs.pop_front().map(Item::Log)
   }

   fn is_empty(&self) -> bool {
      self.items.is_empty() && self.logs.is_empty()
   }

   /// Takes the frames dropped since the last call, so the thread that owns the log reports them.
   fn take_dropped(&mut self) -> u64 {
      std::mem::take(&mut self.dropped_frames)
   }

   /// Records dropped since the last call, so the writer reports them once.
   fn take_dropped_log(&mut self) -> u64 {
      std::mem::take(&mut self.dropped_log)
   }
}

/// The queue every producer shares; the thread waits on `ready` while it is empty.
struct Shared {
   queue: Mutex<Queue>,
   ready: Condvar,
}

impl Shared {
   fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
      self.queue.lock().unwrap_or_else(PoisonError::into_inner)
   }
}

/// Handle to the worker thread; dropping it ends the thread.
pub struct Worker {
   shared: Arc<Shared>,
   done: Receiver<Done>,
}

impl Worker {
   /// Spawns the thread. `None` when it cannot be created; the caller then derives on the GUI
   /// thread rather than leaving the list stale without explanation.
   pub fn spawn(waker: Waker, writer: Writer) -> Option<Self> {
      let shared = Arc::new(Shared {
         queue: Mutex::new(Queue::default()),
         ready: Condvar::new(),
      });
      let (done_tx, done) = mpsc::channel::<Done>();
      let thread_shared = Arc::clone(&shared);
      let spawned = thread::Builder::new()
         .name("netshield-work".to_owned())
         .spawn(move || run(thread_shared, writer, waker, done_tx));
      match spawned {
         Ok(_) => Some(Self { shared, done }),
         Err(err) => {
            log::error!("cannot start the work thread: {err}");
            None
         }
      }
   }

   /// Queues one job; `false` when the thread is gone. Never blocks.
   pub fn submit(&self, job: Job) -> bool {
      self.handle().submit(job)
   }

   /// A submitting handle, for callers that do not own this worker.
   pub fn handle(&self) -> Handle {
      Handle {
         shared: Arc::clone(&self.shared),
      }
   }

   /// Non-blocking drain for the UI: `None` when nothing has finished yet.
   pub fn poll(&self) -> Option<Done> {
      self.done.try_recv().ok()
   }
}

impl Drop for Worker {
   fn drop(&mut self) {
      let mut queue = self.shared.lock();
      queue.closed = true;
      drop(queue);
      self.shared.ready.notify_all();
   }
}

/// A second way into the work thread's queue.
///
/// The `Worker` owns the result channel and belongs to the Connections cache; anything else that
/// only needs to *submit* work takes a handle instead, so one thread serves the whole GUI.
#[derive(Clone)]
pub struct Handle {
   shared: Arc<Shared>,
}

impl Handle {
   /// Queues one job; `false` when the thread is gone. Never blocks.
   pub fn submit(&self, job: Job) -> bool {
      let mut queue = self.shared.lock();
      if queue.closed {
         return false;
      }
      queue.push_job(job);
      drop(queue);
      self.shared.ready.notify_one();
      true
   }

   /// Queues one daemon frame ahead of the jobs; `false` when it could not be queued.
   ///
   /// This is the only write path a paint frame has: it locks, pushes and notifies, and never
   /// touches the socket, so a wedged daemon cannot stall the window.
   pub fn frame(&self, line: String) -> bool {
      let mut queue = self.shared.lock();
      if queue.closed {
         return false;
      }
      let queued = queue.push_frame(line);
      drop(queue);
      self.shared.ready.notify_one();
      queued
   }

   /// Queues one formatted record; `false` when it could not be queued.
   ///
   /// Never blocks and never writes: this is the only path a `log::` call has once the thread is
   /// attached, so a slow or full disk cannot stall the caller.
   pub fn log(&self, record: LogRecord) -> bool {
      let mut queue = self.shared.lock();
      if queue.closed {
         return false;
      }
      let queued = queue.push_log(record);
      drop(queue);
      self.shared.ready.notify_one();
      queued
   }
}

/// Serves the queue forever; returns when the `Worker` is dropped and the queue is empty.
fn run(shared: Arc<Shared>, writer: Writer, waker: Waker, done: Sender<Done>) {
   loop {
      let next = {
         let mut queue = shared.lock();
         while queue.is_empty() && !queue.closed {
            queue = shared.ready.wait(queue).unwrap_or_else(PoisonError::into_inner);
         }
         if queue.closed && queue.is_empty() {
            return;
         }
         queue.pop()
      };
      match next {
         Some(Item::Frame(line)) => {
            writer.write_frame(&line);
         }
         Some(Item::Job(job)) => match job {
            Job::Lines(job) => {
               if done.send(Done::Lines(Box::new(derive(&job)))).is_err() {
                  return;
               }
               // Only a finished derivation has something for the UI to install; a save
               // wakes nobody.
               waker();
            }
            Job::SavePrefs(prefs) => prefs.save(),
         },
         Some(Item::Log(record)) => crate::logging::write_record(&record),
         None => {}
      }
      // Reported from this thread because it owns the log write path; the count is taken so the
      // same drops are never reported twice.
      let dropped = shared.lock().take_dropped();
      if dropped > 0 {
         log::warn!("{dropped} daemon frame(s) dropped: the write queue was full");
      }
      let dropped = shared.lock().take_dropped_log();
      if dropped > 0 {
         log::warn!("{dropped} log record(s) dropped: the log queue was full");
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn frames_are_served_first_and_keep_their_order() {
      let mut queue = Queue::default();
      queue.push_job(Job::SavePrefs(Prefs::default()));
      assert!(queue.push_frame("status".to_owned()));
      assert!(queue.push_frame("listrules".to_owned()));

      assert!(
         matches!(queue.pop(), Some(Item::Frame(line)) if line == "status"),
         "the first frame keeps its order"
      );
      assert!(
         matches!(queue.pop(), Some(Item::Frame(line)) if line == "listrules"),
         "frames are not reversed"
      );
      assert!(
         matches!(queue.pop(), Some(Item::Job(_))),
         "the job is served last"
      );
      assert!(queue.pop().is_none());
   }

   #[test]
   fn a_full_frame_queue_drops_the_newest_and_counts_it() {
      let mut queue = Queue::default();
      for n in 0..FRAME_CAP {
         assert!(
            queue.push_frame(format!("frame {n}")),
            "slot {n} must fit"
         );
      }
      assert!(
         !queue.push_frame("over the cap".to_owned()),
         "the cap must refuse the frame"
      );
      assert_eq!(queue.take_dropped(), 1, "the refusal is counted");
      assert_eq!(queue.take_dropped(), 0, "and counted once");
      assert_eq!(
         queue.frames, FRAME_CAP,
         "the queue never grows past the cap"
      );
   }

   #[test]
   fn records_are_served_after_frames_and_jobs() {
      let mut queue = Queue::default();
      assert!(queue.push_log(LogRecord {
         line: "info line".to_owned(),
         mirror: false,
      }));
      queue.push_job(Job::SavePrefs(Prefs::default()));
      assert!(queue.push_frame("status".to_owned()));

      assert!(
         matches!(queue.pop(), Some(Item::Frame(_))),
         "the frame goes first"
      );
      assert!(
         matches!(queue.pop(), Some(Item::Job(_))),
         "then the job"
      );
      assert!(
         matches!(queue.pop(), Some(Item::Log(record)) if record.line == "info line"),
         "the record is served last"
      );
      assert!(queue.pop().is_none());
   }

   #[test]
   fn a_full_log_queue_drops_the_newest_and_counts_it() {
      let mut queue = Queue::default();
      for n in 0..LOG_CAP {
         assert!(
            queue.push_log(LogRecord {
               line: format!("line {n}"),
               mirror: false,
            }),
            "slot {n} must fit"
         );
      }
      assert!(
         !queue.push_log(LogRecord {
            line: "over the cap".to_owned(),
            mirror: false,
         }),
         "the cap must refuse the record"
      );
      assert_eq!(
         queue.take_dropped_log(),
         1,
         "the refusal is counted"
      );
      assert_eq!(queue.take_dropped_log(), 0, "and counted once");
   }
}
