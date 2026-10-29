//! One background thread for GUI work that must not run on the paint thread.
//!
//! The socket thread already has this shape -- a named `std::thread`, an `mpsc` queue in each
//! direction and a [`Waker`] that schedules the frame draining it -- and a derivation gets no
//! runtime of its own either: there is no async runtime in this crate, by design.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use crate::ipc::Waker;
use crate::ui::connections::{LinesJob, LinesReady, derive};

/// One unit of work handed to the thread.
#[derive(Debug)]
pub enum Job {
   /// Rebuild the Connections lines from an owned snapshot of the log and the rules.
   Lines(Box<LinesJob>),
}

/// One finished derivation, tagged with the inputs it was built from.
#[derive(Debug)]
pub enum Done {
   Lines(Box<LinesReady>),
}

/// Handle to the worker thread; dropping it ends the thread.
pub struct Worker {
   jobs: Sender<Job>,
   done: Receiver<Done>,
}

impl Worker {
   /// Spawns the thread. `None` when it cannot be created; the caller then derives on the GUI
   /// thread rather than leaving the list stale without explanation.
   pub fn spawn(waker: Waker) -> Option<Self> {
      let (jobs, job_rx) = mpsc::channel::<Job>();
      let (done_tx, done) = mpsc::channel::<Done>();
      let spawned = thread::Builder::new().name("netshield-work".to_owned()).spawn(move || {
         while let Ok(job) = job_rx.recv() {
            let finished = match job {
               Job::Lines(job) => Done::Lines(Box::new(derive(&job))),
            };
            if done_tx.send(finished).is_err() {
               break;
            }
            waker();
         }
      });
      match spawned {
         Ok(_) => Some(Self { jobs, done }),
         Err(err) => {
            log::error!("cannot start the work thread: {err}");
            None
         }
      }
   }

   /// Queues one job; `false` when the thread is gone. Never blocks.
   pub fn submit(&self, job: Job) -> bool {
      self.jobs.send(job).is_ok()
   }

   /// Non-blocking drain for the UI: `None` when nothing has finished yet.
   pub fn poll(&self) -> Option<Done> {
      self.done.try_recv().ok()
   }
}
