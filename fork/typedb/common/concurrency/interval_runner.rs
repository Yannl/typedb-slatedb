/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel},
    thread,
    time::Duration,
};

#[derive(Debug)]
pub struct IntervalRunner {
    shutdown_sink: SyncSender<SyncSender<()>>,
}

impl IntervalRunner {
    const ZERO_DURATION: Duration = Duration::from_secs(0);

    pub fn new(action: impl FnMut() + Send + 'static, interval: Duration) -> Self {
        Self::new_with_initial_delay(action, interval, Self::ZERO_DURATION)
    }

    pub fn new_with_initial_delay(
        mut action: impl FnMut() + Send + 'static,
        interval: Duration,
        initial_delay: Duration,
    ) -> Self {
        let (shutdown_sender, shutdown_receiver) = sync_channel::<SyncSender<()>>(1);
        thread::spawn(move || {
            match shutdown_receiver.recv_timeout(initial_delay) {
                Ok(done_sender) => {
                    drop(action);
                    let _ = done_sender.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => return, // TODO log?
            }

            loop {
                action();
                match shutdown_receiver.recv_timeout(interval) {
                    Ok(done_sender) => {
                        drop(action);
                        let _ = done_sender.send(());
                        break;
                    }
                    Err(RecvTimeoutError::Timeout) => (),
                    Err(RecvTimeoutError::Disconnected) => break, // TODO log?
                }
            }
        });
        Self { shutdown_sink: shutdown_sender }
    }
}

impl Drop for IntervalRunner {
    fn drop(&mut self) {
        // Non-panicking teardown: the worker thread may already be gone —
        // its action panicked, or the process is mid-abort — in which case
        // `send` sees a disconnected channel. A panic here would be a panic
        // inside Drop, which during another panic's unwind aborts the
        // process at the wrong place; a missing worker needs no shutdown, so
        // both failure modes are a quiet no-op.
        let (done_sender, done_receiver) = sync_channel(1);
        if self.shutdown_sink.send(done_sender).is_err() {
            return;
        }
        let _ = done_receiver.recv();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::IntervalRunner;

    #[test]
    fn dropping_a_runner_whose_action_panicked_does_not_panic() {
        // the action panic kills the worker thread, disconnecting the
        // shutdown channel; Drop must treat that as "nothing to shut down",
        // not as a second panic (which, during an unwind, aborts the process)
        let runner = IntervalRunner::new(|| panic!("worker died"), Duration::from_secs(3600));
        std::thread::sleep(Duration::from_millis(200));
        drop(runner); // must return quietly
    }

    #[test]
    fn dropping_a_live_runner_still_waits_for_shutdown() {
        let runner = IntervalRunner::new(|| (), Duration::from_secs(3600));
        drop(runner);
    }
}
