use std::future::Future;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
use anyhow::ensure;
use anyhow::{Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;

use super::error::WorkflowError;

pub(super) const SIGINT: i32 = 2;
pub(super) const SIGTERM: i32 = 15;

tokio::task_local! {
    static ACTIVE: Arc<SignalState>;
}

#[cfg(test)]
thread_local! {
    static TEST_ACTIVE: RefCell<Option<Arc<SignalState>>> = const { RefCell::new(None) };
}

#[derive(Default)]
pub(super) struct SignalState {
    received: AtomicI32,
    forwarded: AtomicI32,
}

impl SignalState {
    fn receive(&self, value: i32) {
        let _ = self
            .received
            .compare_exchange(0, value, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub(super) fn received(&self) -> Option<i32> {
        nonzero(self.received.load(Ordering::SeqCst))
    }

    pub(super) fn mark_forwarded(&self, value: i32) {
        let _ = self
            .forwarded
            .compare_exchange(0, value, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn forwarded(&self) -> Option<i32> {
        nonzero(self.forwarded.load(Ordering::SeqCst))
    }
}

pub(super) struct SignalWatch {
    state: Arc<SignalState>,
    interrupt: JoinHandle<()>,
    terminate: JoinHandle<()>,
}

impl SignalWatch {
    pub(super) fn install() -> Result<Self> {
        let state = Arc::new(SignalState::default());
        let mut interrupts =
            signal(SignalKind::interrupt()).context("install SIGINT workflow listener")?;
        let mut terminations =
            signal(SignalKind::terminate()).context("install SIGTERM workflow listener")?;
        let interrupt_state = Arc::clone(&state);
        let interrupt = tokio::spawn(async move {
            if interrupts.recv().await.is_some() {
                interrupt_state.receive(SIGINT);
            }
        });
        let terminate_state = Arc::clone(&state);
        let terminate = tokio::spawn(async move {
            if terminations.recv().await.is_some() {
                terminate_state.receive(SIGTERM);
            }
        });
        Ok(Self {
            state,
            interrupt,
            terminate,
        })
    }

    #[cfg(test)]
    pub(super) async fn scope<F: Future>(&self, future: F) -> F::Output {
        ACTIVE.scope(Arc::clone(&self.state), future).await
    }

    pub(super) async fn scope_workflow<F, T>(&self, future: F) -> Result<T, WorkflowError>
    where
        F: Future<Output = Result<T, WorkflowError>>,
    {
        ACTIVE
            .scope(Arc::clone(&self.state), async {
                let result = future.await;
                normalize_workflow_result(result)
            })
            .await
    }
}

impl Drop for SignalWatch {
    fn drop(&mut self) {
        self.interrupt.abort();
        self.terminate.abort();
    }
}

pub(super) fn active() -> Option<Arc<SignalState>> {
    if let Ok(state) = ACTIVE.try_with(Arc::clone) {
        return Some(state);
    }
    #[cfg(test)]
    {
        return TEST_ACTIVE.with(|slot| slot.borrow().clone());
    }
    #[cfg(not(test))]
    None
}

pub(super) fn forwarded_signal() -> Option<i32> {
    active().and_then(|state| state.forwarded())
}

fn normalize_workflow_result<T>(result: Result<T, WorkflowError>) -> Result<T, WorkflowError> {
    let Some(signal) = forwarded_signal() else {
        return result;
    };
    let code = 128 + signal;
    if result
        .as_ref()
        .is_err_and(|error| error.exit_code() == code)
    {
        return result;
    }
    Err(WorkflowError::child_exit(
        code,
        format!("workflow interrupted by signal {signal} while a child process group was active"),
    ))
}

fn nonzero(value: i32) -> Option<i32> {
    (value != 0).then_some(value)
}

#[cfg(test)]
pub(super) struct TestSignalSession {
    state: Arc<SignalState>,
}

#[cfg(test)]
impl TestSignalSession {
    pub(super) fn install() -> Result<(Self, TestSignalSender)> {
        let state = Arc::new(SignalState::default());
        TEST_ACTIVE.with(|slot| {
            let mut slot = slot.borrow_mut();
            ensure!(
                slot.is_none(),
                "test workflow signal handling is already active"
            );
            *slot = Some(Arc::clone(&state));
            Ok::<_, anyhow::Error>(())
        })?;
        Ok((
            Self {
                state: Arc::clone(&state),
            },
            TestSignalSender { state },
        ))
    }
}

#[cfg(test)]
impl Drop for TestSignalSession {
    fn drop(&mut self) {
        TEST_ACTIVE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &self.state))
            {
                slot.take();
            }
        });
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestSignalSender {
    state: Arc<SignalState>,
}

#[cfg(test)]
impl TestSignalSender {
    pub(super) fn send(&self, value: i32) {
        assert!(matches!(value, SIGINT | SIGTERM));
        self.state.receive(value);
    }
}

#[cfg(test)]
#[path = "supervision_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "supervision_integration_tests.rs"]
mod integration_tests;
