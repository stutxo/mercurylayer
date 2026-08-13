use anyhow::Result;
use sqlx::{Pool, Sqlite, SqliteConnection, Transaction};

pub struct Bip448MutationGuard {
    transaction: Transaction<'static, Sqlite>,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct Bip448BeginImmediateTestHook {
    pub(super) before_acquire: tokio::sync::Notify,
    pub(super) after_acquire: tokio::sync::Notify,
    pub(super) before_emitted: std::sync::atomic::AtomicBool,
    pub(super) after_emitted: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static BIP448_BEGIN_IMMEDIATE_TEST_HOOK:
        std::sync::Arc<Bip448BeginImmediateTestHook>;
}

pub async fn begin_bip448_mutation_guard(pool: &Pool<Sqlite>) -> Result<Bip448MutationGuard> {
    let begin = pool.begin_with("BEGIN IMMEDIATE");
    #[cfg(not(test))]
    let transaction = begin.await?;
    #[cfg(test)]
    let transaction = match BIP448_BEGIN_IMMEDIATE_TEST_HOOK.try_with(Clone::clone) {
        Ok(hook) => {
            use std::future::Future;
            let mut begin = std::pin::pin!(begin);
            let transaction = std::future::poll_fn(|context| {
                if !hook
                    .before_emitted
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    hook.before_acquire.notify_one();
                }
                begin.as_mut().poll(context)
            })
            .await?;
            hook.after_emitted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            hook.after_acquire.notify_one();
            transaction
        }
        Err(_) => begin.await?,
    };
    Ok(Bip448MutationGuard { transaction })
}
impl Bip448MutationGuard {
    pub async fn commit(self) -> Result<()> {
        self.transaction.commit().await?;
        Ok(())
    }

    pub(super) async fn rollback(self) -> Result<()> {
        self.transaction.rollback().await?;
        Ok(())
    }

    pub(super) fn connection(&mut self) -> &mut SqliteConnection {
        &mut self.transaction
    }
}
