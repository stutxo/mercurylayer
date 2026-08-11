use chrono::{DateTime, Utc};

use sqlx::Row;

pub async fn get_batch_id_and_time_by_statechain_id_in_tx(
    connection: &mut sqlx::PgConnection,
    statechain_id: &str,
) -> Result<Option<(String, DateTime<Utc>)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT batch_id, batch_time \
         FROM statechain_transfer \
         WHERE statechain_id = $1 \
           AND batch_id IS NOT NULL \
           AND batch_time IS NOT NULL",
    )
    .bind(statechain_id)
    .fetch_optional(connection)
    .await?;

    Ok(row.map(|row| (row.get(0), row.get(1))))
}

pub async fn is_all_coins_unlocked_in_tx(
    connection: &mut sqlx::PgConnection,
    batch_id: &str,
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT locked, locked2 \
         FROM statechain_transfer \
         WHERE batch_id = $1 \
         FOR UPDATE",
    )
    .bind(batch_id)
    .fetch_all(connection)
    .await?;

    Ok(rows
        .into_iter()
        .all(|row| !row.get::<bool, _>(0) && !row.get::<bool, _>(1)))
}

pub async fn get_batch_id_and_time_by_statechain_id(
    pool: &sqlx::PgPool,
    statechain_id: &str,
) -> Option<(String, DateTime<Utc>)> {
    let query = "\
        SELECT batch_id, batch_time \
        FROM statechain_transfer \
        WHERE statechain_id = $1
        AND batch_id is not null
        AND batch_time is not null";

    let row = sqlx::query(query)
        .bind(statechain_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    match row {
        Some(row) => {
            let batch_id: String = row.get(0);
            let batch_time: DateTime<Utc> = row.get(1);
            Some((batch_id, batch_time))
        }
        None => None,
    }
}

pub async fn is_all_coins_unlocked(pool: &sqlx::PgPool, batch_id: &str) -> bool {
    let query = "\
        SELECT locked, locked2 \
        FROM statechain_transfer \
        WHERE batch_id = $1";

    let rows = sqlx::query(query)
        .bind(batch_id)
        .fetch_all(pool)
        .await
        .unwrap();

    for row in rows {
        let locked: bool = row.get(0);
        let locked2: bool = row.get(1);

        if locked || locked2 {
            return false;
        }
    }

    true
}
