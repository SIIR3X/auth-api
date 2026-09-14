use testkit::TestDb;

#[tokio::test]
async fn all_migrations_apply_to_a_fresh_database() {
    let db = TestDb::new().await;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles")
        .fetch_one(&db.pool)
        .await
        .expect("failed to count seeded roles");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn security_support_tables_exist_after_migrations() {
    let db = TestDb::new().await;

    let names = sqlx::query_scalar::<_, String>(
        "SELECT tablename
             FROM pg_tables
             WHERE schemaname = 'public'
               AND tablename IN (
                    'login_attempts',
                    'email_verification_tokens',
                    'password_reset_tokens',
                    'recovery_codes'
               )
             ORDER BY tablename",
    )
    .fetch_all(&db.pool)
    .await
    .expect("failed to inspect pg_tables");

    assert_eq!(
        names,
        vec![
            "email_verification_tokens".to_owned(),
            "login_attempts".to_owned(),
            "password_reset_tokens".to_owned(),
            "recovery_codes".to_owned(),
        ]
    );
}

#[tokio::test]
async fn hot_tables_are_vacuumed_before_they_bloat() {
    let db = testkit::TestDb::new().await;
    for (table, expected) in [
        (
            "sessions",
            &[
                "autovacuum_vacuum_scale_factor=0.02",
                "autovacuum_analyze_scale_factor=0.01",
            ][..],
        ),
        (
            "login_attempts",
            &[
                "autovacuum_vacuum_scale_factor=0.02",
                "autovacuum_vacuum_insert_scale_factor=0.02",
                "autovacuum_analyze_scale_factor=0.01",
            ][..],
        ),
    ] {
        let options: Vec<String> = sqlx::query_scalar(
            "SELECT unnest(reloptions) FROM pg_class WHERE relname = $1 AND relkind = 'r'",
        )
        .bind(table)
        .fetch_all(&db.pool)
        .await
        .unwrap();
        for option in expected {
            assert!(
                options.iter().any(|o| o == option),
                "{table} lacks {option}: {options:?}"
            );
        }
    }
}
