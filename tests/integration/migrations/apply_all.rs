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
