use crate::common::db::TestDatabase;

#[test]
fn all_migrations_apply_to_a_fresh_database() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let count: i64 = db
        .client()
        .query_one("SELECT COUNT(*) FROM roles", &[])
        .expect("failed to count seeded roles")
        .get(0);

    assert_eq!(count, 2);
}

#[test]
fn security_support_tables_exist_after_migrations() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let rows = db
        .client()
        .query(
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
            &[],
        )
        .expect("failed to inspect pg_tables");

    let names = rows
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();

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
