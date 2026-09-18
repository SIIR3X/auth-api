use testkit::TestDb;

#[tokio::test]
async fn required_extensions_are_enabled() {
    let db = TestDb::new().await;

    let names = sqlx::query_scalar::<_, String>(
        "SELECT extname
             FROM pg_extension
             WHERE extname IN ('pgcrypto', 'citext')
             ORDER BY extname",
    )
    .fetch_all(&db.pool)
    .await
    .expect("failed to inspect installed extensions");

    assert_eq!(names, vec!["citext".to_owned(), "pgcrypto".to_owned()]);
}
