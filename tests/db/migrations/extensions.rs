use crate::common::db::TestDatabase;

#[test]
fn required_extensions_are_enabled() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let rows = db
        .client()
        .query(
            "SELECT extname
             FROM pg_extension
             WHERE extname IN ('pgcrypto', 'citext')
             ORDER BY extname",
            &[],
        )
        .expect("failed to inspect installed extensions");

    let names = rows
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();

    assert_eq!(names, vec!["citext".to_owned(), "pgcrypto".to_owned()]);
}
