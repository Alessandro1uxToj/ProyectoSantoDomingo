BEGIN;
CREATE SEQUENCE IF NOT EXISTS sd_record_ids;
CREATE TABLE IF NOT EXISTS sd_records (
  kind TEXT NOT NULL CHECK(kind IN ('users','subjects','scores','periods','studentPeriods')),
  record_key TEXT NOT NULL,
  payload JSONB NOT NULL,
  PRIMARY KEY(kind, record_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS sd_usernames_unique
  ON sd_records (lower(payload->>'username')) WHERE kind='users';
CREATE INDEX IF NOT EXISTS sd_student_grade
  ON sd_records ((payload->>'grade_code')) WHERE kind='users';
CREATE INDEX IF NOT EXISTS sd_score_student
  ON sd_records ((payload->>'student_id')) WHERE kind='scores';
CREATE TABLE IF NOT EXISTS sd_meta (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS sd_login_attempts (
  key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  first_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_until TIMESTAMPTZ
);
COMMIT;
