"""Schema checks for the database created at startup."""

import unittest

from sqlalchemy import inspect, text

from app.persistence.database import engine, init_db
from app.persistence.orm import Alert, Finding
from tests.support import reset_db

EXPECTED_TABLES = {
    "analysis_sessions",
    "flow_summaries",
    "protocol_events",
    "findings",
    "alerts",
    "indicators",
    "timeline_events",
    "reports",
}


class DatabaseInitTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_db()

    def test_init_db_creates_planned_tables(self) -> None:
        init_db()
        table_names = set(inspect(engine).get_table_names())
        self.assertTrue(EXPECTED_TABLES <= table_names)
        self.assertNotIn("packets", table_names)

    def test_severity_and_confidence_stay_separate(self) -> None:
        finding_columns = {column.name for column in Finding.__table__.columns}
        alert_columns = {column.name for column in Alert.__table__.columns}
        self.assertIn("confidence", finding_columns)
        self.assertIn("severity", finding_columns)
        self.assertIn("confidence", alert_columns)
        self.assertIn("severity", alert_columns)
        self.assertNotIn("risk_score", finding_columns)
        self.assertNotIn("risk_score", alert_columns)

    def test_outdated_schema_is_recreated(self) -> None:
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE findings"))
            connection.execute(text("CREATE TABLE findings (id INTEGER PRIMARY KEY, confidence FLOAT)"))
        init_db()
        columns = {column["name"] for column in inspect(engine).get_columns("findings")}
        self.assertIn("severity", columns)
        self.assertIn("confidence", columns)


if __name__ == "__main__":
    unittest.main()
