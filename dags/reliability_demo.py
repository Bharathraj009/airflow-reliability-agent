"""A tiny, manually triggered pipeline for learning Airflow fundamentals."""

from datetime import datetime, timezone
import json
from pathlib import Path

from airflow.sdk import DAG, task
from airflow.providers.standard.operators.empty import EmptyOperator


# Read at task execution time, so changing the control needs no DAG code edit.
# config/ is already mounted here by Docker Compose. A missing file preserves
# the failing demo by default; malformed controls fail safely instead of healing.
DEMO_CONTROL = Path("/opt/airflow/config/reliability_demo_control.json")


def simulate_failure():
    if not DEMO_CONTROL.exists():
        return True
    control = json.loads(DEMO_CONTROL.read_text(encoding="utf-8"))
    if (not isinstance(control, dict) or set(control) != {"simulate_failure"}
            or type(control["simulate_failure"]) is not bool):
        raise ValueError("Invalid synthetic demo control: expected a simulate_failure boolean.")
    return control["simulate_failure"]


# A DAG describes tasks and their dependencies. Defining it does not run it:
# the scheduler creates task runs after you trigger the DAG in the Airflow UI.
with DAG(
    dag_id="reliability_demo",
    description="Process a few numbers, then check the result.",
    start_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
    schedule=None,  # Manual runs only, so nothing starts on a timer.
    catchup=False,  # Do not create historical runs for past schedule periods.
    max_active_runs=1,
    tags=["learning", "reliability"],
) as dag:
    # EmptyOperator is a visible marker; it performs no processing.
    start = EmptyOperator(task_id="start")

    # @task turns a Python function into an Airflow task. Its body executes
    # inside a task run, not when Airflow first reads this file.
    @task
    def process_data() -> list[int]:
        """Double three sample values without external files or services."""
        # Simulate an upstream source that omitted a required field. Raise
        # inside the task so the DAG still loads and start can succeed.
        # Airflow records this exception in the task logs and marks the task
        # failed; downstream tasks cannot run with the default all_success rule.
        if simulate_failure():
            raise ValueError(
                'Source data validation failed: required source field "customer_id" '
                'is missing. Check the upstream source schema before processing.'
            )

        # With the toggle off, the original successful processing is unchanged.
        raw_data = [1, 2, 3]
        processed_data = [value * 2 for value in raw_data]
        print(f"Processed data: {processed_data}")
        # Airflow stores this small return value as an XCom so the next task
        # can receive it. XCom is for small messages, not large datasets.
        return processed_data

    @task
    def data_quality_check(values: list[int]) -> None:
        """Fail visibly if the processed sample does not meet expectations."""
        if len(values) != 3:
            raise ValueError("Expected exactly three processed values.")
        if any(not isinstance(value, int) or value <= 0 for value in values):
            raise ValueError("Every processed value must be a positive integer.")
        if values != [2, 4, 6]:
            raise ValueError(f"Unexpected processed values: {values}")
        print("Data quality check passed.")

    end = EmptyOperator(task_id="end")

    # Calling decorated functions here creates task definitions. Passing
    # processed into the check also creates the process -> check dependency.
    processed = process_data()
    checked = data_quality_check(processed)

    # >> means "must finish successfully before". The default all_success
    # rule prevents end from succeeding if the quality check fails.
    start >> processed >> checked >> end
