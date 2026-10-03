from datetime import datetime, timedelta

from airflow import DAG
from airflow.providers.common.sql.sensors.sql import SqlSensor
from airflow.providers.common.sql.operators.sql import SQLExecuteQueryOperator
from airflow.providers.standard.operators.python import PythonOperator


default_args = {
    "owner": "data_engineering",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
    "on_failure_callback": task_failure_alert,
}
def validate_reconciliation(**context):
    ti = context["ti"]

    source_metrics = ti.xcom_pull(
        task_ids="get_expected_metrics"
    )

    target_metrics = ti.xcom_pull(
        task_ids="get_target_metrics"
    )

    source_count = source_metrics[0][0]
    source_amount = float(source_metrics[0][1])

    target_count = target_metrics[0][0]
    target_amount = float(target_metrics[0][1])

    print(f"Expected count: {source_count}")
    print(f"Target count: {target_count}")
    print(f"Expected amount: {source_amount}")
    print(f"Target amount: {target_amount}")

    if source_count != target_count:
        raise ValueError(
            f"Record count mismatch: expected {source_count}, got {target_count}"
        )

    if source_amount != target_amount:
        raise ValueError(
            f"Amount mismatch: expected {source_amount}, got {target_amount}"
        )

    print("Reconciliation passed")

def task_failure_alert(context):
    task_instance = context["task_instance"]
    exception = context.get("exception")

    print("PIPELINE FAILURE ALERT")
    print(f"DAG: {task_instance.dag_id}")
    print(f"Task: {task_instance.task_id}")
    print(f"Run ID: {task_instance.run_id}")
    print(f"Error: {exception}")

with DAG(
    dag_id="daily_transaction_reconciliation",
    description="Automates daily transaction processing and reconciliation",
    start_date=datetime(2026, 10, 1),
    schedule="0 7 * * *",
    catchup=False,
    default_args=default_args,
    max_active_runs=1,
    tags=["transactions", "reconciliation"],
) as dag:

    # Task 1: Wait for new or updated source data after the last watermark
    check_source = SqlSensor(
    task_id="check_source",
    conn_id="transactions_db",
    sql="""
        SELECT COUNT(*)
        FROM raw_transactions
        WHERE updated_at > (
            SELECT last_processed_at
            FROM pipeline_watermark
            WHERE pipeline_name = 'daily_transaction_reconciliation'
        );
    """,
    poke_interval=300,
    timeout=1800,
    mode="reschedule",
)

    # Task 2: Apply business rules and deduplicate
    transform_and_dedupe = SQLExecuteQueryOperator(
    task_id="transform_and_dedupe",
    conn_id="transactions_db",
    pool="postgres_etl_pool",
    execution_timeout=timedelta(minutes=30),
    sql="""
        DROP TABLE IF EXISTS cleaned_transactions;

        CREATE TABLE cleaned_transactions AS
        WITH ranked AS (
            SELECT *,
                   ROW_NUMBER() OVER (
                       PARTITION BY transaction_id
                       ORDER BY updated_at DESC
                   ) AS rn
            FROM raw_transactions
            WHERE updated_at > (
                SELECT last_processed_at
                FROM pipeline_watermark
                WHERE pipeline_name = 'daily_transaction_reconciliation'
            )
              AND status = 'COMPLETED'
              AND amount IS NOT NULL
              AND customer_id NOT LIKE 'TEST%'
        )
        SELECT
            transaction_id,
            customer_id,
            amount,
            status,
            transaction_date,
            updated_at
        FROM ranked
        WHERE rn = 1;
    """,
)

    # Task 3: Calculate expected metrics
    get_expected_metrics = SQLExecuteQueryOperator(
        task_id="get_expected_metrics",
        conn_id="transactions_db",
        sql="""
            SELECT
                COUNT(*) AS record_count,
                COALESCE(SUM(amount), 0) AS total_amount
            FROM cleaned_transactions;
        """,
        do_xcom_push=True,
    )
    # Task 4: Load cleaned data into target
    load_target = SQLExecuteQueryOperator(
        task_id="load_target",
        conn_id="transactions_db",
        sql="""
            INSERT INTO reporting_transactions (
                transaction_id,
                customer_id,
                amount,
                status,
                transaction_date,
                updated_at
            )
            SELECT
                transaction_id,
                customer_id,
                amount,
                status,
                transaction_date,
                updated_at
            FROM cleaned_transactions

            ON CONFLICT (transaction_id)
            DO UPDATE SET
                customer_id = EXCLUDED.customer_id,
                amount = EXCLUDED.amount,
                status = EXCLUDED.status,
                transaction_date = EXCLUDED.transaction_date,
                updated_at = EXCLUDED.updated_at;
        """,
    )
    
    # Task 5: Calculate actual target metrics
    get_target_metrics = SQLExecuteQueryOperator(
    task_id="get_target_metrics",
    conn_id="transactions_db",
    sql="""
        SELECT
            COUNT(*) AS record_count,
            COALESCE(SUM(r.amount), 0) AS total_amount
        FROM reporting_transactions r
        JOIN cleaned_transactions c
            ON r.transaction_id = c.transaction_id;
    """,
    do_xcom_push=True,
)
    # Task 6: Reconcile expected vs actual target metrics
    validate_reconciliation_task = PythonOperator(
    task_id="validate_reconciliation",
    python_callable=validate_reconciliation,
    retries=0,
)
    # Task 7: Update watermark after successful reconciliation
    update_watermark = SQLExecuteQueryOperator(
    task_id="update_watermark",
    conn_id="transactions_db",
    sql="""
        UPDATE pipeline_watermark
        SET last_processed_at = (
            SELECT MAX(updated_at)
            FROM cleaned_transactions
        )
        WHERE pipeline_name = 'daily_transaction_reconciliation';
    """,
)

    check_source >> transform_and_dedupe >> get_expected_metrics >> load_target >> get_target_metrics >> validate_reconciliation_task >> update_watermark