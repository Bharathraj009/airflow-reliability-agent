# Airflow Reliability Agent — Phase 1

A local Apache Airflow learning environment. Phase 1 contains only Airflow,
PostgreSQL, and one small demo DAG. Airflow runs entirely inside Docker; do not
install it in your Windows Python environment.

## Prerequisites

- Start Docker Desktop with Linux containers (the WSL 2 backend is recommended).
- Give Docker at least 4 GB of memory; 8 GB is preferable.
- Use Docker Compose v2.14 or newer, included with Docker Desktop.
- Run the commands below in PowerShell from this project directory.

## Configuration

`docker-compose.yaml` pins the official `apache/airflow:3.1.7` image and uses
PostgreSQL 16. `LocalExecutor` runs tasks inside the scheduler container, with
parallelism limited to two tasks for this small environment. The API server
provides Airflow's built-in UI, and the DAG processor reads Python DAG files.
The one-shot init service migrates the database and creates the admin account.

All Airflow services mount these project folders:

| Local folder | Container folder | Purpose |
| --- | --- | --- |
| `dags/` | `/opt/airflow/dags` | DAG source files |
| `logs/` | `/opt/airflow/logs` | Task and service logs |
| `plugins/` | `/opt/airflow/plugins` | Future Airflow plugins |
| `config/` | `/opt/airflow/config` | Local Airflow configuration |

Settings are supplied through environment variables. Airflow may generate
`config/airflow.cfg`; it is ignored by Git. PostgreSQL stores metadata in the
`postgres-data` Docker volume, so ordinary shutdowns preserve run history.

The local `.env` has already been created with random database/encryption/signing
secrets and the learning-only UI login `airflow` / `airflow`. It is ignored by Git.
The UI uses host port `8090`, and PostgreSQL has no published host port.
This is a local learning setup, not a production deployment.

For a fresh clone where `.env` is absent, create it using this PowerShell block
**once**. Do not overwrite an existing `.env`: changing its database password or
encryption key can break access to existing data.

```powershell
if (Test-Path .env) { throw '.env already exists; keep your existing secrets.' }
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function New-LocalSecret {
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_')
}
$lines = @(
    'AIRFLOW_UID=50000'
    'AIRFLOW_ADMIN_USERNAME=airflow'
    'AIRFLOW_ADMIN_PASSWORD=airflow'
    ('POSTGRES_PASSWORD=' + (New-LocalSecret))
    ('AIRFLOW_FERNET_KEY=' + (New-LocalSecret))
    ('AIRFLOW_JWT_SECRET=' + (New-LocalSecret))
    ('AIRFLOW_API_SECRET_KEY=' + (New-LocalSecret))
)
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'), $lines)
$rng.Dispose()
```

`AIRFLOW_UID=50000` is appropriate for Docker Desktop on Windows; no Linux
`id`, `chmod`, or host Python installation is required.

## First start

From this project directory, initialize the database and admin account:

```powershell
docker compose up airflow-init
```

The first run downloads the images and can take several minutes. Wait for
`airflow-init` to exit with code **0**, then start the remaining services:

```powershell
docker compose up -d
docker compose ps
```

Wait until the running services are healthy, then open
<http://localhost:8090> and sign in with **airflow / airflow** (or the credentials
you set in `.env` before initialization). An exited init container is expected.
Changing `.env` later does not reset an existing UI user's password.

## Run the demo

Allow a minute for `reliability_demo` to appear in the DAG list. Enable/unpause it,
then use **Trigger DAG**. There is no automatic schedule.

```text
start -> process_data -> data_quality_check -> end
```

- `start`: marks the beginning without doing work.
- `process_data`: doubles `[1, 2, 3]` into `[2, 4, 6]` and logs the result.
- `data_quality_check`: receives the small result through Airflow XCom and
  checks its length, positive integer values, and expected contents.
- `end`: succeeds only after the preceding tasks succeed.

Open the run in the UI to inspect task states and logs. A failed check raises
`ValueError`, which marks the task failed and prevents `end` from succeeding.
The DAG file is heavily commented to explain these concepts.

## Stop and restart

Stop and remove containers while keeping metadata and local files:

```powershell
docker compose down
```

Start again:

```powershell
docker compose up -d
```

Optional full metadata reset — **deletes all Airflow run history, users,
connections, and other metadata stored in PostgreSQL**. Local DAGs and logs remain:

```powershell
docker compose down --volumes
docker compose up airflow-init
docker compose up -d
```

## Troubleshooting and verification

Validate Compose configuration without displaying secrets:

```powershell
docker compose config --quiet
```

Inspect service status, startup logs, and DAG import errors:

```powershell
docker compose ps -a
docker compose logs --tail=100 airflow-init airflow-api-server airflow-scheduler airflow-dag-processor
docker compose exec airflow-scheduler airflow dags list-import-errors
```

If Docker cannot connect, start Docker Desktop and wait for its engine. If port
8090 is occupied, stop the conflicting application or choose another host port
in `8090:8080` and use that host port in the browser. Keep the internal port at 8080.
If bind mounts fail, check Docker Desktop's access to this project directory.

This setup adapts the [official Airflow Docker guide](https://airflow.apache.org/docs/apache-airflow/3.1.7/howto/docker-compose/index.html)
to LocalExecutor for a smaller local environment.
