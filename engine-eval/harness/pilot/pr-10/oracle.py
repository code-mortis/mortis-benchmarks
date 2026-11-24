import tomllib


def check(files):
    config = tomllib.loads(files["deploy/staging.toml"])
    worker = config["worker"]
    http = config["http"]
    docs = files["README.md"]
    return (
        type(worker["concurrency"]) is int
        and worker["concurrency"] == 4
        and worker["maximum_pending"] == 128
        and worker["retry_delays_seconds"] == [1, 3, 9]
        and worker["timeout_seconds"] == 45
        and worker["drain_seconds"] == 60
        and http["bind_host"] == "127.0.0.1"
        and http["port"] == 8095
        and http["health_path"] == "/health"
        and config["logging"]["include_payloads"] is False
        and config["logging"]["format"] == "json"
        and "**4 concurrent tasks**" in docs
        and "**2 concurrent tasks**" not in docs
        and "http://127.0.0.1:8095/health" in docs
    )
