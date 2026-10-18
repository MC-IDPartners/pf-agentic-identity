FROM ghcr.io/spiffe/spire-agent:1.9.0 AS spire

FROM python:3.12-slim
WORKDIR /app
COPY --from=spire /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workload.py federation.py entity_host.py fedresolve.py rs_accounts.py agent.py probe.py sub_agent.py principals.py ./
CMD ["python", "workload.py"]