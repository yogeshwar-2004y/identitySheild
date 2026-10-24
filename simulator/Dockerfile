FROM python:3.12-slim
WORKDIR /app
COPY simulator/requirements.txt /app/simulator/requirements.txt
RUN pip install --no-cache-dir -r /app/simulator/requirements.txt && useradd -m -u 10001 sim
COPY simulator/ /app/simulator/
USER sim
ENTRYPOINT ["python", "-m", "simulator"]
