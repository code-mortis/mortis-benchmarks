FROM python:3.13-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962
COPY requirements.txt /evaluation-requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /evaluation-requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["python", "-I", "/evaluation/evaluate.py"]
