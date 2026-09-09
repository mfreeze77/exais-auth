FROM python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN --network=none --mount=type=bind,from=python_wheels,target=/wheels \
    pip install --no-index --find-links=/wheels --no-cache-dir --no-compile --require-hashes --only-binary=:all: -r /app/requirements.lock \
    && pip check
COPY app.py /app/app.py
USER 65532:65532
EXPOSE 8300
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8300", "--no-access-log"]
