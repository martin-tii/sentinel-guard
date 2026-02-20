FROM openpolicyagent/opa:latest AS opa-bin

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/tmp/huggingface \
    TRANSFORMERS_CACHE=/tmp/huggingface/transformers

RUN useradd --create-home --shell /usr/sbin/nologin sentinel

WORKDIR /opt/sentinel

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY --from=opa-bin /opa /usr/local/bin/opa

RUN pip install --no-cache-dir -e ".[prompt-guard]" "torch>=2.4.0,<3.0.0"

RUN chown -R sentinel:sentinel /opt/sentinel
USER sentinel

ENTRYPOINT ["/opt/sentinel/scripts/entrypoint.sh"]
CMD ["python", "/opt/sentinel/tests/verify_fixes.py"]
