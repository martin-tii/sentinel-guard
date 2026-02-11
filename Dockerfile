FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /usr/sbin/nologin sentinel

WORKDIR /opt/sentinel

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R sentinel:sentinel /opt/sentinel
USER sentinel

ENTRYPOINT ["/opt/sentinel/scripts/entrypoint.sh"]
CMD ["python", "/opt/sentinel/tests/verify_fixes.py"]
