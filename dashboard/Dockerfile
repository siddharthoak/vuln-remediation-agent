# Single-stage: server-rendered (Jinja2 + HTMX), no JS build step at all --
# no Node, no npm install, no frontend/ directory. See dashboard/backend/app.py
# for why (build-time cost vs. the earlier React version).
FROM python:3.11-slim
WORKDIR /app

COPY dashboard/backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# common/ is the same tracking_store.py / knowledge_store.py the other agents use
COPY agents/common/ /app/agents/common/
COPY dashboard/backend/ /app/dashboard/backend/

WORKDIR /app/dashboard/backend
EXPOSE 8000
CMD ["uvicorn", "app:app", "--app-dir", "/app/dashboard/backend", "--host", "0.0.0.0", "--port", "8000"]
