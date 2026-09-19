# Single-stage: server-rendered (Jinja2 + HTMX), no JS build step at all --
# no Node, no npm install, no frontend/ directory. See dashboard/backend/app.py
# for why (build-time cost vs. the earlier React version).
FROM python:3.11-slim
WORKDIR /app

COPY dashboard/backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# common/ is the same tracking_store.py / knowledge_store.py the other agents use.
# playbooks/ is needed too -- knowledge_store.py merges tier2_playbook entries
# fresh on every read (not persisted to kb.json), so without this the
# dashboard's KB tab would silently never show any tier2_playbook entries,
# no matter how correct PLAYBOOKS_DIR's path resolution is.
COPY agents/common/ /app/agents/common/
COPY playbooks/ /app/playbooks/
COPY dashboard/backend/ /app/dashboard/backend/

WORKDIR /app/dashboard/backend
EXPOSE 8000
CMD ["uvicorn", "app:app", "--app-dir", "/app/dashboard/backend", "--host", "0.0.0.0", "--port", "8000"]
