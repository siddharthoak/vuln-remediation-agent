FROM python:3.11-slim

WORKDIR /app

COPY agents/watcher/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# pr_client.py is shared between fixer and watcher; watcher never touches git directly.
COPY agents/fixer/pr_client.py /app/pr_client.py
COPY agents/common/ /app/common/
COPY agents/watcher/ /app/

CMD ["python", "main.py"]
