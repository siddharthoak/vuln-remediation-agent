import sys

with open('agents/knowledge/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

if "import concurrent.futures" not in content:
    content = content.replace("import json\n", "import json\nimport concurrent.futures\n")

replacement = """        try:
            def _call_model():
                return self._model.generate_content(
                    prompt,
                    generation_config={"response_mime_type": "application/json", "temperature": 0.0},
                )
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(_call_model)
                response = future.result(timeout=45)
            data = json.loads(response.text)"""

content = content.replace("""        try:
            response = self._model.generate_content(
                prompt,
                generation_config={"response_mime_type": "application/json", "temperature": 0.0},
            )
            data = json.loads(response.text)""", replacement)

with open('agents/knowledge/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
