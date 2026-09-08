import json

entries = [
    {
        "entry_id": "log4j-1-to-reload4j",
        "component_name": "log4j:log4j",
        "from_version": "1.2.17",
        "to_version": "UNKNOWN",
        "from_major": -1,
        "to_major": -1,
        "source": "knowledge_agent",
        "breaking_changes": [],
        "api_removals": [],
        "migration_steps": [],
        "patterns": [
            {
                "find": "<groupId>log4j</groupId>\\s*<artifactId>log4j</artifactId>",
                "replace": "<groupId>ch.qos.reload4j</groupId>\\n      <artifactId>reload4j</artifactId>",
                "description": "Replace log4j with reload4j"
            }
        ],
        "confidence": "high",
        "created_at": "2026-09-07T00:00:00Z"
    },
    {
        "entry_id": "log4j-core-2171",
        "component_name": "org.apache.logging.log4j:log4j-core",
        "from_version": "2.14.1",
        "to_version": "2.17.1",
        "from_major": -1,
        "to_major": -1,
        "source": "knowledge_agent",
        "breaking_changes": [],
        "api_removals": [],
        "migration_steps": [],
        "patterns": [],
        "confidence": "high",
        "created_at": "2026-09-07T00:00:00Z"
    },
    {
        "entry_id": "commons-io-2140",
        "component_name": "commons-io:commons-io",
        "from_version": "2.2",
        "to_version": "2.14.0",
        "from_major": -1,
        "to_major": -1,
        "source": "knowledge_agent",
        "breaking_changes": [],
        "api_removals": [],
        "migration_steps": [],
        "patterns": [],
        "confidence": "high",
        "created_at": "2026-09-07T00:00:00Z"
    },
    {
        "entry_id": "xwork-core-2337",
        "component_name": "org.apache.struts.xwork:xwork-core",
        "from_version": "2.3.30",
        "to_version": "2.3.37",
        "from_major": -1,
        "to_major": -1,
        "source": "knowledge_agent",
        "breaking_changes": [],
        "api_removals": [],
        "migration_steps": [],
        "patterns": [],
        "confidence": "high",
        "created_at": "2026-09-07T00:00:00Z"
    }
]

with open('data/kb.json', 'w') as f:
    json.dump({"entries": entries}, f, indent=2)
