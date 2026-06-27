---
name: knowledge-base
description: "Searchable vulnerability knowledge base with disclosed reports, payloads, bypass techniques, and references. Serves as a learning resource and reference during hunting."
---

# Vulnerability Knowledge Base

Centralized repository for:
- Disclosed bug bounty reports (from HackerOne, Bugcrowd, etc.)
- Payload collections and bypass techniques
- Methodology references
- CVE details and exploit PoCs
- Training data for LLM fine-tuning

## Usage

### Via Dashboard
Open http://127.0.0.1:5000/knowledge-base
- Browse by bug class
- Search by keyword, tag, or content
- Add entries manually

### Via API
```bash
# Search knowledge base
curl http://127.0.0.1:5000/api/knowledge-base?q=xss+bypass

# Filter by class
curl http://127.0.0.1:5000/api/knowledge-base?class=ssrf

# All entries
curl http://127.0.0.1:5000/api/knowledge-base
```

### Via CLI (database direct)
```bash
# Search for SSRF payloads
python3 -c "
from dashboard.database import search_knowledge_base
for e in search_knowledge_base(search='ssrf'):
    print(f\"{e['title']} ({e['bug_class']})\")
"

# Add from disclosed report
python3 -c "
from dashboard.database import add_to_knowledge_base
add_to_knowledge_base(
    title='SSRF via PDF generator',
    bug_class='ssrf',
    severity='high',
    source='HackerOne #12345',
    content='... full details ...',
    payloads=['file:///etc/passwd', 'http://169.254.169.254/'],
    techniques=['OOB detection via Burp Collaborator'],
    tags='ssrf,oob,cloud-metadata,pdf'
)
"
```

### AI Training Data Export
```bash
# Export KB + findings as OpenAI-compatible training data
python3 tools/ai_training_data.py --format openai --output training.jsonl

# Show available data stats
python3 tools/ai_training_data.py --stats
```

## Adding Entries

KB entries should include:
- Title (descriptive)
- Bug class (xss, ssrf, sqli, etc.)
- Severity (if applicable)
- Source (where it came from)
- Full content/methodology
- Payloads (JSON array)
- Techniques (JSON array)
- Tags (comma-separated keywords for search)
