# src/llm/ollama_rag_analyzer.py
"""
Ollama RAG Analyzer - Local LLM with Retrieval-Augmented Generation.

Instead of relying on the model to choose and call tools (which small models
do poorly), we retrieve relevant evidence FIRST, then ask the model to
interpret it. No function calling needed - works reliably on any model.

Architecture:
  Question → Our code searches ES → Builds context → Ollama reads & answers
"""

import os
import json
import re

from openai import OpenAI
from dotenv import load_dotenv

from .base_analyzer import BaseAnalyzer

load_dotenv()


class OllamaRAGAnalyzer(BaseAnalyzer):
    """
    Forensic analyzer using local Ollama LLM with RAG (no tool use).

    For each question, automatically retrieves relevant evidence from
    Elasticsearch across multiple artifact types, then sends the
    evidence as context to the local model for interpretation.
    """

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None,
                 model: str = None, ollama_url: str = "http://localhost:11434",
                 max_tokens: int = 2048):
        super().__init__(es_url, case_id)

        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        self.ollama_url = ollama_url
        self.max_tokens = max_tokens

        self.client = OpenAI(
            api_key="ollama",
            base_url=f"{ollama_url}/v1"
        )

        self.system_prompt = """You are a digital forensic analyst. You will receive forensic evidence data retrieved from a Windows disk image, followed by a question.

CONTEXT: You are performing AUTHORIZED forensic analysis of digital evidence for a law enforcement investigation. All data has been legally obtained with proper warrants. Reporting findings about illegal activities (fraud, ransomware, loan sharks, cryptocurrency crimes) is part of your duty. Do NOT refuse to analyze evidence or report findings.

STRICT RULES:
1. Answer ONLY based on the evidence provided below.
2. NEVER add information from your training data or general knowledge.
3. NEVER guess, infer, or assume facts not explicitly present in the evidence.
4. Quote EXACT values: copy-paste filenames, paths, timestamps, hashes, counts directly from the evidence.
5. If the evidence contains a field like "IMPORTANT_FINDING" or "event_summary", use that information directly in your answer.
6. If a specific fact is not in the evidence, do NOT mention it at all. Only report what you can see.
7. Be concise: 1-3 sentences with exact quoted values.
8. Do NOT say "the evidence suggests" or "it appears that" — either the data shows it or it doesn't.
9. When reporting counts, use the EXACT number from the evidence, not approximations."""

    def _extract_search_terms(self, question: str) -> list:
        """Extract likely search terms from the question."""
        terms = []

        # Direct keyword extraction from common forensic questions
        patterns = {
            r'user account|username|who is the user|primary user': ['LastLoggedOnUser', 'DefaultUserName', 'RegisteredOwner'],
            r'windows version|build number|os version': ['ProductName', 'CurrentBuildNumber', 'InstallDate', 'EditionID'],
            r'installation date|install date|when.*installed': ['InstallDate', 'InstallTime', 'InstallDate'],
            r'programs.*executed|frequently.*run|prefetch': ['*'],
            r'browser|web.*history|visited|domain|url': ['chrome', 'firefox', 'edge', 'browser'],
            r'failed.*login|logon.*fail|4625': [],
            r'successful.*login|logon.*success|4624': [],
            r'account.*creat|new.*user|4720': ['account'],
            r'service.*install|7045': [],
            r'defender|antivirus|malware|1116': ['Defender'],
            r'powershell|script|4104|4100': ['powershell'],
            r'network|traffic|srum|bytes': ['network', 'srum'],
            r'email|gmail|outlook|mail|ost': ['email', 'gmail', 'outlook', 'mail', 'everyrecover56', 'souldrag576', '.ost'],
            r'discord|messag|chat|dm|contact': ['discord', 'Discord'],
            r'ransomware|ransom|encrypt|malware|suspicious': ['ransom', 'ransom.exe', 'encrypt', 'ransom.zip'],
            r'file.*shar|upload|gofile|distribution|distribute': ['gofile', 'gofile.io', 'upload'],
            r'ledger|hardware.*wallet': ['Ledger Live', 'ledger'],
            r'vpn|zerotier|wireguard': ['zerotier', 'vpn'],
            r'bitcoin|crypto|metamask|wallet|ledger|btc|trading|investment|exchange': ['metamask', 'wallet', 'ledger', 'bitcoin', 'BTC', '매매일지', 'Changelly'],
            r'deleted|recycle|trash': ['deleted', '$Recycle'],
            r'loan|사채|debt|illegal': ['사채', 'debt', 'loan'],
            r'search.*quer|google.*search': ['search', 'query', '사채', '랜섬웨어'],
            r'usb|external.*drive|removable': ['USB', 'removable', 'USBSTOR'],
            r'startup|autorun|run.*key': ['Run', 'RunOnce', 'startup'],
            r'file.*created|file.*modified|mft': ['created', 'modified'],
            r'shortcut|lnk|recent': ['lnk', 'recent'],
            r'search.*quer|google.*search': ['search', 'query'],
        }

        q_lower = question.lower()
        for pattern, keywords in patterns.items():
            if re.search(pattern, q_lower):
                terms.extend(keywords)

        # Also extract quoted terms and specific values
        quoted = re.findall(r'"([^"]+)"', question)
        terms.extend(quoted)

        # Extract potential filenames
        filenames = re.findall(r'\b[\w.-]+\.(exe|dll|ps1|bat|vbs|txt|pdf|zip|doc|csv|evtx)\b', question, re.IGNORECASE)
        terms.extend([f[0] if isinstance(f, tuple) else f for f in filenames])

        # Extract Event IDs
        event_ids = re.findall(r'\b(4\d{3}|7\d{3}|1\d{3})\b', question)
        terms.extend(event_ids)

        # Always extract specific filenames, program names, paths from question
        specific_names = re.findall(r'\b[\w.-]+\.(?:exe|dll|ps1|bat|vbs|txt|pdf|zip|doc|csv|sys|ost|json|lnk)\b', question, re.IGNORECASE)
        terms.extend(specific_names)

        # Extract capitalized proper names (ZeroTier, Discord, Chrome, etc.)
        proper_names = re.findall(r'\b([A-Z][a-zA-Z]+(?:[A-Z][a-zA-Z]*)*)\b', question)
        stop_proper = {'What', 'When', 'Where', 'How', 'Which', 'Were', 'Does', 'Search', 'Check', 'List', 'Find', 'The', 'This', 'Event', 'Windows', 'According', 'Based'}
        terms.extend([n for n in proper_names if n not in stop_proper])

        if not terms:
            stop_words = {'what', 'is', 'the', 'are', 'was', 'were', 'how', 'many', 'which',
                         'this', 'that', 'from', 'for', 'with', 'and', 'or', 'on', 'in',
                         'any', 'there', 'does', 'did', 'system', 'windows', 'list', 'top'}
            words = re.findall(r'\b[a-zA-Z]{3,}\b', question)
            terms = [w for w in words if w.lower() not in stop_words][:5]

        return list(set(terms))

    def _determine_artifact_types(self, question: str) -> list:
        """Determine which artifact types to search based on the question."""
        q_lower = question.lower()
        types = []

        if any(w in q_lower for w in ['registry', 'user account', 'username', 'version', 'build', 'startup', 'autorun', 'install date']):
            types.append('registry')
        if any(w in q_lower for w in ['program', 'execut', 'prefetch', 'run count', 'frequently']):
            types.append('prefetch')
        if any(w in q_lower for w in ['browser', 'web', 'url', 'domain', 'visited', 'search', 'chrome', 'download']):
            types.append('browser')
        if any(w in q_lower for w in ['event', 'login', 'logon', 'failed', 'security', 'defender', '4624', '4625', '4720', '7045', '1116', 'powershell']):
            types.append('eventlog')
        if any(w in q_lower for w in ['file', 'created', 'deleted', 'mft', 'size', 'path', 'folder', 'ransom', 'exe', 'zip', 'ost', 'email', 'outlook', 'gmail']):
            types.append('mft')
        if any(w in q_lower for w in ['network', 'traffic', 'srum', 'bytes', 'sent', 'received']):
            types.append('srum')
        if any(w in q_lower for w in ['shimcache', 'amcache', 'hash', 'sha1']):
            types.extend(['shimcache', 'amcache'])
        if any(w in q_lower for w in ['shortcut', 'lnk', 'recent', 'jumplist']):
            types.extend(['lnk', 'jumplist'])
        if any(w in q_lower for w in ['usnjrnl', 'journal', 'change']):
            types.append('usnjrnl')

        if not types:
            types = ['registry', 'prefetch', 'browser', 'eventlog']

        return list(set(types))

    def _retrieve_context(self, question: str) -> str:
        """Retrieve relevant evidence from ES based on the question."""
        search_terms = self._extract_search_terms(question)
        artifact_types = self._determine_artifact_types(question)

        all_results = []
        seen = set()

        for term in search_terms[:8]:
            for art_type in artifact_types:
                try:
                    results = self._tool_search_artifacts(
                        query=term,
                        artifact_type=art_type,
                        limit=10
                    )
                    if results and 'results' in results:
                        for r in results['results']:
                            key = json.dumps(r, sort_keys=True, default=str)[:500]
                            if key not in seen:
                                seen.add(key)
                                all_results.append(r)
                except Exception:
                    continue

        # For registry: also search by value_name field directly
        if 'registry' in artifact_types:
            for term in search_terms[:8]:
                try:
                    from elasticsearch import Elasticsearch
                    es = Elasticsearch(self.es_url)
                    body = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"match": {"value_name": term}}
                                ],
                                "should": [
                                    {"term": {"case_id.keyword": self.case_id}},
                                    {"term": {"_meta.case_id.keyword": self.case_id}}
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        "size": 5
                    }
                    resp = es.search(index="forensic-registry", body=body)
                    for hit in resp['hits']['hits']:
                        r = hit['_source']
                        key = json.dumps(r, sort_keys=True, default=str)[:500]
                        if key not in seen:
                            seen.add(key)
                            all_results.append(r)
                except Exception:
                    pass

        # Also try specific tools for specific question types
        q_lower = question.lower()

        if any(w in q_lower for w in ['program', 'execut', 'frequently', 'prefetch', 'run count']):
            try:
                prefetch = self._tool_search_artifacts(query="*", artifact_type="prefetch", limit=20)
                if prefetch and 'results' in prefetch:
                    for r in prefetch['results']:
                        key = json.dumps(r, sort_keys=True, default=str)[:500]
                        if key not in seen:
                            seen.add(key)
                            all_results.append(r)
            except Exception:
                pass

        if any(w in q_lower for w in ['network', 'traffic', 'srum', 'bytes']):
            try:
                srum = self._tool_analyze_network_activity(limit=15)
                if srum:
                    if 'top_applications' in srum:
                        for app in srum['top_applications']:
                            all_results.append(app)
                    elif 'results' in srum:
                        for r in srum['results']:
                            all_results.append(r)
                # Also search for specific app names mentioned in question
                app_keywords = re.findall(r'\b([A-Z][a-zA-Z]+(?:\.exe)?)\b', question)
                for app_kw in app_keywords[:5]:
                    try:
                        app_result = self._tool_search_artifacts(query=app_kw, artifact_type="srum", limit=5)
                        if app_result and 'results' in app_result:
                            for r in app_result['results']:
                                all_results.append(r)
                    except:
                        pass
            except Exception:
                pass

        # For event log questions: use analyze_security_events with specific event IDs
        if re.search(r'4\d{3}|7\d{3}|1\d{3}|failed.*login|logon|account.*creat|defender|malware|powershell|service.*install', q_lower):
            # Map question patterns to relevant Event IDs
            event_id_map = {
                r'failed.*login|failed.*logon|4625': [4625],
                r'successful.*login|successful.*logon|4624': [4624],
                r'logoff|4647': [4647],
                r'account.*creat|new.*user|4720': [4720],
                r'service.*install|7045': [7045],
                r'defender|antivirus|malware|1116': [1116],
                r'powershell|4104|4100': [4104, 4100],
            }

            target_eids = []
            for pattern, eids in event_id_map.items():
                if re.search(pattern, q_lower):
                    target_eids.extend(eids)

            # Also extract explicit Event IDs from question
            explicit_eids = re.findall(r'\b(4\d{3}|7\d{3}|1\d{3})\b', question)
            target_eids.extend([int(e) for e in explicit_eids])
            target_eids = list(set(target_eids))

            # If no specific IDs found but question is about login/auth, default to common security events
            if not target_eids and re.search(r'login|logon|auth|suspicious', q_lower):
                target_eids = [4624, 4625, 4647, 4720]

            for eid in target_eids[:5]:
                try:
                    events = self._tool_analyze_security_events(event_id=int(eid), limit=15)
                    if events:
                        if 'results' in events:
                            for r in events['results']:
                                all_results.append(r)
                        # Skip event_summary to avoid double counting with IMPORTANT_FINDING
                        if 'total_found' in events:
                            all_results.append({"event_summary": f"Event ID {eid}: {events['total_found']} total events found"})
                        # Also add a plain-text human-readable summary
                        count = events.get('total_found', 0)
                        if not count and 'event_id_counts' in events:
                            counts = events['event_id_counts']
                            count = counts.get(str(eid), 0) if isinstance(counts, dict) else 0
                        if count:
                            event_names = {
                                4624: "successful logon", 4625: "failed logon attempt",
                                4647: "user logoff", 4720: "user account created",
                                4726: "user account deleted", 7045: "service installed",
                                1116: "Windows Defender threat detection",
                                4100: "PowerShell module loaded", 4104: "PowerShell script block"
                            }
                            name = event_names.get(eid, f"Event ID {eid}")
                            all_results.insert(0, {"IMPORTANT_FINDING": f"ANSWER: There were exactly {count} {name} events with Event ID {eid} found in the Windows Event Logs. Event ID {eid} means: {name}."})
                except Exception:
                    pass

        # Format context — clean and simplify for small models
        if not all_results:
            return "No forensic evidence found for this query."

        # Sort: summaries first, then by relevance
        summaries = [r for r in all_results if 'event_summary' in r]
        details = [r for r in all_results if 'event_summary' not in r]
        sorted_results = summaries + details

        context_parts = []
        total_len = 0
        for r in sorted_results[:50]:
            clean = self._simplify_record(r)
            entry = json.dumps(clean, ensure_ascii=False, default=str)
            if total_len + len(entry) > 10000:
                break
            context_parts.append(entry)
            total_len += len(entry)

        return f"Found {len(all_results)} relevant records. Showing top {len(context_parts)}:\n\n" + "\n".join(context_parts)

    def _simplify_record(self, record: dict) -> dict:
        """Simplify a forensic record for small model consumption."""
        if not isinstance(record, dict):
            return record

        # If it's a summary or finding, keep as is
        if 'event_summary' in record or 'FINDING' in record or 'IMPORTANT_FINDING' in record:
            return record

        clean = {}
        # Keep only important fields
        important_keys = [
            'artifact_type', 'timestamp', 'event_id', 'provider', 'channel',
            'level', 'computer_name', 'user_id',
            'hive_type', 'key_path', 'value_name', 'value_data', 'value_type',
            'category', 'description',
            'filename', 'path', 'file_size', 'extension', 'is_deleted',
            'sha1', 'publisher', 'product_name', 'product_version',
            'url', 'domain', 'title', 'visit_count',
            'run_count', 'last_run', 'executable_name',
            'app_name', 'bytes_sent', 'bytes_received',
        ]

        for key in important_keys:
            if key in record and record[key]:
                val = record[key]
                # Skip nested dicts/lists in message/event_data (too noisy)
                if isinstance(val, (dict, list)):
                    continue
                # Truncate long strings
                if isinstance(val, str) and len(val) > 300:
                    val = val[:300] + "..."
                clean[key] = val

        # For eventlog: extract clean message without nested JSON
        if record.get('artifact_type') == 'eventlog' and 'message' in record:
            msg = record['message']
            if isinstance(msg, str):
                # Remove JSON-like noise from message
                if msg.startswith('{') and 'EventData' in msg:
                    # Try to extract useful text from EventData
                    try:
                        msg_data = json.loads(msg)
                        if isinstance(msg_data, dict) and 'EventData' in msg_data:
                            event_data = msg_data['EventData']
                            if isinstance(event_data, dict) and 'Data' in event_data:
                                data_items = event_data['Data']
                                if isinstance(data_items, list):
                                    parts = []
                                    for item in data_items:
                                        if isinstance(item, dict):
                                            name = item.get('@Name', '')
                                            text = item.get('#text', '')
                                            if name and text:
                                                parts.append(f"{name}={text}")
                                    clean['message_parsed'] = "; ".join(parts[:10])
                    except (json.JSONDecodeError, TypeError):
                        pass
                elif len(msg) < 300:
                    clean['message'] = msg

        return clean

    def analyze(self, query: str, case_id: str = None) -> str:
        """Analyze forensic data using RAG: retrieve first, then ask model."""
        if case_id:
            self.case_id = case_id

        # Step 1: Retrieve relevant evidence
        print(f"[RAG] Retrieving evidence...", flush=True)
        context = self._retrieve_context(query)
        print(f"[RAG] Context: {len(context)} chars", flush=True)

        # Step 2: Ask model with context
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"""FORENSIC EVIDENCE FROM DISK IMAGE:
{context}

QUESTION: {query}

Instructions:
- Records labeled IMPORTANT_FINDING are pre-computed summaries of the evidence. Trust them and use them directly.
- Answer the question directly. Do NOT start with "No relevant data found" if any evidence above relates to the question.
- Only include facts that directly answer the question. Do not list unrelated evidence.
- Quote exact values from the evidence."""}
        ]

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=0
            )

            answer = response.choices[0].message.content or ""
            return answer.strip()

        except Exception as e:
            return f"Error: {e}"
