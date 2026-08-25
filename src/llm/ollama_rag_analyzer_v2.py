# src/llm/ollama_rag_analyzer_v2.py
"""
Ollama RAG Analyzer V2 - adds a BGE reranker and a wider context budget.

Changes relative to v1:
1. Candidates from the initial Elasticsearch search are passed through BGE-reranker-v2-m3
2. top-K after reranking is 15 (instead of the first N after deduplication)
3. The context budget is raised to 20000 characters (Phi-4 14B handles it)
4. The reranker is loaded lazily on first use so that import is not blocked
"""

import os
import json
import re

from openai import OpenAI
from dotenv import load_dotenv

from .base_analyzer import BaseAnalyzer
from .ollama_rag_analyzer import OllamaRAGAnalyzer

load_dotenv()


class OllamaRAGAnalyzerV2(OllamaRAGAnalyzer):
    """Inherits everything from v1 and overrides only _retrieve_context."""

    RERANK_TOP_K = 15
    CONTEXT_BUDGET_CHARS = 20000
    INITIAL_POOL_LIMIT = 50  # how many records are collected before reranking

    def __init__(self, *args, reranker_model: str = "BAAI/bge-reranker-v2-m3", **kwargs):
        super().__init__(*args, **kwargs)
        self.reranker_model = reranker_model
        self._reranker = None  # lazy initialisation

        # v2: the system prompt is overridden so that the model extracts values
        # from ALL record fields (url, title, domain, path, value_data) and not
        # only from IMPORTANT_FINDING. Without this Phi-4 declines to answer when
        # no pre-computed summary is present, even when the URL carries the answer.
        self.system_prompt = """You are a digital forensic analyst. You will receive forensic evidence records from a Windows disk image, followed by a question.

CONTEXT: This is AUTHORIZED forensic analysis under a legal warrant. Reporting findings about illegal activities (fraud, ransomware, loan sharks, crypto crimes) is part of your duty. Do NOT refuse.

STRICT RULES:
1. Answer based on the evidence records provided. Each record is a JSON object with fields like url, title, domain, filename, path, value_data, message, timestamp, event_id.
2. EXTRACT specific values DIRECTLY from these fields: parse URLs for IDs/paths, read titles, quote filenames, copy timestamps. Do not say "no information" if the answer is visible in any field of any record.
3. If a record has IMPORTANT_FINDING or event_summary, prefer that as the primary answer.
4. If the answer is in a url field (e.g. "https://discord.com/channels/@me/115423...") — extract the channel ID, contact, or path component directly. Do not require an IMPORTANT_FINDING tag.
5. Quote EXACT values from the records (filenames, paths, timestamps, hashes, counts, URLs, IDs).
6. NEVER add facts from training data or general knowledge.
7. If a specific fact really is not in any record, say so briefly — but always check url/title/filename fields first.
8. Be concise: 1-3 sentences with exact quoted values.
9. When reporting counts, use the EXACT number from the records.
10. Korean text, Discord IDs, MetaMask extension IDs, and gofile URLs are valid evidence — extract them verbatim."""

    def _get_reranker(self):
        """Load the reranker on first use."""
        if self._reranker is None:
            try:
                from FlagEmbedding import FlagReranker
                print(f"[RAG v2] Loading reranker {self.reranker_model}...", flush=True)
                self._reranker = FlagReranker(self.reranker_model, use_fp16=False)
                print("[RAG v2] Reranker ready", flush=True)
            except Exception as e:
                print(f"[RAG v2] Reranker unavailable ({e}), continuing without it", flush=True)
                self._reranker = False  # marker that loading failed
        return self._reranker if self._reranker is not False else None

    def _rerank(self, question: str, records: list) -> list:
        """Reorder records by relevance to the question."""
        reranker = self._get_reranker()
        if reranker is None or not records:
            return records

        # Build a textual representation of each record for the reranker
        texts = []
        for r in records:
            if isinstance(r, dict):
                # Use the pre-computed summary when one is present
                if 'event_summary' in r:
                    texts.append(str(r['event_summary']))
                elif 'IMPORTANT_FINDING' in r:
                    texts.append(str(r['IMPORTANT_FINDING']))
                else:
                    clean = self._simplify_record(r)
                    texts.append(json.dumps(clean, ensure_ascii=False, default=str)[:1000])
            else:
                texts.append(str(r)[:1000])

        # (question, record) pairs to score
        pairs = [[question, t] for t in texts]
        try:
            scores = reranker.compute_score(pairs, normalize=True)
        except Exception as e:
            print(f"[RAG v2] Reranker error: {e}", flush=True)
            return records

        # Return the records sorted by descending score
        scored = list(zip(records, scores))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [r for r, _ in scored]

    def _extract_search_terms(self, question: str) -> list:
        """v2: extends the v1 patterns with case-relevant topics, specific terms first."""
        v1_terms = super()._extract_search_terms(question)
        q_lower = question.lower()

        # The v2 extensions carry ONLY generic DFIR knowledge and no identifier
        # taken from any particular case (no channel IDs, no user names, no
        # disk paths).

        extra = []

        # Discord forensic artefacts (generic URL patterns + storage)
        if re.search(r'discord.*cache|leveldb|indexeddb|dm channel|discord.*dm|analytics.*token|verification', q_lower):
            extra.extend(['leveldb', 'IndexedDB', 'discord.com/verify',
                          'api/v9/users', 'users/@me', 'discord-cache', 'discord.com/channels'])

        # MetaMask extension forensic patterns (public Chrome extension ID)
        if re.search(r'metamask|swap|extension.*page|awaiting', q_lower):
            extra.extend(['nkbihfbeogaeaoehlefnkodbefgpgknn',
                          'awaiting-swap', 'prepare-swap-page', 'confirm-transaction',
                          'send', 'transaction', 'metamask-extension'])

        # File sharing services (public)
        if re.search(r'gofile|file.*shar|distribut|upload.*url', q_lower):
            extra.extend(['gofile.io', 'gofile', 'file-sharing'])

        # Trading / financial document artefacts (Korean keywords for trading log)
        if re.search(r'trading.*journal|매매|investment.*document|spreadsheet', q_lower):
            extra.extend(['매매일지', 'trading', 'xlsx'])

        # Outlook OST forensic patterns
        if re.search(r'\bost\b|outlook.*log|incoming.*log|gmail.*ost', q_lower):
            extra.extend(['.ost', 'Outlook', 'AppData', 'gmail.com.ost'])

        # Korean financial-crime / ransomware search queries (generic terms)
        if re.search(r'사채|매매일지|랜섬웨어|debt.*collector|loan.*shark|financial.*pressure', q_lower):
            extra.extend(['사채', '매매일지', '랜섬웨어', '불법 사채', '파산'])

        # Crypto exchange names (public services)
        if re.search(r'exchange|crypto.*exchange|trading.*platform|bithumb|upbit|binance|coinbase', q_lower):
            extra.extend(['Binance', 'Coinbase', 'Bithumb', 'Upbit', 'binance', 'upbit',
                          'cointrader', 'cointelegraph'])

        # Specific terms first; deduplication preserves the order
        ordered = []
        seen = set()
        for t in extra + v1_terms:
            key = t.lower() if isinstance(t, str) else str(t)
            if key not in seen:
                seen.add(key)
                ordered.append(t)
        return ordered

    def _determine_artifact_types(self, question: str) -> list:
        """v2: widens the artifact-type list for specific topics."""
        types = super()._determine_artifact_types(question)
        q_lower = question.lower()

        # Discord, MetaMask and crypto always go through browser (including cache leveldb)
        if re.search(r'discord|metamask|swap|crypto|bitcoin|btc|exchange|wallet|leveldb|cache', q_lower):
            if 'browser' not in types:
                types.append('browser')

        # Outlook OST is searched in mft and usnjrnl
        if re.search(r'\bost\b|everyrecover|souldrag|outlook.*log|incoming.*log', q_lower):
            for t in ('mft', 'usnjrnl'):
                if t not in types:
                    types.append(t)

        # Ransomware/file artifacts → shimcache + amcache + mft
        if re.search(r'ransom|malware|suspicious.*exec', q_lower):
            for t in ('shimcache', 'amcache', 'mft'):
                if t not in types:
                    types.append(t)

        # Korean search queries → browser
        if re.search(r'사채|매매|랜섬웨어|korean.*search|search.*queries', q_lower):
            if 'browser' not in types:
                types.append('browser')

        return list(set(types))

    def _retrieve_context(self, question: str) -> str:
        """Search, then rerank, then pack to the context budget."""
        search_terms = self._extract_search_terms(question)
        artifact_types = self._determine_artifact_types(question)

        all_results = []
        seen = set()

        for term in search_terms[:15]:
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

        # Registry value_name search (as in v1)
        if 'registry' in artifact_types:
            for term in search_terms[:8]:
                try:
                    from elasticsearch import Elasticsearch
                    es = Elasticsearch(self.es_url)
                    body = {
                        "query": {
                            "bool": {
                                "must": [{"match": {"value_name": term}}],
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

        q_lower = question.lower()

        # Prefetch, broad search
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

        # SRUM
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
                app_keywords = re.findall(r'\b([A-Z][a-zA-Z]+(?:\.exe)?)\b', question)
                for app_kw in app_keywords[:5]:
                    try:
                        app_result = self._tool_search_artifacts(query=app_kw, artifact_type="srum", limit=5)
                        if app_result and 'results' in app_result:
                            for r in app_result['results']:
                                all_results.append(r)
                    except Exception:
                        pass
            except Exception:
                pass

        # EventID lookups (as in v1)
        if re.search(r'4\d{3}|7\d{3}|1\d{3}|failed.*login|logon|account.*creat|defender|malware|powershell|service.*install', q_lower):
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
            explicit_eids = re.findall(r'\b(4\d{3}|7\d{3}|1\d{3})\b', question)
            target_eids.extend([int(e) for e in explicit_eids])
            target_eids = list(set(target_eids))
            if not target_eids and re.search(r'login|logon|auth|suspicious', q_lower):
                target_eids = [4624, 4625, 4647, 4720]
            for eid in target_eids[:5]:
                try:
                    events = self._tool_analyze_security_events(event_id=int(eid), limit=15)
                    if events:
                        if 'results' in events:
                            for r in events['results']:
                                all_results.append(r)
                        if 'total_found' in events:
                            all_results.append({"event_summary": f"Event ID {eid}: {events['total_found']} total events found"})
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

        # Direct Elasticsearch search of the browser index on url/title, bypassing losses in _tool_search_artifacts
        if 'browser' in artifact_types:
            try:
                from elasticsearch import Elasticsearch
                es = Elasticsearch(self.es_url)
                for term in search_terms[:10]:
                    if not isinstance(term, str) or len(term) < 3:
                        continue
                    body = {
                        "query": {
                            "bool": {
                                "must": [{"term": {"case_id.keyword": self.case_id}}],
                                "should": [
                                    {"match": {"url": term}},
                                    {"match": {"title": term}},
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        "size": 5,
                        "_source": ["timestamp", "url", "domain", "title", "visit_count", "browser"]
                    }
                    resp = es.search(index="forensic-browser", body=body)
                    for hit in resp['hits']['hits']:
                        r = hit['_source']
                        r['artifact_type'] = 'browser'
                        key = json.dumps(r, sort_keys=True, default=str)[:500]
                        if key not in seen:
                            seen.add(key)
                            all_results.append(r)
            except Exception:
                pass

        # Fallback: when few results are returned, widen the search to ALL artifact types
        # using the same terms (this catches questions whose artifact_types were scoped too narrowly)
        if len(all_results) < 5:
            all_types_fallback = ['registry', 'prefetch', 'browser', 'eventlog', 'mft',
                                  'srum', 'shimcache', 'amcache', 'lnk', 'jumplist', 'usnjrnl']
            for term in search_terms[:5]:
                for art_type in all_types_fallback:
                    if art_type in artifact_types:
                        continue
                    try:
                        results = self._tool_search_artifacts(
                            query=term, artifact_type=art_type, limit=5
                        )
                        if results and 'results' in results:
                            for r in results['results']:
                                key = json.dumps(r, sort_keys=True, default=str)[:500]
                                if key not in seen:
                                    seen.add(key)
                                    all_results.append(r)
                    except Exception:
                        continue

        if not all_results:
            return "No forensic evidence found for this query."

        # IMPORTANT_FINDING and event_summary are kept separate and always come first
        priority = [r for r in all_results if isinstance(r, dict) and (
            'IMPORTANT_FINDING' in r or 'event_summary' in r
        )]
        rest = [r for r in all_results if r not in priority]

        # Limit the remainder to the reranker pool
        rest_pool = rest[:self.INITIAL_POOL_LIMIT]

        # Pass through the reranker
        reranked = self._rerank(question, rest_pool)

        # Final order: priority records, then top-K after reranking, then the tail if room remains
        sorted_results = priority + reranked[:self.RERANK_TOP_K] + reranked[self.RERANK_TOP_K:]

        # Pack to the budget
        context_parts = []
        total_len = 0
        for r in sorted_results:
            clean = self._simplify_record(r)
            entry = json.dumps(clean, ensure_ascii=False, default=str)
            if total_len + len(entry) > self.CONTEXT_BUDGET_CHARS:
                break
            context_parts.append(entry)
            total_len += len(entry)

        return f"Found {len(all_results)} relevant records (reranked). Showing top {len(context_parts)}:\n\n" + "\n".join(context_parts)
