# benchmark/evaluation_metrics.py
"""
Evaluation metrics for forensic AI system:
1. Factual Accuracy - correctness of answers vs ground truth
2. Consistency - same answers on repeated questions
3. Hallucination Detection - detecting fabricated facts
"""

import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import requests


@dataclass
class EvaluationResult:
    """Result of a single evaluation."""
    metric_type: str  # "accuracy", "consistency", "hallucination"
    score: float  # 0.0 - 1.0
    details: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class HallucinationReport:
    """Detailed hallucination analysis."""
    total_claims: int = 0
    verified_claims: int = 0
    hallucinated_claims: int = 0
    unverifiable_claims: int = 0

    # Specific hallucination types
    fake_files: List[str] = field(default_factory=list)
    fake_timestamps: List[str] = field(default_factory=list)
    fake_events: List[str] = field(default_factory=list)
    fake_users: List[str] = field(default_factory=list)

    @property
    def hallucination_rate(self) -> float:
        if self.total_claims == 0:
            return 0.0
        return self.hallucinated_claims / self.total_claims

    @property
    def accuracy_rate(self) -> float:
        if self.total_claims == 0:
            return 1.0
        return self.verified_claims / self.total_claims


class FactExtractor:
    """Extract verifiable facts from LLM responses."""

    # Patterns for extracting facts
    PATTERNS = {
        # File paths (Windows) - require filename with extension or min 2 segments
        "file_path": r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)+[^\\/:*?"<>|\r\n\s\.]{2,}',

        # Timestamps (various formats)
        "timestamp_iso": r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        "timestamp_date": r'\d{4}-\d{2}-\d{2}',

        # Event IDs
        "event_id": r'[Ee]vent\s*(?:ID)?[:\s]*(\d{4,5})',

        # Usernames (require quoted or specific format to avoid false positives)
        "username": r'(?:user(?:name)?|account)\s*(?:is|was|named|called|:)\s*["\']?([A-Za-z0-9_\-\.]{3,})["\']?',

        # IP addresses
        "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',

        # SHA1/MD5 hashes
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',

        # Executable names
        "executable": r'\b([a-zA-Z0-9_\-]+\.exe)\b',

        # Registry keys
        "registry_key": r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU)\\[^\s\n]+',

        # Run counts
        "run_count": r'run\s*count[:\s]*(\d+)',
    }

    # Common words that get falsely extracted as usernames/facts
    IGNORE_VALUES = {
        'username': {'the', 'is', 'was', 'on', 'in', 'to', 'for', 'and', 'not',
                     'account', 'system', 'primary', 'user', 'admin', 'found',
                     'this', 'that', 'with', 'from', 'have', 'has', 'are', 'were'},
        'executable': {'setup.exe', 'install.exe'},  # generic
    }

    def extract_facts(self, response: str) -> Dict[str, List[str]]:
        """Extract all verifiable facts from response."""
        facts = {}

        for fact_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, response, re.IGNORECASE)
            if matches:
                # Clean, deduplicate, and filter out common false positives
                ignore = self.IGNORE_VALUES.get(fact_type, set())
                cleaned = list(set(
                    str(m).strip() for m in matches
                    if m and str(m).strip().lower() not in ignore and len(str(m).strip()) >= 3
                ))
                if cleaned:
                    facts[fact_type] = cleaned

        return facts

    def extract_claims(self, response: str) -> List[Dict]:
        """Extract structured claims from response."""
        claims = []
        facts = self.extract_facts(response)

        # Convert to claims
        for fact_type, values in facts.items():
            for value in values:
                claims.append({
                    "type": fact_type,
                    "value": value,
                    "verified": None,  # To be filled by verifier
                    "source": None
                })

        return claims


class FactVerifier:
    """Verify facts against Elasticsearch data."""

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None):
        self.es_url = es_url
        self.case_id = case_id

    # Fact types that are hard to verify - treat as unverifiable if not found
    SOFT_VERIFY_TYPES = {"username", "ip_address", "md5", "sha1", "run_count",
                         "timestamp_date", "timestamp_iso", "registry_key",
                         "file_path"}

    def verify_fact(self, fact_type: str, value: str) -> Tuple[bool, Optional[str]]:
        """
        Verify a single fact against ES.

        Returns:
            (is_verified, source_index) - True=verified, False=hallucinated, None=unverifiable
        """
        result = None
        if fact_type == "file_path":
            result = self._verify_file_path(value)
        elif fact_type == "executable":
            result = self._verify_executable(value)
        elif fact_type in ("timestamp_iso", "timestamp_date"):
            result = self._verify_timestamp(value)
        elif fact_type == "event_id":
            result = self._verify_event_id(value)
        elif fact_type == "sha1":
            result = self._verify_hash(value, "sha1")
        elif fact_type == "registry_key":
            result = self._verify_registry_key(value)
        elif fact_type == "username":
            result = self._verify_username(value)
        else:
            return (None, None)  # Unverifiable type

        # For soft-verify types, treat "not found" as unverifiable instead of hallucinated
        if result[0] is False and fact_type in self.SOFT_VERIFY_TYPES:
            return (None, None)

        return result

    def _es_search(self, index: str, query: str, size: int = 1) -> List[Dict]:
        """Execute ES search."""
        try:
            body = {
                "size": size,
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["*"],
                        "type": "best_fields"
                    }
                }
            }

            if self.case_id:
                body["query"] = {
                    "bool": {
                        "must": [body["query"]],
                        "filter": [{"term": {"case_id.keyword": self.case_id}}]
                    }
                }

            response = requests.post(
                f"{self.es_url}/{index}/_search",
                json=body,
                timeout=5
            )

            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                return [hit["_source"] for hit in hits]
        except Exception:
            pass
        return []

    def _verify_file_path(self, path: str) -> Tuple[bool, Optional[str]]:
        """Verify file path exists in MFT, Prefetch, or other artifacts."""
        # Normalize path
        path_lower = path.lower()
        filename = path.split("\\")[-1] if "\\" in path else path

        # Search in MFT
        results = self._es_search("forensic-mft", filename, 5)
        for r in results:
            if path_lower in r.get("file_path", "").lower():
                return (True, "forensic-mft")

        # Search in Prefetch
        results = self._es_search("forensic-prefetch", filename, 5)
        for r in results:
            if path_lower in str(r.get("files_loaded", [])).lower():
                return (True, "forensic-prefetch")
            if path_lower in r.get("executable_path", "").lower():
                return (True, "forensic-prefetch")

        # Search in LNK
        results = self._es_search("forensic-lnk", filename, 5)
        for r in results:
            if path_lower in r.get("target_path", "").lower():
                return (True, "forensic-lnk")

        return (False, None)

    def _verify_executable(self, exe_name: str) -> Tuple[bool, Optional[str]]:
        """Verify executable exists in Prefetch/Shimcache/Amcache."""
        exe_lower = exe_name.lower()

        # Prefetch
        results = self._es_search("forensic-prefetch", exe_name, 5)
        for r in results:
            if exe_lower in r.get("executable_name", "").lower():
                return (True, "forensic-prefetch")

        # Shimcache
        results = self._es_search("forensic-shimcache", exe_name, 5)
        for r in results:
            if exe_lower in r.get("path", "").lower():
                return (True, "forensic-shimcache")

        # Amcache
        results = self._es_search("forensic-amcache", exe_name, 5)
        for r in results:
            if exe_lower in r.get("name", "").lower():
                return (True, "forensic-amcache")

        return (False, None)

    def _verify_timestamp(self, timestamp: str) -> Tuple[bool, Optional[str]]:
        """Verify timestamp exists in data (within reasonable range)."""
        # Extract date part
        date_part = timestamp[:10] if len(timestamp) >= 10 else timestamp

        # Search across all indices
        results = self._es_search("forensic-*", date_part, 1)
        if results:
            return (True, "forensic-*")

        return (False, None)

    def _verify_event_id(self, event_id: str) -> Tuple[bool, Optional[str]]:
        """Verify Event ID exists in Event Logs."""
        try:
            eid = int(event_id)
            body = {
                "size": 1,
                "query": {"term": {"event_id": eid}}
            }

            if self.case_id:
                body["query"] = {
                    "bool": {
                        "must": [body["query"]],
                        "filter": [{"term": {"case_id.keyword": self.case_id}}]
                    }
                }

            response = requests.post(
                f"{self.es_url}/forensic-eventlog/_search",
                json=body,
                timeout=5
            )

            if response.status_code == 200:
                total = response.json().get("hits", {}).get("total", {})
                count = total.get("value", 0) if isinstance(total, dict) else total
                if count > 0:
                    return (True, "forensic-eventlog")
        except Exception:
            pass

        return (False, None)

    def _verify_hash(self, hash_value: str, hash_type: str) -> Tuple[bool, Optional[str]]:
        """Verify hash exists in Amcache."""
        results = self._es_search("forensic-amcache", hash_value, 1)
        for r in results:
            if hash_value.lower() == r.get("sha1", "").lower():
                return (True, "forensic-amcache")

        return (False, None)

    def _verify_registry_key(self, key_path: str) -> Tuple[bool, Optional[str]]:
        """Verify registry key exists."""
        # Extract key name for search
        key_name = key_path.split("\\")[-1] if "\\" in key_path else key_path

        results = self._es_search("forensic-registry", key_name, 5)
        for r in results:
            if key_path.lower() in r.get("key_path", "").lower():
                return (True, "forensic-registry")

        return (False, None)

    def _verify_username(self, username: str) -> Tuple[bool, Optional[str]]:
        """Verify username exists in data."""
        results = self._es_search("forensic-*", username, 5)
        for r in results:
            # Check various user fields
            for field in ["user", "user_id", "user_name", "account"]:
                if username.lower() in str(r.get(field, "")).lower():
                    return (True, "forensic-*")

        return (False, None)


class HallucinationDetector:
    """Detect hallucinations in LLM responses."""

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None):
        self.extractor = FactExtractor()
        self.verifier = FactVerifier(es_url, case_id)

    def analyze(self, response: str) -> HallucinationReport:
        """Analyze response for hallucinations."""
        report = HallucinationReport()

        # Extract claims
        claims = self.extractor.extract_claims(response)
        report.total_claims = len(claims)

        # Verify each claim
        for claim in claims:
            verified, source = self.verifier.verify_fact(
                claim["type"], claim["value"]
            )

            if verified is True:
                report.verified_claims += 1
                claim["verified"] = True
                claim["source"] = source
            elif verified is False:
                report.hallucinated_claims += 1
                claim["verified"] = False

                # Categorize hallucination
                if claim["type"] in ("file_path", "executable"):
                    report.fake_files.append(claim["value"])
                elif claim["type"] in ("timestamp_iso", "timestamp_date"):
                    report.fake_timestamps.append(claim["value"])
                elif claim["type"] == "event_id":
                    report.fake_events.append(claim["value"])
                elif claim["type"] == "username":
                    report.fake_users.append(claim["value"])
            else:
                report.unverifiable_claims += 1

        return report


class ConsistencyEvaluator:
    """Evaluate consistency of responses across repeated questions."""

    def __init__(self):
        self.extractor = FactExtractor()

    def evaluate(self, responses: List[str]) -> EvaluationResult:
        """
        Evaluate consistency across multiple responses to same question.

        Args:
            responses: List of responses to the same question

        Returns:
            EvaluationResult with consistency score
        """
        if len(responses) < 2:
            return EvaluationResult(
                metric_type="consistency",
                score=1.0,
                details={"note": "Only one response, consistency = 1.0"}
            )

        # Extract facts from each response
        all_facts = [self.extractor.extract_facts(r) for r in responses]

        # Calculate fact overlap
        metrics = {
            "exact_match_pairs": 0,
            "total_pairs": 0,
            "avg_jaccard": 0.0,
            "key_facts_consistency": 0.0,
            "fact_counts": [sum(len(v) for v in f.values()) for f in all_facts]
        }

        jaccard_scores = []

        # Compare each pair of responses
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                metrics["total_pairs"] += 1

                facts_i = self._flatten_facts(all_facts[i])
                facts_j = self._flatten_facts(all_facts[j])

                # Jaccard similarity
                intersection = facts_i & facts_j
                union = facts_i | facts_j

                if union:
                    jaccard = len(intersection) / len(union)
                    jaccard_scores.append(jaccard)

                    if jaccard > 0.9:
                        metrics["exact_match_pairs"] += 1
                else:
                    jaccard_scores.append(1.0)  # Both empty = consistent

        # Calculate final score
        metrics["avg_jaccard"] = sum(jaccard_scores) / len(jaccard_scores) if jaccard_scores else 1.0

        # Key facts consistency (files, timestamps)
        key_consistency = self._calculate_key_facts_consistency(all_facts)
        metrics["key_facts_consistency"] = key_consistency

        # Combined score (weighted)
        score = 0.6 * metrics["avg_jaccard"] + 0.4 * key_consistency

        return EvaluationResult(
            metric_type="consistency",
            score=score,
            details=metrics
        )

    def _flatten_facts(self, facts: Dict[str, List[str]]) -> Set[str]:
        """Flatten facts dict to set of strings."""
        result = set()
        for fact_type, values in facts.items():
            for v in values:
                result.add(f"{fact_type}:{v.lower()}")
        return result

    def _calculate_key_facts_consistency(self, all_facts: List[Dict]) -> float:
        """Calculate consistency for key fact types (files, timestamps)."""
        key_types = ["file_path", "executable", "timestamp_iso", "event_id"]

        consistencies = []
        for fact_type in key_types:
            # Get values for this type from all responses
            type_values = []
            for facts in all_facts:
                values = set(v.lower() for v in facts.get(fact_type, []))
                type_values.append(values)

            if not any(type_values):
                continue

            # Calculate pairwise overlap
            overlaps = []
            for i in range(len(type_values)):
                for j in range(i + 1, len(type_values)):
                    if type_values[i] or type_values[j]:
                        union = type_values[i] | type_values[j]
                        inter = type_values[i] & type_values[j]
                        overlaps.append(len(inter) / len(union) if union else 1.0)

            if overlaps:
                consistencies.append(sum(overlaps) / len(overlaps))

        return sum(consistencies) / len(consistencies) if consistencies else 1.0


class AccuracyEvaluator:
    """Evaluate factual accuracy against ground truth."""

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None):
        self.extractor = FactExtractor()
        self.verifier = FactVerifier(es_url, case_id)

    def evaluate(self, response: str, ground_truth: Dict = None) -> EvaluationResult:
        """
        Evaluate accuracy of response.

        Args:
            response: LLM response text
            ground_truth: Optional dict with expected facts

        Returns:
            EvaluationResult with accuracy metrics
        """
        # Extract facts
        facts = self.extractor.extract_facts(response)

        # Verify against ES
        verified = 0
        not_verified = 0
        unverifiable = 0

        verification_details = {}

        for fact_type, values in facts.items():
            verification_details[fact_type] = {
                "total": len(values),
                "verified": 0,
                "not_verified": [],
            }

            for value in values:
                is_verified, source = self.verifier.verify_fact(fact_type, value)

                if is_verified is True:
                    verified += 1
                    verification_details[fact_type]["verified"] += 1
                elif is_verified is False:
                    not_verified += 1
                    verification_details[fact_type]["not_verified"].append(value)
                else:
                    unverifiable += 1

        total_verifiable = verified + not_verified
        accuracy = verified / total_verifiable if total_verifiable > 0 else 1.0

        # If ground truth provided, also check coverage
        coverage = 1.0
        if ground_truth:
            coverage = self._calculate_coverage(facts, ground_truth)

        return EvaluationResult(
            metric_type="accuracy",
            score=accuracy,
            details={
                "verified_facts": verified,
                "not_verified_facts": not_verified,
                "unverifiable_facts": unverifiable,
                "total_facts": verified + not_verified + unverifiable,
                "ground_truth_coverage": coverage,
                "by_type": verification_details
            }
        )

    def _calculate_coverage(self, extracted: Dict, ground_truth: Dict) -> float:
        """Calculate how many ground truth facts are covered."""
        covered = 0
        total = 0

        for fact_type, expected_values in ground_truth.items():
            total += len(expected_values)
            extracted_values = set(v.lower() for v in extracted.get(fact_type, []))

            for expected in expected_values:
                if expected.lower() in extracted_values:
                    covered += 1

        return covered / total if total > 0 else 1.0


class ForensicEvaluator:
    """Main evaluator combining all metrics."""

    def __init__(self, es_url: str = "http://localhost:9200", case_id: str = None):
        self.es_url = es_url
        self.case_id = case_id

        self.accuracy_evaluator = AccuracyEvaluator(es_url, case_id)
        self.consistency_evaluator = ConsistencyEvaluator()
        self.hallucination_detector = HallucinationDetector(es_url, case_id)

    def evaluate_response(self, response: str,
                         ground_truth: Dict = None) -> Dict[str, EvaluationResult]:
        """Evaluate a single response."""
        results = {}

        # Accuracy
        results["accuracy"] = self.accuracy_evaluator.evaluate(response, ground_truth)

        # Hallucination
        hallucination_report = self.hallucination_detector.analyze(response)
        results["hallucination"] = EvaluationResult(
            metric_type="hallucination",
            score=1.0 - hallucination_report.hallucination_rate,  # Higher = better (less hallucination)
            details={
                "total_claims": hallucination_report.total_claims,
                "verified": hallucination_report.verified_claims,
                "hallucinated": hallucination_report.hallucinated_claims,
                "unverifiable": hallucination_report.unverifiable_claims,
                "hallucination_rate": hallucination_report.hallucination_rate,
                "fake_files": hallucination_report.fake_files[:10],
                "fake_timestamps": hallucination_report.fake_timestamps[:10],
                "fake_events": hallucination_report.fake_events[:10],
            }
        )

        return results

    def evaluate_consistency(self, responses: List[str]) -> EvaluationResult:
        """Evaluate consistency across multiple responses."""
        return self.consistency_evaluator.evaluate(responses)

    def full_evaluation(self, question: str, responses: List[str],
                       ground_truth: Dict = None) -> Dict:
        """
        Full evaluation of responses to a question.

        Args:
            question: The question asked
            responses: List of responses (multiple runs)
            ground_truth: Optional expected facts

        Returns:
            Complete evaluation report
        """
        report = {
            "question": question,
            "num_responses": len(responses),
            "timestamp": datetime.now().isoformat(),
            "metrics": {}
        }

        # Evaluate each response for accuracy/hallucination
        response_evals = []
        for i, response in enumerate(responses):
            eval_result = self.evaluate_response(response, ground_truth)
            response_evals.append({
                "response_index": i,
                "accuracy": eval_result["accuracy"].score,
                "hallucination_free": eval_result["hallucination"].score,
                "details": {
                    "accuracy": eval_result["accuracy"].details,
                    "hallucination": eval_result["hallucination"].details
                }
            })

        # Average metrics
        avg_accuracy = sum(e["accuracy"] for e in response_evals) / len(response_evals)
        avg_hallucination_free = sum(e["hallucination_free"] for e in response_evals) / len(response_evals)

        report["metrics"]["accuracy"] = {
            "mean": avg_accuracy,
            "min": min(e["accuracy"] for e in response_evals),
            "max": max(e["accuracy"] for e in response_evals)
        }

        report["metrics"]["hallucination_free"] = {
            "mean": avg_hallucination_free,
            "min": min(e["hallucination_free"] for e in response_evals),
            "max": max(e["hallucination_free"] for e in response_evals)
        }

        # Consistency (only if multiple responses)
        if len(responses) > 1:
            consistency = self.evaluate_consistency(responses)
            report["metrics"]["consistency"] = {
                "score": consistency.score,
                "details": consistency.details
            }
        else:
            report["metrics"]["consistency"] = {"score": 1.0, "details": {"note": "Single response"}}

        report["per_response"] = response_evals

        # Overall score (weighted average)
        report["overall_score"] = (
            0.4 * avg_accuracy +
            0.3 * avg_hallucination_free +
            0.3 * report["metrics"]["consistency"]["score"]
        )

        return report


# Example usage
if __name__ == "__main__":
    # Test with sample response
    sample_response = """
    Based on my analysis, I found the following:

    The user account "johnsmith" executed C:\\Users\\johnsmith\\Downloads\\malware.exe
    on 2023-09-22T14:30:00. This executable was run 5 times according to Prefetch data.

    Event ID 4624 shows successful logon at 2023-09-22T14:25:00.
    The SHA1 hash a1b2c3d4e5f6789012345678901234567890abcd was found in Amcache.

    Registry key HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run contains persistence.
    """

    evaluator = ForensicEvaluator()

    # Test fact extraction
    extractor = FactExtractor()
    facts = extractor.extract_facts(sample_response)
    print("Extracted facts:")
    for fact_type, values in facts.items():
        print(f"  {fact_type}: {values}")

    # Test single response evaluation
    result = evaluator.evaluate_response(sample_response)
    print(f"\nAccuracy score: {result['accuracy'].score:.2f}")
    print(f"Hallucination-free score: {result['hallucination'].score:.2f}")
