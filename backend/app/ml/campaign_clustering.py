"""
MailTrace.AI - Campaign Clustering & Attack DNA Engine
Cosine Similarity on 32-Dimensional Forensic Vectors & Campaign Correlation
"""
import math
from typing import List, Dict, Any, Tuple

class CampaignClusteringEngine:
    """Computes cosine similarity across 32D attack vectors and groups incident campaigns."""

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        """Calculates cosine similarity between two n-dimensional vectors."""
        if len(v1) != len(v2) or not v1:
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(v1, v2))
        norm_v1 = math.sqrt(sum(a * a for a in v1))
        norm_v2 = math.sqrt(sum(b * b for b in v2))
        
        if norm_v1 == 0.0 or norm_v2 == 0.0:
            return 0.0
        
        return round(dot_product / (norm_v1 * norm_v2), 4)

    def correlate_cases(
        self,
        target_case: Dict[str, Any],
        case_catalog: List[Dict[str, Any]],
        threshold: float = 0.85
    ) -> List[Dict[str, Any]]:
        """
        Finds related cases in the catalog with cosine similarity above the threshold.
        """
        target_vec = target_case.get("vector_32d", [])
        if not target_vec:
            return []

        correlations = []
        for case in case_catalog:
            if case.get("case_id") == target_case.get("case_id"):
                continue
            case_vec = case.get("vector_32d", [])
            sim = self.cosine_similarity(target_vec, case_vec)
            if sim >= threshold:
                correlations.append({
                    "related_case_id": case.get("case_id"),
                    "similarity": sim,
                    "similarity_pct": round(sim * 100, 1),
                    "filename": case.get("filename", ""),
                    "fraud_score": case.get("fraud_score", 0.0),
                    "risk_tier": case.get("risk_tier", "UNKNOWN"),
                    "campaign_cluster": f"CMP-{case.get('case_id', '')[:6].upper()}"
                })

        # Sort by similarity descending
        correlations.sort(key=lambda x: x["similarity"], reverse=True)
        return correlations

campaign_engine = CampaignClusteringEngine()
