from datetime import datetime
from src.epss.models import CVEScore


def test_cve_score_repr(test_cve_score):
    repr_str = repr(test_cve_score)
    assert "CVEScore" in repr_str
    assert "CVE-2023-1234" in repr_str
    assert "0.5" in repr_str
