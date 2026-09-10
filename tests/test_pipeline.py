import unittest
from src.pipeline import Indicator, normalize, run, score_indicator

class PipelineTests(unittest.TestCase):
    def test_domain_normalization(self): self.assertEqual(normalize("Example.COM", "domain"), "example.com")
    def test_invalid_hash_rejected(self):
        with self.assertRaises(ValueError): Indicator("bad", "sha256", "test", 50)
    def test_invalid_confidence_rejected(self):
        with self.assertRaises(ValueError): Indicator("203.0.113.1", "ipv4", "test", 101)
    def test_duplicate_indicators_are_collapsed(self):
        items=[Indicator("Example.COM","domain","a",50),Indicator("example.com","domain","b",60)]
        self.assertEqual(len(run(items, {})),1)
    def test_high_context_scores_above_low_context(self):
        i=Indicator("203.0.113.1","ipv4","test",70)
        high=score_indicator(i,{"intel_matches":5,"malicious_votes":5,"first_seen_days":60,"prevalence":1})
        low=score_indicator(i,{})
        self.assertGreater(high.score,low.score)
    def test_score_bounded(self):
        i=Indicator("203.0.113.1","ipv4","test",100)
        self.assertLessEqual(score_indicator(i,{"intel_matches":99,"malicious_votes":99,"first_seen_days":999,"prevalence":0}).score,100)
    def test_finding_id_deterministic(self):
        i=Indicator("Example.COM","domain","test",50)
        self.assertEqual(score_indicator(i,{}).finding_id,score_indicator(i,{}).finding_id)
    def test_attack_techniques_deduplicated(self):
        i=Indicator("example.com","domain","test",50)
        r=score_indicator(i,{"attack_techniques":["T1071.001","T1071.001"]})
        self.assertEqual(r.attack_techniques,("T1071.001",))

if __name__ == "__main__": unittest.main()
