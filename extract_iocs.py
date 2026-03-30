#!/usr/bin/env python3
import re
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline

MODEL_NAME = "cisco-ai/SecureBERT2.0-NER"

FILTER_WORDS = {
    "the", "and", "attack", "attackers", "attacker", "target", "targeting", "using", "used",
    " communicating", "malicious", "identified", "initial", "access", "exploit", "exploited",
    "vulnerability", "malware", "system", "network", "domain", "document", "documents",
    "executing", "execute", "arbitrary", "code", "deploy", "deployed", "campaign", "researchers"
}

def load_model():
    print(f"Loading SecureBERT 2.0 NER model: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_NAME)
    return pipeline("ner", model=model, tokenizer=tokenizer, aggregation_strategy="max")

def is_valid_ioc(text):
    text_lower = text.lower().strip()
    if text_lower in FILTER_WORDS:
        return False
    if len(text_lower) < 2:
        return False
    if re.match(r'^(the|a|an|and|or|to|for|with|via|at|from|into|in|on|of)$', text_lower):
        return False
    return True

def get_grouped_entities(text, ner_pipeline):
    entities = ner_pipeline(text)
    result = {"indicators": set(), "malware": set(), "vulnerabilities": set(), "organizations": set(), "systems": set()}
    for ent in entities:
        group = ent.get("entity_group", "")
        word = ent.get("word", "").strip()
        if is_valid_ioc(word):
            if group == "Indicator":
                result["indicators"].add(word)
            elif group == "Malware":
                result["malware"].add(word)
            elif group == "Vulnerability":
                result["vulnerabilities"].add(word)
            elif group == "Organization":
                result["organizations"].add(word)
            elif group == "System":
                result["systems"].add(word)
    return {k: list(v) for k, v in result.items()}

def demo(ner_pipeline):
    sample_texts = [
        ("CVE Finding", "CVE-2024-12345 vulnerability in Microsoft Exchange Server allows remote attackers to execute arbitrary code. The attack exploited vulnerability to deploy LockBit ransomware. IOC: 192.168.1.100 and malware-domain.evil.com"),
        ("Malware Campaign", "The Emotet malware is being distributed via malicious documents. Researchers at Cisco Talos identified the campaign targeting financial institutions."),
        ("C2 Infrastructure", "Attackers used Cobalt Strike beacon at 10.0.0.25 communicating with evil.example.net. The vulnerability CVE-2021-44228 was exploited for initial access.")
    ]
    for name, text in sample_texts:
        print(f"\n{'='*60}")
        print(f"TEST: {name}")
        print(f"{'='*60}")
        print(f"Input: {text}")
        print()
        results = get_grouped_entities(text, ner_pipeline)
        has_results = False
        for cat, items in results.items():
            if items:
                has_results = True
                print(f"  {cat.upper()}: {', '.join(items)}")
        if not has_results:
            print("  [No entities detected]")

if __name__ == "__main__":
    ner = load_model()
    demo(ner)