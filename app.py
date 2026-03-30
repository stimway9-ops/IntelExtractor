#!/usr/bin/env python3
import streamlit as st
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import pdfplumber
import re
from datetime import datetime
import io

MODEL_NAME = "cisco-ai/SecureBERT2.0-NER"

FILTER_WORDS = {
    "the", "and", "attack", "attackers", "attacker", "target", "targeting", "using", "used",
    "communicating", "malicious", "identified", "initial", "access", "exploit", "exploited",
    "vulnerability", "malware", "system", "network", "domain", "document", "documents",
    "executing", "execute", "arbitrary", "code", "deploy", "deployed", "campaign", "researchers",
    "via", "at", "from", "into", "in", "on", "of", "for", "with"
}

@st.cache_resource
def load_model():
    with st.spinner("Loading SecureBERT 2.0 NER model..."):
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

def extract_iocs(text, ner_pipeline):
    entities = ner_pipeline(text)
    result = {"indicators": [], "malware": [], "vulnerabilities": [], "organizations": [], "systems": []}
    for ent in entities:
        group = ent.get("entity_group", "")
        word = ent.get("word", "").strip()
        if is_valid_ioc(word):
            if group == "Indicator":
                result["indicators"].append({"text": word, "score": ent.get("score", 0)})
            elif group == "Malware":
                result["malware"].append({"text": word, "score": ent.get("score", 0)})
            elif group == "Vulnerability":
                result["vulnerabilities"].append({"text": word, "score": ent.get("score", 0)})
            elif group == "Organization":
                result["organizations"].append({"text": word, "score": ent.get("score", 0)})
            elif group == "System":
                result["systems"].append({"text": word, "score": ent.get("score", 0)})
    return result

def extract_text_from_pdf(file):
    text = ""
    with pdfplumber.open(file) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    return text

def extract_text_from_file(uploaded_file):
    if uploaded_file.name.endswith('.pdf'):
        return extract_text_from_pdf(uploaded_file)
    elif uploaded_file.name.endswith(('.txt', '.log', '.csv', '.json', '.md')):
        return uploaded_file.read().decode('utf-8', errors='ignore')
    else:
        return None

def extract_text_from_url(url):
    from bs4 import BeautifulSoup
    import requests
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        for scripts in soup(["script", "style", "nav", "footer", "header"]):
            scripts.decompose()
        
        text = soup.get_text(separator=' ')
        
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text
        
    except Exception as e:
        return f"ERROR: {str(e)}"

def process_text_in_chunks(text, ner_pipeline, chunk_size=2000):
    words = text.split()
    chunks = []
    for i in range(0, len(words), chunk_size):
        chunks.append(' '.join(words[i:i+chunk_size]))
    
    combined_results = {"indicators": [], "malware": [], "vulnerabilities": [], "organizations": [], "systems": []}
    
    progress_bar = st.progress(0)
    for idx, chunk in enumerate(chunks):
        results = extract_iocs(chunk, ner_pipeline)
        for key in combined_results:
            combined_results[key].extend(results[key])
        progress_bar.progress((idx + 1) / len(chunks))
    
    for key in combined_results:
        seen = set()
        unique = []
        for item in combined_results[key]:
            if item["text"] not in seen:
                seen.add(item["text"])
                unique.append(item)
        combined_results[key] = unique
    
    return combined_results

def main():
    st.set_page_config(page_title="SecureBERT 2.0 IOC Extractor", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ SecureBERT 2.0 Threat Intelligence Extractor")
    st.markdown("Extract IOCs from cybersecurity text, DFIR reports, and threat intel documents")
    
    ner_pipeline = load_model()
    
    st.sidebar.header("⚙️ About")
    st.sidebar.info("""
    **SecureBERT 2.0 NER** extracts:
    - **Indicators**: IPs, domains, hashes, CVEs, emails
    - **Malware**: Malware names & families
    - **Vulnerabilities**: CVE IDs
    - **Organizations**: Threat groups, companies
    - **Systems**: Software, platforms
    """)
    st.sidebar.markdown("---")
    st.sidebar.subheader("📁 Supported Files")
    st.sidebar.markdown("- **PDF**: DFIR reports, threat advisories")
    st.sidebar.markdown("- **TXT**: Log files, incident notes")
    st.sidebar.markdown("- **CSV**: IOC feeds")
    st.sidebar.markdown("- **JSON**: Threat intel exports")
    st.sidebar.markdown("- **URL**: Web threat reports")
    
    tab1, tab2, tab3 = st.tabs(["📝 Text Input", "📁 File Upload", "🌐 URL/Website"])
    
    with tab1:
        text_input = st.text_area("Paste Threat Intelligence Text", height=200, 
                                   placeholder="Enter threat report, incident description, or security advisory text...")
        col1, col2 = st.columns([1, 4])
        with col1:
            process_text_btn = st.button("🔍 Extract from Text", type="primary", key="text_btn")
    
    with tab2:
        uploaded_file = st.file_uploader("Upload PDF or Text File", 
                                          type=['pdf', 'txt', 'log', 'csv', 'json', 'md'],
                                          help="Upload DFIR reports, threat intel PDFs, or IOC files")
        
        if uploaded_file:
            st.success(f"📄 File uploaded: {uploaded_file.name}")
            with st.spinner("Extracting text from file..."):
                file_text = extract_text_from_file(uploaded_file)
            
            if file_text:
                st.text_area("Extracted Text Preview", file_text[:5000] + ("..." if len(file_text) > 5000 else ""), 
                            height=150, disabled=True)
                
                word_count = len(file_text.split())
                st.info(f"📊 Extracted {word_count:,} words from {uploaded_file.name}")
                process_file_btn = st.button("🔍 Extract IOCs from File", type="primary", key="file_btn")
            else:
                st.error("Unsupported file format")
                process_file_btn = False
        else:
            process_file_btn = False
    
    with tab3:
        url_input = st.text_input("🌐 Enter URL to Scrape", placeholder="https://example.com/threat-report")
        
        col_url1, col_url2 = st.columns([1, 3])
        with col_url1:
            scrape_btn = st.button("🔍 Fetch & Extract", type="primary", key="url_btn")
        with col_url2:
            if url_input:
                st.info(f"Target: {url_input}")
        
        url_text = None
        if scrape_btn and url_input:
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'https://' + url_input
            
            with st.spinner(f"Fetching {url_input}..."):
                url_text = extract_text_from_url(url_input)
            
            if url_text and not url_text.startswith("ERROR:"):
                st.text_area("Extracted Text Preview", url_text[:5000] + ("..." if len(url_text) > 5000 else ""), 
                            height=150, disabled=True)
                word_count = len(url_text.split())
                st.info(f"📊 Fetched {word_count:,} words from URL")
            elif url_text and url_text.startswith("ERROR:"):
                st.error(url_text)
            else:
                st.error("Could not extract text from URL")
    
    col_clear, col_export = st.columns([1, 1])
    with col_clear:
        if 'history' not in st.session_state:
            st.session_state.history = []
        clear_btn = st.button("🗑️ Clear History")
    with col_export:
        export_btn = st.button("📥 Export Latest IOCs")
    
    if clear_btn:
        st.session_state.history = []
        st.rerun()
    
    if export_btn and st.session_state.history:
        latest = st.session_state.history[0]
        all_iocs = []
        for cat, items in latest['results'].items():
            for item in items:
                all_iocs.append(f"{cat.strip().rstrip('s')}: {item['text']}")
        export_text = "\n".join(all_iocs)
        st.download_button("Download IOCs", export_text, "extracted_iocs.txt", "text/plain")
    
    text_to_process = text_input if process_text_btn and text_input.strip() else None
    
    if 'uploaded_text' not in st.session_state:
        st.session_state.uploaded_text = None
    if 'url_text' not in st.session_state:
        st.session_state.url_text = None
    
    if process_file_btn and uploaded_file:
        st.session_state.uploaded_text = file_text
    
    if scrape_btn and url_input and url_text:
        st.session_state.url_text = url_text
    
    combined_text = text_to_process or st.session_state.uploaded_text or st.session_state.url_text
    
    if combined_text and (process_text_btn or process_file_btn or scrape_btn):
        with st.spinner("Processing text for IOC extraction..."):
            results = process_text_in_chunks(combined_text, ner_pipeline)
        
        if process_text_btn:
            source_name = "Text Input"
        elif process_file_btn:
            source_name = uploaded_file.name if uploaded_file else "File"
        elif scrape_btn:
            source_name = url_input
        else:
            source_name = "Unknown"
        
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source_name,
            "text": combined_text[:500] + "..." if len(combined_text) > 500 else combined_text,
            "results": results
        }
        st.session_state.history.insert(0, entry)
        st.session_state.uploaded_text = None
        st.session_state.url_text = None
        
        st.success("✅ Extraction complete!")
        
        total_iocs = sum(len(v) for v in results.values())
        if total_iocs > 0:
            st.metric("Total IOCs Extracted", total_iocs)
            
            c1, c2, c3, c4, c5 = st.columns(5)
            with c1:
                st.metric("Indicators", len(results["indicators"]))
            with c2:
                st.metric("Malware", len(results["malware"]))
            with c3:
                st.metric("Vulnerabilities", len(results["vulnerabilities"]))
            with c4:
                st.metric("Organizations", len(results["organizations"]))
            with c5:
                st.metric("Systems", len(results["systems"]))
            
            tabs = st.tabs(["🚨 Indicators", "🦠 Malware", "⚠️ Vulnerabilities", "🏢 Organizations", "💻 Systems"])
            
            with tabs[0]:
                for item in results["indicators"]:
                    st.code(item["text"], language="text")
                if not results["indicators"]:
                    st.info("No indicators found")
            
            with tabs[1]:
                for item in results["malware"]:
                    st.code(item["text"], language="text")
                if not results["malware"]:
                    st.info("No malware found")
            
            with tabs[2]:
                for item in results["vulnerabilities"]:
                    st.code(item["text"], language="text")
                if not results["vulnerabilities"]:
                    st.info("No vulnerabilities found")
            
            with tabs[3]:
                for item in results["organizations"]:
                    st.code(item["text"], language="text")
                if not results["organizations"]:
                    st.info("No organizations found")
            
            with tabs[4]:
                for item in results["systems"]:
                    st.code(item["text"], language="text")
                if not results["systems"]:
                    st.info("No systems found")
                    
            with st.expander("📄 View Source Text"):
                st.text(combined_text)
        else:
            st.warning("No entities detected. Try different content.")
    
    if st.session_state.history:
        st.divider()
        st.subheader("📜 Extraction History")
        for i, entry in enumerate(st.session_state.history[:10]):
            total = len(sum([v for v in entry['results'].values()], []))
            with st.expander(f"{entry['timestamp']} [{entry['source']}] - {total} IOCs"):
                st.text_area("Source", entry["text"], height=60, key=f"hist_{i}", disabled=True)
                r = entry["results"]
                cols = st.columns(5)
                with cols[0]:
                    st.write(f"**Indicators**: {len(r['indicators'])}")
                with cols[1]:
                    st.write(f"**Malware**: {len(r['malware'])}")
                with cols[2]:
                    st.write(f"**Vulns**: {len(r['vulnerabilities'])}")
                with cols[3]:
                    st.write(f"**Orgs**: {len(r['organizations'])}")
                with cols[4]:
                    st.write(f"**Systems**: {len(r['systems'])}")

if __name__ == "__main__":
    main()