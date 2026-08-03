import streamlit as st
import pandas as pd
import requests
import datetime
import plotly.graph_objects as go
import google.generativeai as genai
import os

# Page config
st.set_page_config(page_title="Global Threat Intelligence", layout="wide", initial_sidebar_state="expanded")

# CSS
st.markdown("""
<style>
    .ioc-grid { 
        font-family: 'Courier New', monospace; font-size: 14px; 
    }
    
    /* Threat card style */
    .threat-card { 
        background: rgba(128, 128, 128, 0.05); /* Very faint gray. This is suitable for both light and dark mode */
        border: 1px solid rgba(128, 128, 128, 0.2); 
        border-radius: 8px; 
        padding: 16px; 
        margin-bottom: 12px; 
    }
    .threat-card h4 { 
        margin-top: 0; 
        margin-bottom: 8px; 
        font-size: 16px; 
    }
    .threat-date { 
        font-size: 12px; color: #888; 
    }
    
    .ai-summary { 
        background-color: rgba(59, 130, 246, 0.1);
        border-left: 4px solid #4a90e2; 
        padding: 12px; 
        margin-top: 12px; 
        border-radius: 0 4px 4px 0; 
    }
    .ai-summary p { 
        margin: 4px 0; 
        font-size: 14px; 
    }
    
    .mitre-tag { 
        display: inline-block; 
        background: rgba(128, 128, 128, 0.15); 
        padding: 2px 8px; 
        border-radius: 12px; 
        font-size: 11px; 
        font-weight: 600; 
        margin-right: 6px; 
        margin-top: 8px; 
    }
</style>
""", unsafe_allow_html=True) #This line renders the CSS


# AI Setup
# Gemini 3.6 flash lite was used
def load_gemini_key(filepath="gemini_key.txt"):
    """Loads the Gemini API key from a local text file"""
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            key = f.read().strip()
            if key:
                return key
    return "Error fetching the API key" # Fallback so the UI handles the missing key

GEMINI_API_KEY = load_gemini_key()

if "ai_status" not in st.session_state:
    st.session_state.ai_status = "Connected" if GEMINI_API_KEY != "Error fetching the API key" else "Awaiting API Key"

def get_ai_summary(text):
    """Uses Gemini to summarize threat text and extract MITRE tactics."""
    if GEMINI_API_KEY == "Error fetching the API key":
        st.session_state.ai_status = "Awaiting API Key"
        return {"summary": "Gemini API key not configured. Add your key to generate AI summaries.", "tags": ["T0000: Setup Required"]}
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-3.6-flash')
        prompt = f"""
        Analyze the following cyber threat intelligence text. 
        1. Write a 2-sentence executive summary (Threat and Impact).
        2. Identify up to 2 relevant MITRE ATT&CK Techniques.
        Format your response EXACTLY like this:
        Summary: [Your 2 sentence summary]
        Tags: [Tag 1], [Tag 2]
        
        Text to analyze: {text}
        """
        response = model.generate_content(prompt)
        output = response.text
        
        summary = output.split("Summary:")[1].split("Tags:")[0].strip()
        tags_raw = output.split("Tags:")[1].strip()
        tags = [tag.strip() for tag in tags_raw.split(',')]
        
        st.session_state.ai_status = "Connected"
        return {"summary": summary, "tags": tags}
    except Exception as e:
        st.session_state.ai_status = "Offline"
        return {"summary": f"AI Engine offline: {e}", "tags": []}


# Functions for fetching data
@st.cache_data(ttl=3600) 
def fetch_cisa_kev():
    """Fetches the live CISA Known Exploited Vulnerabilities catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        df = pd.DataFrame(data['vulnerabilities'])
        df['dateAdded'] = pd.to_datetime(df['dateAdded'])
        return df
    except Exception as e:
        st.error(f"Error fetching CISA KEV: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=3600)
def fetch_feodo_tracker():
    """Fetches live Botnet and C2 server data from Abuse.ch."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        df = pd.DataFrame(data)
        df['first_seen'] = pd.to_datetime(df['first_seen'])
        return df
    except Exception as e:
        return pd.DataFrame(columns=['ip_address', 'status', 'country', 'first_seen', 'malware'])


# Loading data
kev_df = fetch_cisa_kev()
c2_df = fetch_feodo_tracker()

# Sidebar
with st.sidebar:
    st.markdown("## Global Threat Intelligence Dashboard")
    st.write("")
    
    time_range = st.selectbox("Time Range", options=["Last 24 hours", "Last 7 days", "Last 30 days"], index=0)
    st.write("")
    
    min_severity = st.slider("Minimum Severity Score", min_value=0, max_value=10, value=7, step=1)
    st.write("")
    
    st.markdown("<p style='font-size: 14px; font-weight: 500; margin-bottom: 5px;'>Data Sources</p>", unsafe_allow_html=True)
    use_nvd = st.checkbox("NVD", value=True)
    use_cisa = st.checkbox("CISA KEV", value=True)
    use_ghsa = st.checkbox("Github Advisories (GHSA)", value=True)
    use_otx = st.checkbox("AlienVault OTX", value=True)
    
    st.divider()
    
    st.markdown("<p style='font-size: 14px; font-weight: 500; margin-bottom: 5px;'>AI Engine Status</p>", unsafe_allow_html=True)
    ai_status_placeholder = st.empty()

# Header row
st.markdown("<h1 style='font-weight: 300; margin-bottom: 0px;'>Global Threat Intelligence</h1>", unsafe_allow_html=True)

header_col1, header_col2 = st.columns([3, 1])
with header_col2:
    now = datetime.datetime.now()
    st.markdown(f"""
        <div style='text-align: right; line-height: 1.2;'>
            <span style='font-size: 20px; font-weight: 300;'>{now.strftime("%H:%M")}</span><br>
            <span style='font-size: 14px; color: #666;'>{now.strftime("%Y-%m-%d")}</span><br>
            <span style='font-size: 14px; color: #666;'>Dashboard Live</span>
        </div>
    """, unsafe_allow_html=True)
st.write("")
st.write("")

# Metrics row
col1, col2, col3 = st.columns(3)

# 1. Total Attacks Metric
with col1:
    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True) 
    if not c2_df.empty:
        online_threats = c2_df[c2_df['status'] == 'online']
        total_active = len(online_threats)
        
        now_utc = datetime.datetime.utcnow()
        yesterday = now_utc - datetime.timedelta(days=1)
        two_days_ago = now_utc - datetime.timedelta(days=2)
        added_today = len(online_threats[online_threats['first_seen'] >= yesterday])
        added_yesterday = len(online_threats[(online_threats['first_seen'] >= two_days_ago) & (online_threats['first_seen'] < yesterday)])
        delta = added_today - added_yesterday

        st.metric(label="Today's attacks (Live C2 Servers)", value=f"{total_active:,}", delta=delta, delta_color="inverse")
    else:
        st.metric(label="Today's attacks", value="0", delta="0", delta_color="inverse")

# 2. Top Countries Bar Chart
with col2:
    st.markdown("<p style='font-size: 14px; text-align: center; margin-bottom: 10px;'>Top Attacks by countries</p>", unsafe_allow_html=True)
    if not c2_df.empty:
        top_countries = c2_df[c2_df['status'] == 'online']['country'].value_counts().head(3)
        max_count = top_countries.max()

        html = '<div style="display: flex; flex-direction: column; gap: 10px; max-width: 200px; margin: 0 auto;">'
        for country_code, count in top_countries.items():
            width_pct = int((count / max_count) * 100)
            html += f"""
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="width: 30px; font-size: 14px; font-weight: 500;">{country_code}</span>
                <div style="flex-grow: 1; background: rgba(128, 128, 128, 0.2); height: 6px; border-radius: 3px;">
                    <div style="width: {width_pct}%; background: #4a90e2; height: 100%; border-radius: 3px;"></div>
                </div>
            </div>
            """
        html += '</div>'
        st.markdown(html, unsafe_allow_html=True)

# 3. Donut Chart
with col3:
    if not c2_df.empty:
        top_malware = c2_df[c2_df['status'] == 'online']['malware'].value_counts().head(3)
        labels = top_malware.index.tolist()
        values = top_malware.values.tolist()
        
        fig = go.Figure(data=[go.Pie(
            labels=labels, values=values, hole=0.6,
            marker=dict(colors=['#27272a', '#52525b', '#a1a1aa']),
            textinfo='none'
        )])
        fig.update_layout(
            margin=dict(t=0, b=0, l=0, r=0), height=140, showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5, font=dict(size=11))
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

st.divider()

# Tabs
tab1, tab2, tab3 = st.tabs(["News Feed & AI", "Vulnerabilities (CISA KEV)", "Indicators of Compromise (Abuse.ch)"])

# Tab 1: News feed
with tab1:
    st.markdown("### Latest High-Profile Vulnerabilities")
    
    if not kev_df.empty:
        top_news = kev_df.sort_values(by='dateAdded', ascending=False).head(2)
        
        for index, row in top_news.iterrows():
            with st.spinner("AI is analyzing this threat..."):
                ai_data = get_ai_summary(row['shortDescription'])
                
            tags_html = "".join([f"<span class='mitre-tag'>{tag}</span>" for tag in ai_data['tags']])
            date_str = row['dateAdded'].strftime('%Y-%m-%d')
            
            card_html = f"""
            <div class='threat-card'>
                <h4>{row['vendorProject']} {row['product']} Vulnerability ({row['cveID']})</h4>
                <span class='threat-date'>Added to KEV: {date_str} | Action Due: {row['dueDate']}</span>
                <p>{row['shortDescription']}</p>
                <div class='ai-summary'>
                    <strong>✨ AI Analysis</strong>
                    <p>{ai_data['summary']}</p>
                    <div>{tags_html}</div>
                </div>
            </div>
            """
            
            st.markdown(card_html, unsafe_allow_html=True)
            
# Tab 2: Vulnerabilities
with tab2:
    if not kev_df.empty and use_cisa:
        st.markdown(f"*(Showing latest entries from the live CISA KEV database)*")
        display_df = kev_df.sort_values(by='dateAdded', ascending=False).head(15)
        display_df = display_df[['cveID', 'vendorProject', 'product', 'shortDescription', 'dateAdded']]
        display_df.columns = ['CVE ID', 'Vendor', 'Product', 'Description', 'Date Added']
        st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.write("Data source not selected or unavailable.")

# Tab 3: IoC
with tab3:
    st.markdown("### Live Command & Control IPs")
    st.write("These indicators represent active, online botnet infrastructure sourced from Abuse.ch.")
    
    if not c2_df.empty:
        ioc_df = c2_df[c2_df['status'] == 'online'][['ip_address', 'port', 'malware', 'first_seen']].copy()
        ioc_df.columns = ['IP Address', 'Port', 'Malware Family', 'First Seen']
        
        # Display as an interactive dataframe allowing for easy search
        st.dataframe(ioc_df, use_container_width=True, hide_index=True)
    else:
        st.info("No active IoCs available at this time.")

# Render AI status
with ai_status_placeholder:
    if st.session_state.ai_status == "Connected":
        status_html = """
        <div style="display: flex; align-items: center; gap: 8px;">
            <div style="position: relative; display: flex; width: 10px; height: 10px;">
              <span style="position: absolute; display: inline-flex; height: 100%; width: 100%; border-radius: 50%; background-color: #4ade80; opacity: 0.75; animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;"></span>
              <span style="position: relative; display: inline-flex; border-radius: 50%; height: 10px; width: 10px; background-color: #22c55e;"></span>
            </div>
            <span style="font-size: 13px; color: #4aff4d;">Connected</span>
        </div>
        <style>@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: .5; transform: scale(1.5); } }</style>
        """
    elif st.session_state.ai_status == "Offline":
        status_html = """
        <div style="display: flex; align-items: center; gap: 8px;">
            <div style="position: relative; display: flex; width: 10px; height: 10px;">
              <span style="position: relative; display: inline-flex; border-radius: 50%; height: 10px; width: 10px; background-color: #ef4444;"></span>
            </div>
            <span style="font-size: 13px; color: #ef4444; font-weight: 500;">Disconnected</span>
        </div>
        """
    else:
         status_html = """
        <div style="display: flex; align-items: center; gap: 8px;">
            <div style="position: relative; display: flex; width: 10px; height: 10px;">
              <span style="position: relative; display: inline-flex; border-radius: 50%; height: 10px; width: 10px; background-color: #facc15;"></span>
            </div>
            <span style="font-size: 13px; color: #ffffff;">Connecting</span>
        </div>
        """
    st.markdown(status_html, unsafe_allow_html=True)
