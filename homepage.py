#python -m streamlit run homepage.py

import streamlit as st

#Presets
dates = ["Last 24 hours","Last 5 days", "Last 7 days", "Last 14 days", "Last 30 days"]
data_sources = ["NVD", "CISA KEV", "Github Advisories (GHSA)", "AlienVault OTX"]

#Page Setup
st.set_page_config(page_title="CTI Dashboard", layout="wide")

#Title
st.title("Global Threat Intelligence")

#Sidebar
st.sidebar.header("Filter Options")
st.sidebar.write("")

#Date dropdown
st.sidebar.markdown("Time Range")
species_options = st.sidebar.selectbox("Select time range from the dropdown", options=dates, index=0)

st.sidebar.write("")

#Severity score slider
st.sidebar.markdown("Minimum Severity Score")
min_severity = st.sidebar.slider(
    label="Select the minimum severity score", # The text shown above the slider
    min_value=0,                  # The lowest possible value
    max_value=10,                 # The highest possible value
    value=7,                      # The default starting value
    step=1,                       # The increment size when sliding
    help="0 (Info) to 10 (Critical)" # Optional tooltip text
)

#Data sources checkbox
st.sidebar.markdown("Data Sources")
use_nvd = st.sidebar.checkbox("NVD (CVEs)", value=True)
use_cisa = st.sidebar.checkbox("CISA KEV", value=True)
use_github = st.sidebar.checkbox("GitHub Advisories", value=True)
use_otx = st.sidebar.checkbox("AlienVault OTX", value=True)

#Filter active data sources in the dashboard
active_sources = []
if use_nvd:
    active_sources.append("NVD")
if use_cisa:
    active_sources.append("CISA KEV")
if use_github:
    active_sources.append("GitHub Advisories")
if use_otx:
    active_sources.append("AlienVault OTX")

st.sidebar.write("")

#AI Engine Status
st.sidebar.markdown("AI Engine Status")