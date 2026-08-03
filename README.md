# Global Threat Intelligence Dashboard

Global Threat Intelligence Dashboard is a centralized Threat Intelligence dashboard built with Python and Streamlit. It aggregates data from various security feeds (CVEs, IoCs, and News) into a single webpage. It also includes AI for analysis.

### Tech used

* **Frontend/Framework:** [Streamlit](https://streamlit.io/)
* **AI Engine:** Google Gemini API (`google-genai` / `google-generativeai`)
* **Data Processing:** `pandas`
* **Styling:** Custom HTML5 / CSS3

### Install dependencies

(`pip install -r requirements.txt`)

### AI Setup

I have used Gemini flash 3.6. The API key was in a file called gemini_key.txt.

### Run the application

(`streamlit run app.py`)
(`python -m streamlit run app.py`)

### Some considerations

* I have not included my gemini_key.txt file here for security reasons.
* (`unsafe_allow_html=True`) is utilized strictly for rendering trusted internal component strings and CSS formatting.
