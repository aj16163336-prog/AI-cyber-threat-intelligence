# Project Presentation Guide (Hinglish)

## 60-second introduction

“Mera project **AI Cyber Threat Intelligence** hai. Windows laptop par ek local sensor selected folders, process starts, installed-app changes, aur public network connection metadata observe karta hai. Dashboard us activity ko risk/anomaly signals, alerts, IOC context, MITRE ATT&CK mapping, incident tracking, aur reports ke saath dikhata hai. File contents laptop se bahar nahi bheje jaate. System analyst ko investigate karne mein help karta hai; ye automatically files delete ya network traffic block nahi karta.”

## System ka simple flow

```text
Windows laptop sensor
        │ event metadata (optional authenticated cloud sync)
        ▼
Local SQLite / Render API + PostgreSQL
        │
        ▼
Streamlit dashboard (desktop window or cloud website)
        │
        ├── Local anomaly model + per-device behavior baseline
        ├── Alert and incident investigation
        └── Optional consent-based OpenAI reviews
```

## 5-minute live presentation

1. **Desktop start karo:** project folder mein `Start_Desktop_App.bat` double-click karo. Desktop launcher dashboard kholta hai aur sensor pehle se chalu na ho to use start karta hai. Login details screen par enter karo; password presentation mein mat dikhana.
2. **Main Dashboard:** events, open alerts, incidents, aur sensor status ka overview samjhao.
3. **Endpoint Security:** sensor heartbeat aur recent file/process/network events dikhayo. Live file event dikhane ke liye Downloads mein ek harmless `.txt` file banao; sensitive file ko test ke liye use mat karo.
4. **AI Engine:** Isolation Forest aur har sensor ka apna behavior baseline samjhao. Score unusual activity ko prioritize karta hai; score malware hone ki probability ya final verdict nahi hai. Historical UNSW-NB15 model offline benchmark hai, live sensor classifier nahi.
5. **Threat Hunting:** Natural-language box mein `Show high-risk network events from the last 24 hours` type karke interpreted filters aur matching events dikhayo. Is query ka parser local hai.
6. **Alert System:** `Check for new notifications` dabao, alert ka evidence aur false-positive review dikhayo. Alert ko close karne ka decision analyst leta hai.
7. **Incident Management:** incident timeline, follow-up actions, PDF/CSV/evidence export dikhayo. AI timeline summary aur investigation brief optional hain.
8. **MITRE ATT&CK Map / Report Generator:** tentative technique mapping aur downloadable report dikha kar presentation close karo.

## OpenAI features ke baare mein

- Live anomaly model aur device baseline local chalte hain; inke liye OpenAI key zaroori nahi.
- Generative incident summaries, MITRE review, aur false-positive explanation ke liye app ki **private settings** mein `OPENAI_API_KEY` chahiye. Har manual review se pehle consent checkbox aur button use hota hai.
- Is computer ke local project settings mein review ke waqt `OPENAI_API_KEY` configured nahi tha. Isliye live generative review ko present karne se pehle private settings check karo; key ko screen share ya GitHub par mat dikhana.
- Is waqt generative prompts ko limited metadata bheja jata hai; file contents aur raw files AI service ko nahi bheje jaate.

## Teacher ke common questions

**“AI ka actual use kya hai?”**  
“Live endpoint events par local Isolation Forest aur per-device baseline unusual patterns ko score karte hain. Analyst feedback future baseline scoring ko influence kar sakta hai. Optional OpenAI reviews explanation aur incident handover text dete hain, jab key set ho aur analyst consent de.”

**“Kya ye threat ko automatically remove karta hai?”**  
“Nahi. Ye monitoring aur analyst triage tool hai. Alert verify karna aur koi response action lena human analyst ki responsibility hai.”

**“Cloud ko kya data jata hai?”**  
“Cloud sync enable ho to endpoint metadata jata hai. File contents aur packet payloads upload nahi hote. Local-only run mein events laptop ki SQLite database mein rehte hain.”

**“Agar real alert na aaye to?”**  
“Normal laptop activity se koi high-risk alert aana guaranteed nahi hai. Safe Test-Event Generator synthetic record banata hai; agar use karun to main use clearly synthetic bataunga, real detection nahi.”

## Presentation se pehle checklist

- [ ] Desktop app sign-in pehle se verify karo; screen share mein password/API token chhupao.
- [ ] `Start_Desktop_App.bat` se dashboard kholo aur Endpoint Security mein sensor heartbeat dekho.
- [ ] Har page par live data hone ki guarantee na do; khaali event window bhi valid hai.
- [ ] Generative AI features dikhane se pehle private `OPENAI_API_KEY` setting aur provider access check karo.
- [ ] Network/API unavailable ho to local sensor events dashboard mein verify karo; cloud sync ko tabhi live bolo jab sensor cloud API se authenticated ho.
- [ ] Findings ko “review signals” bolo; confirmed infection ya perfect coverage ka claim mat karo.

## Last verification snapshot

- 24 Oct 2026: all 29 dashboard sections rendered against isolated test data; no page-level exceptions.
- Python modules compiled, installed package check passed, and new search/baseline/coverage/incident-summary logic passed isolated checks.
- Local desktop dashboard responded successfully, and Render API `/health` returned `ok`.
- Streamlit Cloud served its app page, but cloud event flow was not authenticated during this check.
- Local endpoint sensor was running, but its `CTI_API_URL` and `CTI_API_TOKEN` were not configured. Use the **local desktop** for a live sensor demo; do not promise that fresh laptop events are reaching the cloud until cloud sync is configured and Sensor Health confirms it.
- Tests used a temporary database and did not create test records in the real project database.
