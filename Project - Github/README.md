# 🛡 Community Chat Platform Phishing  
*Machine Learning Detection of Phishing URLs in Messaging Platforms*

---

## 🚀 Project Overview

Phishing URLs remain one of the most common cyberattack vectors in community chat platforms such as Telegram, WhatsApp, and Discord.  
This project develops a **lightweight and real-time phishing URL detection model** designed for deployment in chat environments.

The final system will be integrated into a **Telegram bot**, with potential expansion to additional messaging apps and browser extensions.

---

## 🎯 Objective

✔ Detect phishing URLs **before** users accidentally click them  
✔ Prioritize **high recall** to reduce missed threats  
✔ Ensure real-time performance for interactive chat environments

---

## 📊 Dataset Summary

Two separate datasets were used in this project:

| Dataset | Size | Balance | Purpose |
|--------|-----:|--------:|---------|
| Kaggle Malicious URLs (https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) | 651k → 522k usable | Imbalanced (4.5:1) | Model training + evaluation |
| Mendeley URL Feature Dataset (https://data.mendeley.com/datasets/c2gw7fy2j4/3) | ~11k | Balanced (1:1) | Rich feature benchmarking + future improvements |

Due to large file sizes, datasets are hosted externally:  
➡ Download here: https://drive.google.com/drive/folders/1VoKLITJYEXWPDyVM3TvdxAmw9dI5afbl?usp=drive_link  

