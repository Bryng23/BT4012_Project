import pickle
import pandas as pd
from preprocess import extract_features, headers
from sklearn.preprocessing import StandardScaler
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from telegram import Update
import os
from dotenv import load_dotenv
import re

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

with open("xgb_smote_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

with open("threshold.txt", "r") as f:
    threshold = float(f.read().strip())

def extract_urls(text):
    url_regex = r'(https?://[^\s]+|www\.[^\s]+|\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)'
    urls = re.findall(url_regex, text)
    return urls

def preprocess_url(url):
    features_row = extract_features(url, 0)
    features_row = features_row[:-1]
    if features_row is None:
        print(f"[DEBUG] Feature extraction failed for URL: {url}")
        return None
    print(f"[DEBUG] Features for URL {url}: {features_row}")
    df = pd.DataFrame([features_row], columns=headers)
    X = df.drop(columns=['url'])
    X_scaled = scaler.transform(X)
    print(f"[DEBUG] Scaled features:\n{X_scaled}")
    return X_scaled

def predict_phishing(url):
    features_scaled = preprocess_url(url)
    if features_scaled is None:
        return None, None
    proba = model.predict_proba(features_scaled)[0][1]
    print(f"[DEBUG] Predicted probability for {url}: {proba}")
    return proba * 100, proba >= 0.4

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message_text = update.message.text or ""
    urls = extract_urls(message_text)
    if urls:
        responses = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            risk, is_phishing = predict_phishing(url)
            if risk is None:
                msg = f"Could not process URL: {url}"
            else:
                msg = f"URL: {url}\nPhishing risk: {risk:.2f}%"
                if is_phishing:
                    msg += "\nWarning: Likely phishing!"
            responses.append(msg)
        await update.message.reply_text("\n\n".join(responses))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send me any link and I will check if it's phishing.")

if __name__ == '__main__':
    
    app = ApplicationBuilder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    app.run_polling()