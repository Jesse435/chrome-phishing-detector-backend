import pandas as pd
import re
from urllib.parse import urlparse

df = pd.read_csv("phishing_site_urls.csv")

def extract_features(url):

    parsed = urlparse(url)

    urlLength = len(url)

    hasIP = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 0

    hasHTTPS = 1 if url.startswith("https") else 0

    subdomainCount = parsed.hostname.count(".") if parsed.hostname else 0

    hasAtSymbol = 1 if "@" in url else 0

    suspicious_words = [
        "login","verify","bank","secure",
        "account","update","confirm","password"
    ]

    keywordCount = sum(word in url.lower() for word in suspicious_words)

    hasLoginForm = 1 if "login" in url.lower() else 0

    return {
        "urlLength": urlLength,
        "hasIP": hasIP,
        "hasHTTPS": hasHTTPS,
        "subdomainCount": subdomainCount,
        "hasAtSymbol": hasAtSymbol,
        "keywordCount": keywordCount,
        "externalLinks": 0,
        "internalLinks": 0,
        "scriptCount": 0,
        "iframeCount": 0,
        "hasLoginForm": hasLoginForm
    }

features = df["URL"].apply(extract_features)

feature_df = pd.DataFrame(features.tolist())

feature_df["label"] = df["Label"].apply(lambda x: 1 if x == "bad" else 0)

feature_df.to_csv("training_features.csv", index=False)

print("Feature dataset created.")