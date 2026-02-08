import os
from dotenv import load_dotenv
from tensorflow import keras
from MLmodel.Feature_Extractor import extract_features

# ---------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------

load_dotenv()

# API.py lives in /app/MLmodel
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "Malicious_URL_Prediction.h5"
)

# ---------------------------------------------------------------------
# Load model ONCE at startup
# ---------------------------------------------------------------------

print("[INFO] Resolving model path:", MODEL_PATH)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at: {MODEL_PATH}")

print("[INFO] Loading model...")
model = keras.models.load_model(MODEL_PATH)
print("[INFO] Model loaded successfully")

# ---------------------------------------------------------------------
# Prediction function
# ---------------------------------------------------------------------

def get_prediction(url: str) -> float:
    """
    Takes a URL string and returns the malicious probability (0–100)
    """
    print("[INFO] Extracting features...")
    url_features = extract_features(url)

    # Model expects batch input
    url_features = [url_features]

    print("[INFO] Making prediction...")
    prediction = model.predict(url_features, verbose=0)

    probability = float(prediction[0][0]) * 100
    return round(probability, 3)
