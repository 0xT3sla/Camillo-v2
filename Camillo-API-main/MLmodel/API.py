from tensorflow import keras
from MLmodel.Feature_Extractor import extract_features
from dotenv import load_dotenv
import os

load_dotenv()

# ------------------------------------------------------------------------

# This function takes the url and returns probability value
model_path = os.getenv("MODEL_PATH")

def get_prediction(url):
    print("Loading the model...")
    model = keras.models.load_model(model_path)

    print("Extracting features from url...")
    url_features = extract_features(url)
    print(url_features)

    print("Making prediction...")
    prediction = model.predict([url_features])
    print(prediction)
    i = prediction[0][0] * 100
    i = round(i,3)

    return i
