# Camillo‑v2

Camillo‑v2 is a **containerized full‑stack web application** that analyzes URLs and predicts whether they are malicious using a **TensorFlow machine‑learning model**. The project is split into a Flask‑based backend API and a Flask‑based frontend UI, both orchestrated using **Docker Compose**.

This README explains **what the app does**, **how it is structured**, and **how containerization and networking are implemented**.

---

## 🧠 What the Application Does

1. The **frontend** provides a web UI where a user submits a URL.
2. The frontend sends the URL to the **backend API**.
3. The backend:

   * Extracts features from the URL
   * Loads a pre‑trained TensorFlow `.h5` model
   * Predicts how likely the URL is malicious
4. The result is sent back to the frontend and displayed to the user.

---

## 🏗️ Project Structure

```
Camillo-v2/
│
├── docker-compose.yml
│
├── Camillo-API-main/        # Backend (Flask + ML)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py
│   ├── controller.py
│   ├── model.py
│   └── MLmodel/
│       ├── API.py
│       ├── Feature_Extractor.py
│       └── models/
│           └── Malicious_URL_Prediction.h5
│
└── Camillo-Frontend-main/   # Frontend (Flask UI)
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py
    ├── static/
    └── templates/
```

---

## 🐳 Containerization Overview

The application is fully containerized using **Docker** and orchestrated with **Docker Compose**.

### Services

* **backend**

  * Flask REST API
  * Loads ML model at startup

* **frontend**

  * Flask UI server
  * Communicates with backend over Docker internal network

---

## 🔗 Docker Networking Explained

Docker Compose automatically creates:

* A **shared bridge network**
* An **internal DNS resolver**

This allows containers to talk to each other using **service names**.

### Example

```env
API_URL=http://backend:6969
```

Inside the frontend container:

* `backend` resolves to the backend container’s IP
* No hardcoded IPs are needed
* DNS resolution works at runtime

⚠️ `localhost` **must never be used** between containers.

---

## 📦 Backend Implementation Details

### Model Loading Strategy

The TensorFlow model is loaded **once at container startup**, not per request.

```python
model = keras.models.load_model(MODEL_PATH)
```

This avoids:

* Slow predictions
* Memory leaks
* Repeated disk reads

### Model Path Resolution

The model file exists at:

```
/app/MLmodel/models/Malicious_URL_Prediction.h5
```

Path resolution uses `__file__` to remain Docker‑safe:

```python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "Malicious_URL_Prediction.h5")
```

---

## 🚀 Running the Application

### Build Containers

```bash
docker compose build --no-cache
```

### Start Services

```bash
docker compose up
```

### Access the App

Once the containers are running, the frontend and backend services are available on their respective exposed ports as defined in the Docker Compose configuration.

Access is handled via the frontend service, which internally communicates with the backend over the Docker network.

---

## 🧪 API Endpoint

The backend exposes an internal API endpoint used by the frontend to submit URLs for analysis.

The endpoint accepts a URL string, performs feature extraction and ML inference, and returns a probability score indicating whether the URL is malicious.

```json
{
  "url": "https://example.com"
}
```

**Response**

```json
{
  "probability": 87.432
}
```

---

## 🛠️ Common Issues & Fixes

### Model file not found

Cause:

* Incorrect relative paths

Fix:

* Always resolve paths from `__file__`
* Never hardcode `/models/...`

---

### Backend not reachable from frontend

Cause:

* Using `localhost` instead of service name

Fix:

```env
API_URL=http://backend:6969
```

---

## ⚠️ Notes on Production

* Flask development servers are used for simplicity
* For production usage, the backend should run behind a WSGI server such as Gunicorn
* A reverse proxy (e.g., Nginx) is recommended for routing and TLS termination
* TensorFlow CPU build is used

---

## ✅ Key Takeaways

* Docker Compose provides **automatic DNS**
* Service names replace IP addresses
* ML models must be loaded **once**, not per request
* Path bugs are the #1 cause of Docker ML failures

---

## 🚀 Future Plans: Kubernetes (K8s)

The project is designed with Kubernetes adoption in mind. Planned improvements include:

* Creating Kubernetes manifests for:

  * Backend Deployment and Service
  * Frontend Deployment and Service
* Configuring environment variables using ConfigMaps
* Storing ML model paths and settings in Kubernetes Secrets
* Adding readiness and liveness probes for health monitoring
* Horizontal Pod Autoscaling (HPA) for backend inference scaling
* Separating frontend and backend namespaces
* Adding an Ingress controller for external access

This transition will allow:

* Better scalability
* Zero-downtime deployments
* Improved observability and fault tolerance

---

## 📌 Status

✔ Backend containerized
✔ Frontend containerized
✔ ML model loaded correctly
✔ Inter-container networking working

