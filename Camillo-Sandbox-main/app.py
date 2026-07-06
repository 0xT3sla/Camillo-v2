import asyncio
import json
import time
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import websockets

app = FastAPI(title="Camillo Sandbox Service")

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BROWSERLESS_URL = os.getenv("BROWSERLESS_URL", "ws://sandbox-browser:3000")

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "camillo-sandbox"}

@app.websocket("/sandbox/stream")
async def websocket_endpoint(websocket: WebSocket, url: str):
    await websocket.accept()
    print(f"[SANDBOX] Accepted client connection for target: {url}")
    
    # Establish WebSocket tunnel to Browserless container using Stealth mode and custom screen dimension
    browserless_ws_url = f"{BROWSERLESS_URL}/chrome?stealth&--window-size=1280,720"
    print(f"[SANDBOX] Connecting to Browserless engine at: {browserless_ws_url}")
    
    try:
        async with websockets.connect(browserless_ws_url) as browser_ws:
            print("[SANDBOX] Connected to Browserless. Initializing CDP Screencast...")
            
            # 1. Start screencasting via Chrome DevTools Protocol (CDP)
            await browser_ws.send(json.dumps({
                "id": 1,
                "method": "Page.startScreencast",
                "params": {"format": "jpeg", "quality": 80}
            }))
            
            # 2. Navigate to the suspicious URL
            print(f"[SANDBOX] Navigating browser context to target: {url}")
            await browser_ws.send(json.dumps({
                "id": 2,
                "method": "Page.navigate",
                "params": {"url": url}
            }))
            
            # 3. Initialize timer for strict 5-minute maximum session lifespan (Hard TTL)
            start_time = time.time()
            max_duration = 300  # 300 seconds (5 minutes)
            
            # Task to pipe browser screencast frames to the client
            async def forward_browser_to_client():
                nonlocal start_time
                try:
                    while True:
                        # Check hard TTL limit
                        elapsed = time.time() - start_time
                        if elapsed > max_duration:
                            print(f"[SANDBOX] Hard 5-minute limit reached ({elapsed:.2f}s). Force terminating session.")
                            await websocket.send_json({
                                "type": "timeout",
                                "message": "Session expired (Strict 5-minute lifespan limit reached)."
                            })
                            break
                            
                        # Receive CDP events from Browserless
                        msg_str = await browser_ws.recv()
                        msg = json.loads(msg_str)
                        
                        # Check for screencast frames
                        if msg.get("method") == "Page.screencastFrame":
                            params = msg.get("params", {})
                            data = params.get("data")  # Base64 encoded frame
                            session_id = params.get("sessionId")
                            
                            # Send acknowledgment back to CDP (Required for next frame emission)
                            await browser_ws.send(json.dumps({
                                "id": 100,
                                "method": "Page.screencastFrameAck",
                                "params": {"sessionId": session_id}
                            }))
                            
                            # Stream the frame to frontend
                            await websocket.send_json({
                                "type": "frame",
                                "data": data
                            })
                except Exception as e:
                    print(f"[SANDBOX] Browser reading pipeline closed: {e}")
            
            # Task to pipe user mouse/keyboard events from client to the browser
            async def forward_client_to_browser():
                try:
                    while True:
                        client_msg = await websocket.receive_json()
                        action = client_msg.get("action")
                        
                        if action == "click":
                            x = client_msg.get("x")
                            y = client_msg.get("y")
                            # Dispatch mouse press & release sequence
                            await browser_ws.send(json.dumps({
                                "id": 10,
                                "method": "Input.dispatchMouseEvent",
                                "params": {
                                    "type": "mousePressed",
                                    "x": x,
                                    "y": y,
                                    "button": "left",
                                    "clickCount": 1
                                }
                            }))
                            await browser_ws.send(json.dumps({
                                "id": 11,
                                "method": "Input.dispatchMouseEvent",
                                "params": {
                                    "type": "mouseReleased",
                                    "x": x,
                                    "y": y,
                                    "button": "left",
                                    "clickCount": 1
                                }
                            }))
                            
                        elif action == "type":
                            text = client_msg.get("text")
                            for char in text:
                                # Dispatch key characters
                                await browser_ws.send(json.dumps({
                                    "id": 20,
                                    "method": "Input.dispatchKeyEvent",
                                    "params": {
                                        "type": "char",
                                        "text": char
                                    }
                                }))
                except Exception as e:
                    print(f"[SANDBOX] Client input pipeline closed: {e}")
            
            # Execute both loops concurrently
            await asyncio.gather(
                forward_browser_to_client(),
                forward_client_to_browser(),
                return_exceptions=True
            )
            
    except WebSocketDisconnect:
        print("[SANDBOX] Client closed connection.")
    except Exception as e:
        print(f"[SANDBOX] Orchestrator connection error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass
        print("[SANDBOX] Ephemeral session destroyed and resources released.")
