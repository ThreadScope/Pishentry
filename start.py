import sys
import os
import time
import subprocess
import urllib.request
import signal

# Ensure UTF-8 output encoding for Windows console compatibility
if hasattr(sys.stdout, 'reconfigure'):
  sys.stdout.reconfigure(encoding='utf-8')

API_URL = "http://127.0.0.1:8000/health"

def wait_for_api(timeout_seconds: int = 15):
  """Waits for FastAPI server to become ready."""
  print("⏳ Waiting for FastAPI backend to initialize...")
  start = time.time()
  while time.time() - start < timeout_seconds:
    try:
      with urllib.request.urlopen(API_URL, timeout=2) as response:
        if response.status == 200:
          print(" FastAPI backend is live at http://127.0.0.1:8000")
          return True
    except Exception:
      time.sleep(1)
  print("️ Backend health check timed out. Launching frontend anyway...")
  return False

def main():
  print("==================================================")
  print(" Starting CloneCatcher AI (Backend + Frontend)")
  print("==================================================")
  
  python_exe = sys.executable
  cwd = os.path.dirname(os.path.abspath(__file__))
  
  processes = []
  
  try:
    # 1. Start FastAPI backend (Uvicorn)
    print("▶️ Launching FastAPI backend server on port 8000...")
    backend_cmd = [python_exe, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"]
    backend_proc = subprocess.Popen(backend_cmd, cwd=cwd)
    processes.append(backend_proc)
    
    # 2. Wait for FastAPI to respond
    wait_for_api()
    
    # 3. Start Streamlit frontend
    print("▶️ Launching Streamlit frontend UI on port 8501...")
    frontend_cmd = [python_exe, "-m", "streamlit", "run", "ui/streamlit_app.py", "--server.port", "8501"]
    frontend_proc = subprocess.Popen(frontend_cmd, cwd=cwd)
    processes.append(frontend_proc)
    
    print("\n Both services are running!")
    print("  - API Docs:  http://127.0.0.1:8000/docs")
    print("  - Web App UI: http://localhost:8501")
    print("\nPress Ctrl+C to stop both servers.\n")
    
    # Keep launcher alive and monitor subprocesses
    while True:
      for p in processes:
        if p.poll() is not None:
          print(f"️ A subprocess (PID {p.pid}) exited unexpectedly.")
      time.sleep(2)
      
  except KeyboardInterrupt:
    print("\n Shutting down CloneCatcher AI processes...")
  finally:
    for p in processes:
      if p.poll() is None:
        p.terminate()
        try:
          p.wait(timeout=3)
        except subprocess.TimeoutExpired:
          p.kill()
    print(" Shutdown complete.")

if __name__ == "__main__":
  main()
