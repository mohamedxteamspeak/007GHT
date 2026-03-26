# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║  NEW UPDATE — replit_bot.py                          ║
║  Infinite Account Generator for Replit + Keep-Alive  ║
╚══════════════════════════════════════════════════════╝
"""
import os
import time
import random
import threading
from flask import Flask

from config import DATA_DIR
from guest_maker import create_accounts_batch

# === 1. FLASK WEB SERVER (KEEP-ALIVE) ===
app = Flask(__name__)

@app.route('/')
def home():
    """
    This endpoint allows monitoring services like UptimeRobot
    to ping the script every 5 minutes and keep it awake 24/7.
    """
    total_accs = 0
    if os.path.exists(DATA_DIR):
        files = [f for f in os.listdir(DATA_DIR) if f.endswith('.json')]
        total_accs = len(files) # Approximate count based on batches
    
    return f"""
    <html>
        <body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
            <h1 style="color: #4CAF50;">✅ NEW UPDATE Replit Bot is Online 24/7!</h1>
            <p><strong>Total JSON files in data/:</strong> {total_accs}</p>
            <p><i>Connect this URL to UptimeRobot (HTTP ping every 5 minutes)</i></p>
        </body>
    </html>
    """

def run_flask():
    """Run Flask server in the background."""
    print("🌐 Starting Keep-Alive Web Server on port 8080...")
    # Replit automatically maps port 8080 to the webview
    app.run(host="0.0.0.0", port=8080, use_reloader=False)

# === 2. INFINITE ACCOUNT GENERATOR LOOP ===
def auto_bot_loop():
    """Infinitely generate accounts with safe delays to avoid IP Ban."""
    print("\n🤖 Background Bot Started! Will run infinitely...")
    
    while True:
        try:
            # User specifically requested exactly 100 accounts per batch
            batch_size = 100
            
            print(f"\n[🔄] Starting new batch of {batch_size} accounts...")
            
            # Create accounts using normal speed (speed_mul=1.0)
            # This creates them at a normal, efficient pace without artificial stalling
            create_accounts_batch(
                count=batch_size, 
                region_code="ME", 
                pw_prefix="REPLIT", 
                speed_mul=1.0
            )
            
            # Sleep between 5 to 7 minutes before the next batch of 100
            sleep_time = random.randint(300, 420)
            print(f"\n[💤] Batch finished. Sleeping for {sleep_time // 60} minutes and {sleep_time % 60} seconds before the next 100...")
            time.sleep(sleep_time)
            
        except Exception as e:
            print(f"❌ Error in infinite loop: {e}")
            print("⏳ Retrying in 60 seconds...")
            time.sleep(60)

if __name__ == "__main__":
    # Ensure our data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 1. Start the Flask Keep-Alive Server in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    time.sleep(2) # Give Flask a second to boot up
    
    # 2. Run the infinite bot loop on the main thread
    auto_bot_loop()
