import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, db
import pytesseract
from PIL import ImageGrab, Image
import pyautogui
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time

LICENSE_FILE = "license.json"
ACCOUNT_FILE = "account.json"
ENCRYPTED_KEY_FILE = "encrypted_service_key.json"

# Configure Tesseract path
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Generate a consistent Fernet key from a passphrase
passphrase = b"super_secure_passphrase"
SECRET_KEY = base64.urlsafe_b64encode(hashlib.sha256(passphrase).digest()[:32])

# Mapping dictionary for hero IDs to hero names
hero_id_to_name = {
    1016: "Loki", 1018: "Doctor Strange", 1020: "Mantis", 1021: "Hawkeye",
    1022: "Captain America", 1023: "Rocket Raccoon", 1024: "Hela", 1025: "Cloak & Dagger",
    1026: "Black Panther", 1027: "Groot", 1029: "Magik", 1030: "Moon Knight",
    1031: "Luna Snow", 1032: "Squirrel Girl", 1033: "Black Widow", 1034: "Iron Man",
    1035: "Venom", 1036: "Spider-man", 1037: "Magneto", 1038: "Scarlet Witch",
    1039: "Thor", 1040: "Mister Fantastic", 1041: "Winter Soldier", 1042: "Peni Parker",
    1043: "Star-lord", 1045: "Namor", 1046: "Adam Warlock", 1047: "Jeff The Land Shark",
    1048: "Psylocke", 1049: "Wolverine", 1050: "Invisible Woman", 1052: "Iron Fist"
}

# Function to encrypt the service account key
def load_decrypted_service_key():
    try:
        with open(ENCRYPTED_KEY_FILE, "r") as f:
            encrypted_data = f.read()
        cipher = Fernet(SECRET_KEY)
        decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
        with open("decrypted_serviceAccountKey.json", "w") as f:
            f.write(decrypted_data)
        return "decrypted_serviceAccountKey.json"
    except Exception as e:
        print(f"Failed to decrypt service key: {e}")
        exit(1)

# Initialize Firebase with proper environment validation
try:
    decrypted_key_path = load_decrypted_service_key()
    cred = credentials.Certificate(decrypted_key_path)
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://marvel-rivals-8a194-default-rtdb.firebaseio.com/'
    })
    print("Firebase initialized successfully.")
    os.remove(decrypted_key_path)  # Remove the decrypted file after initialization
except Exception as e:
    print(f"Failed to initialize Firebase: {e}")
    exit(1)

def encrypt_data(data):
    cipher = Fernet(SECRET_KEY)
    return cipher.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(data):
    try:
        cipher = Fernet(SECRET_KEY)
        return json.loads(cipher.decrypt(data.encode()).decode())
    except (InvalidToken, Exception) as e:
        print(f"Failed to decrypt data: {e}")
        return None

def save_license_locally(key, username="User"):
    activation_date = datetime.now().isoformat()
    expiration_date = (datetime.now() + timedelta(days=30)).isoformat()
    license_data = {
        "key": key,
        "activation_date": activation_date,
        "expires_at": expiration_date,
        "username": username
    }
    encrypted_data = encrypt_data(license_data)
    with open(LICENSE_FILE, "w") as f:
        f.write(encrypted_data)
    print("License saved locally for 30 days.")

def load_license():
    if not os.path.exists(LICENSE_FILE):
        return None
    with open(LICENSE_FILE, "r") as f:
        encrypted_data = f.read()
    if not encrypted_data:
        return None
    return decrypt_data(encrypted_data)

def verify_license():
    license_data = load_license()
    if not license_data:
        return False

    expiration_date = datetime.fromisoformat(license_data.get('expires_at'))
    if datetime.now() > expiration_date:
        print("License expired. Please reactivate.")
        return False

    username = license_data.get('username', 'User')
    print(f"Welcome, {username}! License is still valid.")
    return True

def check_and_activate_license():
    try:
        if verify_license():
            print("Access granted. Running application...")
            main_application()
            return

        username = input("Enter a name for this device: ") or "User"

        while True:
            user_input = input("Enter your license key: ")
            if len(user_input) != 25:
                print("Invalid key format. Please enter a 25-character key.")
                continue

            # Search for the key in the database
            try:
                licenses_ref = db.reference('licenses').get()
                found_key = None
                found_id = None

                if licenses_ref:
                    for license_id, license_info in licenses_ref.items():
                        if license_info.get('key') == user_input:
                            found_key = license_info
                            found_id = license_id
                            break

                if found_key:
                    save_license_locally(user_input, username)
                    db.reference(f'licenses/{found_id}').delete()  # Remove key after successful activation
                    print(f"License activated successfully. Welcome, {username}! Access granted for 30 days.")
                    main_application()
                    break
                else:
                    print("Invalid or non-existent license key. Please try again.")
            except Exception as e:
                print(f"Database connection error: {e}")
                print("Please check your network connection and Firebase configuration.")
                break
    except Exception as e:
        print(f"Unexpected error in authentication process: {e}")
        exit(1)

def get_player_names():
    """Capture screenshots, perform OCR, and allow user confirmation."""
    name_boxes = [
        (1435, 190, 1600, 209),
        (1402, 311, 1600, 333),
        (1371, 439, 1591, 460),
        (1340, 560, 1545, 590),
        (1308, 687, 1561, 715),
        (1280, 813, 1530, 836)
    ]

    full_screenshot = pyautogui.screenshot()
    full_screenshot.save("full_screenshot.png")
    full_screenshot.show()

    screenshots = [ImageGrab.grab(bbox=box) for box in name_boxes]
    names = []
    for i, img in enumerate(screenshots):
        text = pytesseract.image_to_string(img, config='--psm 7').strip()
        print(f"\nName {i + 1}: {text}")
        corrected_name = input("Press Enter if correct, or type the correct name: ").strip()
        final_name = corrected_name if corrected_name else text
        names.append(final_name)
    return names

def main_application():
    player_names = get_player_names()

    # Retrieve player IDs concurrently
    with ThreadPoolExecutor() as executor:
        id_futures = {executor.submit(get_player_id, name): name for name in player_names}
        player_ids = {}
        for future in as_completed(id_futures):
            name = id_futures[future]
            player_id = future.result()
            if player_id:
                player_ids[name] = player_id

    # Process player data concurrently
    results = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_player_data, pid, name): name for name, pid in player_ids.items()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    # Print final results
    print("\n--- Player List ---")
    for res in results:
        print(
            f"\nPlayer Name: {res['player_name']}\n"
            f"Player Rank: {res['rank']}\n"
            f"Top 3 Heroes: {res['top_heroes']}\n"
            f"Most Used Hero: {res['most_used_hero']} | Win/Loss: {res['win_loss']}\n"
            f"Updated: {res['updated']}"
        )

    # Save results to file
    with open("players_top_heroes.txt", "w") as outfile:
        json.dump(results, outfile, indent=2)
    print("\nResults saved to players_top_heroes.txt")
    time.sleep(1200)

def get_player_id(player_name):
    try:
        url = f'https://mrapi.org/api/player-id/{player_name}'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get("id")
    except requests.exceptions.RequestException:
        return None

def process_player_data(player_id, player_name):
    try:
        url = f'https://mrapi.org/api/player/{player_id}'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        player_rank = data.get("stats", {}).get("rank", {}).get("rank", "Unknown")
        hero_stats = data.get("hero_stats", {})
        heroes = sorted(
            [
                (h["hero_name"], h.get("ranked", {}).get("playtime", {}).get("raw", 0))
                for h in hero_stats.values()
            ],
            key=lambda x: x[1],
            reverse=True
        )[:3]
        top_heroes_str = ", ".join(f"{hero[0]} ({round(hero[1]/3600)} hrs)" for hero in heroes)

        url = f"https://mrapi.org/api/player-match/{player_id}"
        response = requests.get(url)
        response.raise_for_status()
        matches = response.json()[:10]

        hero_counts = Counter()
        wins, losses = 0, 0
        for match in matches:
            hero_id = match.get("stats", {}).get("hero", {}).get("id")
            if hero_id:
                hero_counts[hero_id] += 1
            if match.get("stats", {}).get("is_win", False):
                wins += 1
            else:
                losses += 1

        most_used_hero_id = hero_counts.most_common(1)[0][0] if hero_counts else None
        most_used_hero = hero_id_to_name.get(most_used_hero_id, f"Hero ID: {most_used_hero_id}")
        total_games = wins + losses
        win_percentage = round((wins / total_games) * 100) if total_games > 0 else 0

        return {
            "player_name": player_name,
            "rank": player_rank,
            "top_heroes": top_heroes_str,
            "most_used_hero": most_used_hero,
            "win_loss": f"{wins}/{losses} ({win_percentage}%)",
            "updated": True
        }
    except Exception as e:
        print(f"Error processing player {player_name}: {e}")
        return None

def main(): # Run this once to generate the encrypted key
    check_and_activate_license()

if __name__ == "__main__":
    main()
