import requests
import json
import os
from datetime import datetime, timedelta

# PhishTank database URL (raw content from GitHub)
PHISHTANK_URL = "https://raw.githubusercontent.com/ProKn1fe/phishtank-database/master/online-valid.json"
LOCAL_FILE = "online-valid.json"
UPDATE_INTERVAL_HOURS = 24  # Update if file is older than 24 hours


def download_phishtank_data():
    """
    Download the latest PhishTank database from GitHub.
    Returns True if download is successful, False otherwise.
    """
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Downloading PhishTank database...")
    
    try:
        response = requests.get(PHISHTANK_URL, timeout=30)
        response.raise_for_status()  # Raise an error for bad status codes
        
        # Save the JSON data to a local file
        with open(LOCAL_FILE, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Successfully downloaded PhishTank database.")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Saved to: {LOCAL_FILE}")
        return True
    
    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error downloading PhishTank data: {e}")
        return False


def is_database_outdated():
    """
    Check if the local PhishTank database is outdated.
    Returns True if file doesn't exist or is older than UPDATE_INTERVAL_HOURS.
    """
    if not os.path.exists(LOCAL_FILE):
        return True
    
    # Get file modification time
    file_mtime = os.path.getmtime(LOCAL_FILE)
    file_age = datetime.now() - datetime.fromtimestamp(file_mtime)
    
    return file_age > timedelta(hours=UPDATE_INTERVAL_HOURS)


def auto_update_database():
    """
    Automatically update the PhishTank database if it's outdated.
    Returns True if database is up-to-date (either was already fresh or successfully updated).
    """
    if is_database_outdated():
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Database is outdated or missing. Updating...")
        return download_phishtank_data()
    else:
        file_mtime = os.path.getmtime(LOCAL_FILE)
        file_date = datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Database is up-to-date (last updated: {file_date})")
        return True


def load_phishtank_data():
    """
    Load the PhishTank database from the local JSON file.
    Returns a list of phishing URLs or None if file doesn't exist.
    """
    if not os.path.exists(LOCAL_FILE):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] PhishTank database file not found!")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Please run download_phishtank_data() first.")
        return None
    
    try:
        with open(LOCAL_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Loaded {len(data)} phishing URLs from database.")
        return data
    
    except json.JSONDecodeError as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error parsing JSON file: {e}")
        return None
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error loading PhishTank data: {e}")
        return None


def check_url_in_phishtank(url, phishtank_data=None):
    """
    Check if a given URL exists in the PhishTank database.
    
    Args:
        url (str): The URL to check
        phishtank_data (list): Optional. Pre-loaded PhishTank data. 
                              If None, will load from file.
    
    Returns:
        dict: A dictionary with 'is_phishing' (bool) and 'message' (str)
    """
    # Load data if not provided
    if phishtank_data is None:
        phishtank_data = load_phishtank_data()
        if phishtank_data is None:
            return {
                'is_phishing': False,
                'message': 'Error: Could not load PhishTank database'
            }
    
    # Normalize the URL for comparison
    url_normalized = url.strip().lower()
    
    # Check if URL exists in the database
    for entry in phishtank_data:
        # PhishTank entries typically have a 'url' field
        phish_url = entry.get('url', '').strip().lower()
        
        if phish_url == url_normalized:
            return {
                'is_phishing': True,
                'message': f'⚠️ WARNING: This URL is FLAGGED as a known PHISHING URL in PhishTank database!',
                'phish_id': entry.get('phish_id', 'N/A'),
                'verified': entry.get('verified', 'N/A'),
                'submission_time': entry.get('submission_time', 'N/A')
            }
    
    return {
        'is_phishing': False,
        'message': '✓ This URL is not found in the PhishTank database (does not mean it\'s safe)'
    }


def check_multiple_urls(urls, phishtank_data=None):
    """
    Check multiple URLs against the PhishTank database.
    
    Args:
        urls (list): List of URLs to check
        phishtank_data (list): Optional. Pre-loaded PhishTank data.
    
    Returns:
        list: List of results for each URL
    """
    if phishtank_data is None:
        phishtank_data = load_phishtank_data()
        if phishtank_data is None:
            return []
    
    results = []
    for url in urls:
        result = check_url_in_phishtank(url, phishtank_data)
        result['url'] = url
        results.append(result)
    
    return results


# Main execution example
if __name__ == "__main__":
    print("=" * 60)
    print("PhishTank URL Checker")
    print("=" * 60)
    
    # Step 1: Download the latest PhishTank database
    if download_phishtank_data():
        print()
        
        # Step 2: Load the database
        phishtank_data = load_phishtank_data()
        
        if phishtank_data:
            print()
            
            # Step 3: Test with example URLs
            print("-" * 60)
            print("Testing URL checking functionality:")
            print("-" * 60)
            
            # You can test with actual URLs here
            test_urls = [
                "https://www.google.com",  # Safe URL (probably not in PhishTank)
                # Add actual phishing URLs from the database to test
            ]
            
            for test_url in test_urls:
                result = check_url_in_phishtank(test_url, phishtank_data)
                print(f"\nURL: {test_url}")
                print(f"Status: {result['message']}")
                if result['is_phishing']:
                    print(f"Phish ID: {result.get('phish_id', 'N/A')}")
                    print(f"Verified: {result.get('verified', 'N/A')}")
            
            print()
            print("=" * 60)
            print("Interactive Mode: Enter a URL to check (or 'quit' to exit)")
            print("=" * 60)
            
            while True:
                user_input = input("\nEnter URL: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("Exiting...")
                    break
                
                if not user_input:
                    continue
                
                result = check_url_in_phishtank(user_input, phishtank_data)
                print(f"\n{result['message']}")
                
                if result['is_phishing']:
                    print(f"Phish ID: {result.get('phish_id', 'N/A')}")
                    print(f"Verified: {result.get('verified', 'N/A')}")
                    print(f"Submission Time: {result.get('submission_time', 'N/A')}")
