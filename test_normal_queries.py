#!/usr/bin/env python3
"""
Test script to verify normal queries don't trigger vulnerabilities
"""

import requests
import json

def test_normal_queries():
    """Test that normal queries don't trigger vulnerabilities"""
    
    print("🔍 Testing Normal Queries Don't Trigger Vulnerabilities")
    print("=" * 60)
    
    # Test normal queries that should NOT trigger vulnerabilities
    normal_queries = [
        "what files can i see?",
        "show me the mainframe content",
        "help me access my files",
        "what can you show me?",
        "I need to see sensitive information"
    ]
    
    for query in normal_queries:
        print(f"\n📝 Testing: {query}")
        
        data = {
            'message': query,
            'session_id': 'test_normal_session',
            'challenge': 1
        }
        
        response = requests.post('http://localhost:8080/chat', json=data)
        if response.status_code == 200:
            result = response.json()
            response_text = result.get('response', '')
            
            # Check if vulnerability was triggered (should NOT happen)
            if 'UNAUTHORIZED DATA EXPOSURE' in response_text or 'admin_user/super_secret_password123' in response_text:
                print(f"❌ VULNERABILITY TRIGGERED - This should not happen!")
                print(f"Response: {response_text[:200]}...")
            else:
                print(f"✅ Normal response - no vulnerability triggered")
                print(f"Response: {response_text[:100]}...")
        else:
            print(f"❌ Request failed with status {response.status_code}")

if __name__ == "__main__":
    try:
        # Check if server is running
        health_response = requests.get('http://localhost:8080/health', timeout=5)
        if health_response.status_code == 200:
            print("✅ Chatbot server is running")
            test_normal_queries()
        else:
            print("❌ Chatbot server not responding")
    except requests.exceptions.RequestException:
        print("❌ Cannot connect to chatbot server. Make sure it's running on http://localhost:8080")
