import json
import sqlite3
import time
from datetime import datetime, timedelta
import html

import requests

# WordPress site and credentials
site_url = "https://socca.tech"
api_url = f"{site_url}/wp-json/wp/v2/posts"
categories_url = f"{site_url}/wp-json/wp/v2/categories"
username = "ianrelecker"
password = "nRTX y8ZZ vEXp B2W7 7z0t S84g"

# Authentication setup for basic auth
auth = (username, password)


def getcontent(cve_id):

    post_title = cve_id  # Replace with the title of the post

    # WordPress API endpoint for searching posts
    search_endpoint = f"{site_url}/wp-json/wp/v2/posts"

    # Search for the post by title
    params = {"search": post_title}
    response = requests.get(search_endpoint, params=params, auth=auth)

    # Check the response
    if response.status_code == 200:
        posts = response.json()
        # Find the post with the exact title
        for post in posts:
            if post.get('title', {}).get('rendered') == post_title:
                content = post.get('content', {}).get('rendered', '')
                published_date = post.get('date', '')
                #print(f"Title: {post_title}")
                #print(f"Content: {content}")
                #print(f"pub: {published_date}")

                break
        else:
            print(f"Post with title '{post_title}' not found.")
    else:
        print(f"Failed to search posts. Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    return content, published_date


# Function to create a post
def create_post(api_url, wpid, cve_id):
    try:
        update_url = f"{api_url}/{wpid}"
        content, publish = getcontent(cve_id)
        kevwarm = '<div style="color: red;">This CVE is on the <a href="https://www.cisa.gov/known-exploited-vulnerabilities" target="_blank" style="color: #004085;">Known Exploited Vulnerabilities list</a></div>'
        if str(content).startswith('<div style="color: red;">This CVE is on the'):
            print("yes:"+str(content)[:35])
        else:
            print("no:" + str(content)[:35])
            content = str(kevwarm) + str(content)
            cat = [1366]
            post_data = {
                "title": str(cve_id),
                "content": content,
                "status": "publish",  # Options: 'publish', 'draft', 'pending', etc.
                "categories": cat,
                "date": publish
            }
            print(update_url)
            # time.sleep(60)
            # Perform the API request using PUT
            response = requests.post(
                update_url,
                json=post_data,
                auth=auth
            )

            # Check for successful response
            if response.status_code == 200:  # 201 Created
                print("Post created successfully.")
                print("Post URL:", response.json()["link"])
            else:
                print("Failed to create post:", response.status_code)
                print(response.json())  # Print error details




    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
    #time.sleep(60)
    


def getpostid(cve_id):
    search_title = "Post Title"  # Replace with the post title
    print("id"+cve_id)
    response = requests.get(
        f"{api_url}?search={cve_id}",
        auth=auth
    )
    if response.status_code == 200:
        posts = response.json()
        for post in posts:
            print(f"Post ID: {post['id']}, Title: {post['title']['rendered']}")
    else:
        print(f"Failed to search posts. HTTP Status Code: {response.status_code}")

    return post['id']

def main():
    # Poll continuously
    conn = sqlite3.connect('kev_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM kev_entries")
    kevs = cursor.fetchall()

    for kev in kevs:
        create_post(api_url, getpostid(kev[0]), kev[0])
        print(kev[0])


# Run the function to create the post
#create_post(api_url, post_data, auth)
#newcvepost("CVE-2024-50589")
main()