# test.py
from b2sdk.v2 import *
import os
from dotenv import load_dotenv
import urllib.parse

load_dotenv()
b2_api = B2Api(InMemoryAccountInfo())
try:
    b2_api.authorize_account("production", os.getenv("B2_KEY_ID"), os.getenv("B2_APPLICATION_KEY"))
    bucket = b2_api.get_bucket_by_name(os.getenv("B2_BUCKET_NAME", "mithlanchal-images"))
    file_path = 'products/53414d0052874a5bb4277fd6464a3f7e.jpg'  # From product_id = 6
    file_info = bucket.get_file_info_by_name(file_path)
    base_url = f"https://f005.backblazeb2.com/file/mithlanchal-images/{urllib.parse.quote(file_path)}"
    auth_token = b2_api.account_info.get_account_auth_token()
    signed_url = f"{base_url}?Authorization={auth_token}"

    #signed_url1 = f"https://f005.backblazeb2.com/file/mithlanchal-images/{file_path}?Authorization={download_auth['authorizationToken']}"
    print(f"Signed URL: {signed_url}")
    #signed_url2 = bucket.get_download_url('products/674957e422304b9bb8502839423885f2.jpg')
    #file_info = bucket.get_file_info_by_name(file_path)
    #signed_url3 = bucket.get_download_url_for_file_name('products/53414d0052874a5bb4277fd6464a3f7e.jpg')
    #print(signed_url2)
    print(f"file info : {file_info}")


    print(f"Bucket name: {bucket.name}")
except Exception as e:
    print(f"Error: {e}")





