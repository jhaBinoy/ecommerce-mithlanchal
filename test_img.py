from b2sdk.v2 import B2Api, InMemoryAccountInfo

b2_api = B2Api(InMemoryAccountInfo())
b2_api.authorize_account("production", "your_key_id", "your_application_key")
bucket = b2_api.get_bucket_by_name('mithlanchal-images')
signed_url = bucket.get_download_url('products/674957e422304b9bb8502839423885f2.jpg', valid_duration_in_seconds=3600)
print(signed_url)