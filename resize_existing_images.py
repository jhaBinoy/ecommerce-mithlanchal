from PIL import Image
import os

upload_folder = 'static/uploads'
for filename in os.listdir(upload_folder):
    filepath = os.path.join(upload_folder, filename)
    if os.path.isfile(filepath):
        try:
            img = Image.open(filepath)
            img = img.resize((300, 300), Image.Resampling.LANCZOS)
            img.save(filepath, quality=85)
            print(f"Resized {filename}")
        except Exception as e:
            print(f"Error resizing {filename}: {e}")