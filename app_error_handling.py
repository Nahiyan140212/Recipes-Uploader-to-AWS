import streamlit as st
import boto3
import json
import os
import uuid
import datetime
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from PIL import Image
import io
import hmac
import hashlib
import base64

# Function to get secrets from either Streamlit Cloud or local .env file
def get_secret(key, default=None):
    # Try to get from Streamlit secrets
    if key in st.secrets:
        return st.secrets[key]
    
    # If not in Streamlit secrets, try local .env file (for development)
    load_dotenv()
    return os.getenv(key, default)

# AWS Credentials
AWS_ACCESS_KEY = get_secret('AWS_ACCESS_KEY')
AWS_SECRET_KEY = get_secret('AWS_SECRET_KEY')
S3_BUCKET_NAME = get_secret('S3_BUCKET_NAME')
DYNAMODB_TABLE_NAME = get_secret('DYNAMODB_TABLE_NAME')
AWS_REGION = get_secret('AWS_REGION', 'us-east-1')

# Cognito Settings
COGNITO_USER_POOL_ID = get_secret('COGNITO_USER_POOL_ID')
COGNITO_APP_CLIENT_ID = get_secret('COGNITO_APP_CLIENT_ID')
COGNITO_APP_CLIENT_SECRET = get_secret('COGNITO_APP_CLIENT_SECRET')

# Initialize AWS services
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)
recipe_table = dynamodb.Table(DYNAMODB_TABLE_NAME)
user_table = dynamodb.Table('recipe_app_users')  # Additional table for user data

# --- Helper Functions for S3 and File Uploads ---

def check_and_fix_s3_urls(url):
    """
    Ensure S3 URLs are properly formatted for embedding in Streamlit
    """
    if not url:
        return url
        
    # Ensure the URL uses HTTPS
    if url.startswith('http://'):
        url = url.replace('http://', 'https://')
    
    # Add missing protocol if needed
    if not url.startswith('https://'):
        url = f"https://{url}"
    
    return url

def upload_file_to_s3(file, file_name, content_type):
    """Upload a file to S3 bucket with proper permissions and return the URL"""
    try:
        # Set content disposition to force browser to display/download
        content_disposition = 'inline' if content_type.startswith('image/') else 'attachment'
        
        s3_client.upload_fileobj(
            file,
            S3_BUCKET_NAME,
            file_name,
            ExtraArgs={
                'ContentType': content_type,
                'ACL': 'public-read',  # Make object public
                'ContentDisposition': f'{content_disposition}; filename="{os.path.basename(file_name)}"'
            }
        )
        
        # Return properly formatted URL
        return f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{file_name}"
    except Exception as e:
        st.error(f"Error uploading file to S3: {e}")
        return None

# def upload_large_file_to_s3(file, bucket, object_name):
#     """
#     Upload a large file to S3 using multipart upload
    
#     :param file: File to upload
#     :param bucket: Bucket to upload to
#     :param object_name: S3 object name
#     :return: True if file was uploaded, else False
#     """
#     # Save the uploaded file to a temporary file
#     with tempfile.NamedTemporaryFile(delete=False) as tmp:
#         # Copy the file data to the temporary file
#         shutil.copyfileobj(file, tmp)
#         tmp_filename = tmp.name
    
#     # Create S3 client
#     s3_client = boto3.client(
#         's3',
#         aws_access_key_id=AWS_ACCESS_KEY,
#         aws_secret_access_key=AWS_SECRET_KEY,
#         region_name=AWS_REGION
#     )
    
#     # Upload the file using multipart upload
#     try:
#         # Create a multipart upload
#         response = s3_client.create_multipart_upload(
#             Bucket=bucket,
#             Key=object_name,
#             ContentType=file.type,
#             ACL='public-read'  # Make the object publicly readable
#         )
#         upload_id = response['UploadId']
        
#         # Get file size
#         file_size = os.path.getsize(tmp_filename)
        
#         # Define chunk size (5MB is the minimum allowed by S3)
#         chunk_size = 5 * 1024 * 1024
        
#         # Calculate number of parts
#         num_parts = (file_size // chunk_size) + 1
        
#         # Progress bar for upload
#         progress_bar = st.progress(0)
#         status_text = st.empty()
        
#         # Upload parts
#         parts = []
        
#         def upload_part(part_number):
#             # Calculate start and end positions
#             start = (part_number - 1) * chunk_size
#             end = min(start + chunk_size, file_size)
            
#             # Read part data
#             with open(tmp_filename, 'rb') as f:
#                 f.seek(start)
#                 part_data = f.read(end - start)
            
#             # Upload part
#             response = s3_client.upload_part(
#                 Body=part_data,
#                 Bucket=bucket,
#                 Key=object_name,
#                 PartNumber=part_number,
#                 UploadId=upload_id
#             )
            
#             # Update progress
#             progress = int((part_number / num_parts) * 100)
#             progress_bar.progress(progress / 100)
#             status_text.text(f"Uploading: {progress}% complete")
            
#             # Return part information
#             return {
#                 'PartNumber': part_number,
#                 'ETag': response['ETag']
#             }
        
#         # Use ThreadPoolExecutor for parallel uploads
#         with ThreadPoolExecutor(max_workers=4) as executor:
#             parts = list(executor.map(upload_part, range(1, num_parts + 1)))
        
#         # Complete the multipart upload
#         s3_client.complete_multipart_upload(
#             Bucket=bucket,
#             Key=object_name,
#             MultipartUpload={'Parts': parts},
#             UploadId=upload_id
#         )
        
#         # Clean up temporary file
#         os.unlink(tmp_filename)
        
#         progress_bar.progress(1.0)
#         status_text.text("Upload complete!")
        
#         # Return the URL of the uploaded file
#         return f"https://{bucket}.s3.amazonaws.com/{object_name}"
    
#     except Exception as e:
#         # Abort the multipart upload if it was created
#         if 'upload_id' in locals():
#             s3_client.abort_multipart_upload(
#                 Bucket=bucket,
#                 Key=object_name,
#                 UploadId=upload_id
#             )
        
#         # Clean up temporary file
#         if os.path.exists(tmp_filename):
#             os.unlink(tmp_filename)
        
#         st.error(f"Error uploading file: {e}")
#         return None

def compress_video(input_file, max_size_mb=200):
    """
    Compress video file to keep it under the specified maximum size
    Returns path to compressed video file
    """
    import cv2
    import os
    import tempfile
    import math
    from moviepy.editor import VideoFileClip

    # Create a temporary file for the compressed video
    temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')
    temp_output_path = temp_output.name
    temp_output.close()
    
    try:
        # Get original video info
        clip = VideoFileClip(input_file)
        original_duration = clip.duration
        original_size = os.path.getsize(input_file) / (1024 * 1024)  # Size in MB
        
        # Calculate target bitrate (rule of thumb: size in bits / duration in seconds = bitrate)
        # Target size in bits = max_size_mb * 8 * 1024 * 1024 (convert MB to bits)
        # Apply a 0.9 factor to ensure we stay under the limit (accounting for container overhead)
        target_size_bits = max_size_mb * 8 * 1024 * 1024 * 0.9
        target_bitrate = int(target_size_bits / original_duration)
        
        # Minimum bitrate to maintain reasonable quality (500 Kbps)
        min_bitrate = 500 * 1024
        if target_bitrate < min_bitrate:
            target_bitrate = min_bitrate
            # If we can't achieve the target size with minimum quality, we'll reduce resolution
            
        # Calculate resolution scaling factor if necessary
        scale_factor = 1.0
        if target_bitrate < min_bitrate:
            # Estimate how much we need to reduce resolution to meet size requirements
            # Since file size roughly scales with pixel count, we can adjust resolution
            excess_ratio = math.sqrt(original_size / max_size_mb)
            scale_factor = 1.0 / excess_ratio
            # Cap the minimum scale to 0.5 (half resolution)
            scale_factor = max(0.5, scale_factor)
        
        # Get original dimensions
        width, height = clip.size
        
        # Calculate new dimensions if scaling is needed
        new_width = int(width * scale_factor)
        new_height = int(height * scale_factor)
        
        # Ensure dimensions are even (required by some codecs)
        new_width = new_width if new_width % 2 == 0 else new_width - 1
        new_height = new_height if new_height % 2 == 0 else new_height - 1
        
        # Close the clip to free resources
        clip.close()
        
        # Create OpenCV VideoCapture and VideoWriter objects
        cap = cv2.VideoCapture(input_file)
        fps = cap.get(cv2.CAP_PROP_FPS)
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')  # H.264 codec
        out = cv2.VideoWriter(temp_output_path, fourcc, fps, (new_width, new_height))
        
        # Process the video
        while True:
            ret, frame = cap.read()
            if not ret:
                break
                
            # Resize frame if needed
            if scale_factor < 1.0:
                frame = cv2.resize(frame, (new_width, new_height))
                
            out.write(frame)
        
        # Release resources
        cap.release()
        out.release()
        
        # Check compressed size
        compressed_size = os.path.getsize(temp_output_path) / (1024 * 1024)
        compression_ratio = original_size / compressed_size if compressed_size > 0 else 0
        
        return {
            'path': temp_output_path,
            'original_size_mb': original_size,
            'compressed_size_mb': compressed_size,
            'compression_ratio': compression_ratio,
            'new_width': new_width,
            'new_height': new_height
        }
    
    except Exception as e:
        # Clean up on error
        if os.path.exists(temp_output_path):
            os.unlink(temp_output_path)
        raise e

# Modified process_video_upload function that includes compression
def process_video_upload(video_file, recipe_id):
    """Process video upload with compression for large files"""
    if video_file:
        video_extension = video_file.name.split('.')[-1]
        video_filename = f"videos/{recipe_id}.mp4"  # Always use mp4 for consistency
        
        # Check file size
        file_size_mb = video_file.size / (1024 * 1024)
        
        if file_size_mb > 200:
            st.warning(f"""
            Your video is {file_size_mb:.1f} MB, which exceeds our limit of 200 MB.
            We'll automatically compress the video to reduce its size.
            """)
            
            # Save uploaded file to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{video_extension}') as tmp:
                shutil.copyfileobj(video_file, tmp)
                tmp_filename = tmp.name
            
            try:
                # Show compression progress indicator
                with st.spinner("Compressing video... This may take a while."):
                    # Compress the video
                    compression_result = compress_video(tmp_filename)
                
                # Show compression results
                st.success(f"""
                Video compressed successfully:
                - Original: {compression_result['original_size_mb']:.1f} MB
                - Compressed: {compression_result['compressed_size_mb']:.1f} MB
                - Compression ratio: {compression_result['compression_ratio']:.1f}x
                - New resolution: {compression_result['new_width']}x{compression_result['new_height']}
                """)
                
                # Upload the compressed file
                with open(compression_result['path'], 'rb') as compressed_file:
                    video_url = upload_file_to_s3(
                        compressed_file, 
                        video_filename, 
                        "video/mp4"
                    )
                
                # Clean up temporary files
                os.unlink(tmp_filename)
                os.unlink(compression_result['path'])
                
            except Exception as e:
                st.error(f"Error compressing video: {e}")
                # Clean up
                if os.path.exists(tmp_filename):
                    os.unlink(tmp_filename)
                # Fall back to YouTube recommendation
                st.error("Video compression failed. Please consider uploading to YouTube instead.")
                return None
        else:
            # For smaller videos, use the regular upload
            video_url = upload_file_to_s3(
                video_file, 
                video_filename, 
                f"video/mp4"
            )
        
        return video_url
    return None

def test_s3_access():
    """Test S3 bucket access and configurations"""
    st.subheader("S3 Bucket Access Test")
    
    try:
        # List bucket objects
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, MaxKeys=5)
        
        if 'Contents' in response:
            st.success(f"Successfully connected to S3 bucket '{S3_BUCKET_NAME}'")
            st.write("Sample objects in bucket:")
            for item in response['Contents'][:5]:
                st.write(f"- {item['Key']}")
        else:
            st.warning(f"Connected to bucket '{S3_BUCKET_NAME}' but it appears to be empty")
            
        # Test public access
        st.write("Testing public access permissions...")
        test_object_key = f"test/access_test_{uuid.uuid4()}.txt"
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=test_object_key,
            Body="Test file to check public access",
            ACL='public-read'
        )
        
        test_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{test_object_key}"
        st.write(f"Test URL: [Access Test]({test_url})")
        
        # Clean up test object after a delay
        s3_client.delete_object(
            Bucket=S3_BUCKET_NAME,
            Key=test_object_key
        )
        
    except Exception as e:
        st.error(f"Error testing S3 access: {e}")
        st.write("Check your AWS credentials and bucket permissions")

# --- Authentication Functions ---

def get_cognito_secret_hash(username):
    """Generate a secret hash for Cognito authentication"""
    message = username + COGNITO_APP_CLIENT_ID
    dig = hmac.new(
        str(COGNITO_APP_CLIENT_SECRET).encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def register_user(username, email, password):
    """Register a new user with Cognito"""
    try:
        # Create a boto3 client for Cognito
        cognito_client = boto3.client(
            'cognito-idp',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
        
        # Calculate the secret hash
        secret_hash = get_cognito_secret_hash(username)
        
        # Sign up the user with the secret hash
        response = cognito_client.sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            SecretHash=secret_hash,
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': email
                }
            ]
        )
        
        # Save additional user data in DynamoDB
        user_data = {
            'username': username,
            'email': email,
            'created_at': datetime.datetime.now().isoformat(),
            'user_id': str(uuid.uuid4())
        }
        user_table.put_item(Item=user_data)
        
        return True, "Registration successful! Please check your email for verification code."
    except Exception as e:
        return False, str(e)

def verify_user(username, verification_code):
    """Verify a user with the code sent to their email"""
    try:
        cognito_client = boto3.client(
            'cognito-idp',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
        
        # Calculate the secret hash
        secret_hash = get_cognito_secret_hash(username)
        
        # Confirm sign up with the secret hash
        response = cognito_client.confirm_sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            SecretHash=secret_hash,
            Username=username,
            ConfirmationCode=verification_code
        )
        
        return True, "Email verified successfully! You can now login."
    except Exception as e:
        return False, str(e)

def login_user(username, password):
    """Authenticate a user with Cognito"""
    try:
        cognito_client = boto3.client(
            'cognito-idp',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
        
        # Calculate the secret hash
        secret_hash = get_cognito_secret_hash(username)
        
        # Initiate auth with the secret hash
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        
        id_token = response['AuthenticationResult']['IdToken']
        access_token = response['AuthenticationResult']['AccessToken']
        refresh_token = response['AuthenticationResult']['RefreshToken']
        
        return True, id_token, access_token, refresh_token, None
    except Exception as e:
        return False, None, None, None, str(e)

def get_user_info(username):
    """Get user information from DynamoDB"""
    try:
        response = user_table.get_item(Key={'username': username})
        return response.get('Item', {})
    except Exception as e:
        st.error(f"Error retrieving user data: {e}")
        return {}

# --- Recipe functions ---

def generate_unique_id():
    """Generate a unique ID for the recipe"""
    return str(uuid.uuid4())

def save_recipe_to_dynamodb(recipe_data):
    """Save recipe data to DynamoDB"""
    try:
        recipe_table.put_item(Item=recipe_data)
        return True
    except Exception as e:
        st.error(f"Error saving to DynamoDB: {e}")
        return False

def get_recipe_by_id(recipe_id):
    """Get a recipe by its ID"""
    try:
        response = recipe_table.get_item(Key={'recipe_id': recipe_id})
        return response.get('Item')
    except Exception as e:
        st.error(f"Error retrieving recipe: {e}")
        return None

def delete_recipe(recipe_id):
    """Delete a recipe from DynamoDB and associated files from S3"""
    try:
        # Get the recipe first to find associated files
        recipe = get_recipe_by_id(recipe_id)
        
        if not recipe:
            return False, "Recipe not found"
        
        # Delete the recipe from DynamoDB
        recipe_table.delete_item(Key={'recipe_id': recipe_id})
        
        # Delete associated files from S3
        try:
            # Get image and video URLs if they exist
            image_url = recipe.get('image_url')
            video_url = recipe.get('video_url')
            
            # Delete image if it exists
            if image_url and S3_BUCKET_NAME in image_url:
                # Extract the key from the URL
                image_key = image_url.split(f"{S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
                s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=image_key)
            
            # Delete video if it exists
            if video_url and S3_BUCKET_NAME in video_url:
                # Extract the key from the URL
                video_key = video_url.split(f"{S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
                s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=video_key)
        except Exception as e:
            st.warning(f"Error deleting associated files: {e}")
            # Continue with recipe deletion even if file deletion fails
        
        return True, "Recipe deleted successfully"
    except Exception as e:
        return False, str(e)

def update_recipe(recipe_data):
    """Update an existing recipe in DynamoDB"""
    try:
        # Make sure recipe exists
        existing_recipe = get_recipe_by_id(recipe_data['recipe_id'])
        if not existing_recipe:
            return False, "Recipe not found"
        
        # Update the recipe
        recipe_data['updated_at'] = datetime.datetime.now().isoformat()
        recipe_table.put_item(Item=recipe_data)
        return True, "Recipe updated successfully"
    except Exception as e:
        return False, str(e)

# --- Streamlit App ---
st.set_page_config(page_title="Recipe Manager", layout="wide")

# Initialize session state for auth
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'access_token' not in st.session_state:
    st.session_state.access_token = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'login'
if 'current_recipe_id' not in st.session_state:
    st.session_state.current_recipe_id = None
if 'recipe_to_delete' not in st.session_state:
    st.session_state.recipe_to_delete = None

# Sidebar navigation
def sidebar_menu():
    with st.sidebar:
        st.title("Recipe Manager")
        
        if st.session_state.authenticated:
            st.write(f"Welcome, {st.session_state.username}!")
            
            if st.button("My Recipes"):
                st.session_state.current_page = 'my_recipes'
            
            if st.button("Add New Recipe"):
                st.session_state.current_page = 'add_recipe'
            
            if st.button("Browse All Recipes"):
                st.session_state.current_page = 'browse'
                
            if st.button("My Profile"):
                st.session_state.current_page = 'profile'

            if st.button("Test S3 Connection"):
                st.session_state.current_page = 'test_s3'
                
            if st.button("Logout"):
                st.session_state.authenticated = False
                st.session_state.username = None
                st.session_state.access_token = None
                st.session_state.current_page = 'login'
                st.experimental_rerun()
        else:
            if st.button("Login"):
                st.session_state.current_page = 'login'
                
            if st.button("Register"):
                st.session_state.current_page = 'register'
                
            if st.button("Verify Account"):
                st.session_state.current_page = 'verify'

# Authentication Pages
def login_page():
    st.title("Login to Recipe Manager")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if username and password:
                success, id_token, access_token, refresh_token, error_msg = login_user(username, password)
                if success:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.access_token = access_token
                    st.session_state.current_page = 'my_recipes'
                    st.success("Login successful!")
                    st.experimental_rerun()
                else:
                    st.error(f"Login failed: {error_msg}")
            else:
                st.error("Please enter both username and password")

def register_page():
    st.title("Create an Account")
    
    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        password_confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if not (username and email and password and password_confirm):
                st.error("Please fill in all fields")
            elif password != password_confirm:
                st.error("Passwords do not match")
            else:
                success, message = register_user(username, email, password)
                if success:
                    st.success(message)
                    st.session_state.current_page = 'verify'
                    st.experimental_rerun()
                else:
                    st.error(f"Registration failed: {message}")

def verify_page():
    st.title("Verify Your Account")
    
    with st.form("verify_form"):
        username = st.text_input("Username")
        verification_code = st.text_input("Verification Code")
        submitted = st.form_submit_button("Verify")
        
        if submitted:
            if not (username and verification_code):
                st.error("Please enter both username and verification code")
            else:
                success, message = verify_user(username, verification_code)
                if success:
                    st.success(message)
                    st.session_state.current_page = 'login'
                    st.experimental_rerun()
                else:
                    st.error(f"Verification failed: {message}")

# Recipe Pages
def add_recipe_page():
    st.title("Add New Recipe")
    
    with st.form("recipe_form"):
        recipe_name = st.text_input("Recipe Name")
        description = st.text_area("Description")
        ingredients = st.text_area("Ingredients (one per line)")
        instructions = st.text_area("Instructions (step by step)")
        servings = st.number_input("Servings", min_value=1, value=4)
        cooking_time = st.number_input("Cooking Time (minutes)", min_value=1, value=30)
        
        # Categories and cuisine as dropdowns
        category_options = ["Main Course", "Dessert", "Appetizer", "Breakfast", "Lunch", "Dinner", "Snack", "Beverage", "Other"]
        category = st.selectbox("Category", category_options)
        
        cuisine_options = ["Bangladeshi", "Italian", "Chinese", "Mexican", "Indian", "American", "French", "Japanese", "Thai", "Mediterranean", "Other"]
        cuisine = st.selectbox("Cuisine", cuisine_options)
        
        difficulty_options = ["Easy", "Medium", "Hard"]
        difficulty = st.selectbox("Difficulty Level", difficulty_options)
        
        # Additional fields
        nutritional_info = st.text_area("Nutritional Information (optional)")
        
        allergen_options = ["Nuts", "Gluten", "Dairy", "Eggs", "Soy", "Shellfish", "Fish", "None"]
        allergens = st.multiselect("Allergens", allergen_options)
        
        dietary_options = ["Vegetarian", "Vegan", "Gluten-Free", "Dairy-Free", "Keto", "Low-Carb", "Paleo", "None"]
        dietary_restrictions = st.multiselect("Dietary Restrictions", dietary_options)
        
        tags = st.text_input("Tags (comma separated)")
        youtube_link = st.text_input("YouTube Link (optional)")
        
        # File uploads
        image_file = st.file_uploader("Upload Recipe Image", type=["jpg", "jpeg", "png"])
        video_file = st.file_uploader("Upload Recipe Video (optional)", type=["mp4", "mov", "avi"])
        
        # Handle large videos
        if video_file is not None:
            file_size_mb = video_file.size / (1024 * 1024)
            if file_size_mb > 200:
                st.warning(f"""
                Your video is {file_size_mb:.1f} MB, which exceeds the recommended size (200 MB).
                For better performance, consider:
                1. Uploading to YouTube and providing the link
                2. Compressing your video before uploading
                """)
        
        # Privacy settings
        is_public = st.checkbox("Make this recipe public", value=True)
        
        submitted = st.form_submit_button("Save Recipe")

    if submitted:
        if not recipe_name:
            st.error("Recipe Name is required!")
        else:
            # Generate unique ID for the recipe
            recipe_id = generate_unique_id()
            
            # Process image upload if provided
            image_url = None
            if image_file:
                image_extension = image_file.name.split('.')[-1]
                image_filename = f"images/{recipe_id}.{image_extension}"
                image_url = upload_file_to_s3(image_file, image_filename, f"image/{image_extension}")
            
            # Process video upload if provided
            video_url = None
            if video_file:
                video_url = process_video_upload(video_file, recipe_id)
            
            # Prepare recipe data
            recipe_data = {
                "recipe_id": recipe_id,
                "user_id": st.session_state.username,  # Associate recipe with user
                "recipe_name": recipe_name,
                "description": description,
                "ingredients": ingredients.split('\n') if ingredients else [],
                "instructions": instructions.split('\n') if instructions else [],
                "servings": servings,
                "cooking_time": cooking_time,
                "category": category,
                "cuisine": cuisine,
                "difficulty_level": difficulty,
                "nutritional_info": nutritional_info if nutritional_info else None,
                "allergens": allergens if allergens else [],
                "dietary_restrictions": dietary_restrictions if dietary_restrictions else [],
                "tags": [tag.strip() for tag in tags.split(',')] if tags else [],
                "youtube_link": youtube_link if youtube_link else None,
                "image_url": image_url,
                "video_url": video_url,
                "is_public": is_public,
                "created_at": datetime.datetime.now().isoformat(),
                "updated_at": datetime.datetime.now().isoformat()
            }
            
            # Save to DynamoDB
            if save_recipe_to_dynamodb(recipe_data):
                st.success(f"Recipe '{recipe_name}' saved successfully!")
                st.write("Recipe ID: ", recipe_id)
            else:
                st.error("Failed to save recipe. Please try again.")

def my_recipes_page():
    st.title("My Recipes")
    
    try:
        # Query DynamoDB for user's recipes
        response = recipe_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('user_id').eq(st.session_state.username)
        )
        recipes = response.get('Items', [])
        
        if not recipes:
            st.info("You haven't created any recipes yet.")
            if st.button("Create Your First Recipe"):
                st.session_state.current_page = 'add_recipe'
                st.experimental_rerun()
        else:
            # Create columns for recipe cards
            col1, col2 = st.columns(2)
            
            # Display recipes in a grid
            for i, recipe in enumerate(recipes):
                with col1 if i % 2 == 0 else col2:
                    with st.container():
                        st.subheader(recipe['recipe_name'])
                        
                        # Display image if available
                        if recipe.get('image_url'):
                            try:
                                image_url = check_and_fix_s3_urls(recipe['image_url'])
                                st.image(image_url, use_column_width=True)
                            except Exception as e:
                                st.error(f"Error loading image: {e}")
                                st.write(f"Image URL: [View Image]({recipe['image_url']})")
                        
                        st.write(f"**Category:** {recipe['category']} | **Cuisine:** {recipe['cuisine']}")
                        st.write(f"**Difficulty:** {recipe['difficulty_level']} | **Time:** {recipe['cooking_time']} min")
                        
                        # Add buttons for actions
                        col_view, col_edit, col_delete = st.columns(3)
                        with col_view:
                            if st.button(f"View", key=f"view_{recipe['recipe_id']}"):
                                # Set recipe ID in session state and navigate to detail page
                                st.session_state.current_recipe_id = recipe['recipe_id']
                                st.session_state.current_page = 'recipe_detail'
                                st.experimental_rerun()
                        
                        with col_edit:
                            if st.button(f"Edit", key=f"edit_{recipe['recipe_id']}"):
                                # Set recipe ID in session state and navigate to edit page
                                st.session_state.current_recipe_id = recipe['recipe_id']
                                st.session_state.current_page = 'edit_recipe'
                                st.experimental_rerun()
                        
                        with col_delete:
                            if st.button(f"Delete", key=f"delete_{recipe['recipe_id']}"):
                                # Confirm deletion
                                st.session_state.recipe_to_delete = recipe['recipe_id']
                                st.session_state.current_page = 'confirm_delete'
                                st.experimental_rerun()
                        
                        st.markdown("---")
    
    except Exception as e:
        st.error(f"Error retrieving recipes: {e}")

def browse_recipes_page():
    st.title("Browse Recipes")
    
    # Add search and filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        search_term = st.text_input("Search recipes", "")
    with col2:
        category_filter = st.selectbox(
            "Filter by category",
            ["All Categories", "Main Course", "Dessert", "Appetizer", "Breakfast", "Lunch", "Dinner", "Snack", "Beverage", "Other"]
        )
    with col3:
        cuisine_filter = st.selectbox(
            "Filter by cuisine",
            ["All Cuisines", "Italian", "Chinese", "Mexican", "Indian", "American", "French", "Japanese", "Thai", "Mediterranean", "Other"]
        )
    
    # Additional filters in expandable section
    with st.expander("Advanced Filters"):
        col1, col2 = st.columns(2)
        with col1:
            difficulty_filter = st.multiselect(
                "Difficulty Level",
                ["Easy", "Medium", "Hard"]
            )
        with col2:
            dietary_filter = st.multiselect(
                "Dietary Restrictions",
                ["Vegetarian", "Vegan", "Gluten-Free", "Dairy-Free", "Keto", "Low-Carb", "Paleo"]
            )
    
    try:
        # Query DynamoDB for public recipes
        response = recipe_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('is_public').eq(True)
        )
        all_recipes = response.get('Items', [])
        
        # Apply filters
        filtered_recipes = all_recipes
        
        # Search term filter
        if search_term:
            filtered_recipes = [
                r for r in filtered_recipes if 
                search_term.lower() in r['recipe_name'].lower() or
                search_term.lower() in r.get('description', '').lower() or
                any(search_term.lower() in tag.lower() for tag in r.get('tags', []))
            ]
        
        # Category filter
        if category_filter != "All Categories":
            filtered_recipes = [r for r in filtered_recipes if r['category'] == category_filter]
        
        # Cuisine filter
        if cuisine_filter != "All Cuisines":
            filtered_recipes = [r for r in filtered_recipes if r['cuisine'] == cuisine_filter]
        
        # Difficulty filter
        if difficulty_filter:
            filtered_recipes = [r for r in filtered_recipes if r['difficulty_level'] in difficulty_filter]
        
        # Dietary restrictions filter
        if dietary_filter:
            filtered_recipes = [
                r for r in filtered_recipes if 
                any(restriction in r.get('dietary_restrictions', []) for restriction in dietary_filter)
            ]
        
        # Display results
        st.subheader(f"Found {len(filtered_recipes)} recipes")
        
        if not filtered_recipes:
            st.info("No recipes match your search criteria.")
        else:
            # Create columns for recipe cards
            col1, col2, col3 = st.columns(3)
            
            # Display recipes in a grid
            for i, recipe in enumerate(filtered_recipes):
                with col1 if i % 3 == 0 else col2 if i % 3 == 1 else col3:
                    with st.container():
                        st.subheader(recipe['recipe_name'])
                        
                        # Display image if available
                        if recipe.get('image_url'):
                            try:
                                image_url = check_and_fix_s3_urls(recipe['image_url'])
                                st.image(image_url, use_column_width=True)
                            except Exception as e:
                                st.write(f"Image URL: [View Image]({recipe['image_url']})")
                        
                        # Show recipe details
                        st.write(f"**By:** {recipe['user_id']}")
                        st.write(f"**Category:** {recipe['category']} | **Cuisine:** {recipe['cuisine']}")
                        st.write(f"**Difficulty:** {recipe['difficulty_level']} | **Time:** {recipe['cooking_time']} min")
                        
                        # Short description
                        if recipe.get('description'):
                            desc = recipe['description']
                            if len(desc) > 100:
                                desc = desc[:100] + "..."
                            st.write(desc)
                        
                        # View button
                        if st.button(f"View Recipe", key=f"view_{recipe['recipe_id']}"):
                            st.session_state.current_recipe_id = recipe['recipe_id']
                            st.session_state.current_page = 'recipe_detail'
                            st.experimental_rerun()
                        
                        st.markdown("---")
    
    except Exception as e:
        st.error(f"Error retrieving recipes: {e}")

def recipe_detail_page():
    """Show recipe details"""
    # Get recipe ID from session state
    recipe_id = st.session_state.current_recipe_id
    
    if not recipe_id:
        st.error("Recipe not found")
        return
    
    # Get recipe data
    recipe = get_recipe_by_id(recipe_id)
    
    if not recipe:
        st.error("Recipe not found")
        return
    
    # Display recipe
    st.title(recipe['recipe_name'])
    
    # Show author info
    st.write(f"Created by: **{recipe['user_id']}**")
    
    # Create two columns for layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Display image if available
        if recipe.get('image_url'):
            try:
                image_url = check_and_fix_s3_urls(recipe['image_url'])
                st.image(image_url, use_column_width=True)
            except Exception as e:
                st.write(f"Image URL: [View Image]({recipe['image_url']})")
        
        # Description
        if recipe.get('description'):
            st.subheader("Description")
            st.write(recipe['description'])
        
        # Ingredients
        st.subheader("Ingredients")
        if recipe.get('ingredients'):
            for ingredient in recipe['ingredients']:
                if ingredient.strip():  # Skip empty lines
                    st.write(f"- {ingredient}")
        else:
            st.write("No ingredients listed")
            
        # Instructions
        st.subheader("Instructions")
        if recipe.get('instructions'):
            for i, step in enumerate(recipe['instructions'], 1):
                if step.strip():  # Skip empty lines
                    st.write(f"**Step {i}:** {step}")
        else:
            st.write("No instructions listed")
        
        # Video if available
        if recipe.get('video_url'):
            st.subheader("Video")
            video_url = check_and_fix_s3_urls(recipe['video_url'])
            st.video(video_url)
        
        # YouTube link if available
        if recipe.get('youtube_link'):
            st.subheader("Video Tutorial")
            st.video(recipe['youtube_link'])
    
    with col2:
        # Recipe details in a card-like container
        with st.container():
            st.markdown("### Recipe Details")
            st.write(f"**Category:** {recipe['category']}")
            st.write(f"**Cuisine:** {recipe['cuisine']}")
            st.write(f"**Difficulty:** {recipe['difficulty_level']}")
            st.write(f"**Cooking Time:** {recipe['cooking_time']} minutes")
            st.write(f"**Servings:** {recipe['servings']}")
            
            # Dietary info
            if recipe.get('dietary_restrictions') and recipe['dietary_restrictions'] != ['None']:
                st.markdown("### Dietary Information")
                for diet in recipe['dietary_restrictions']:
                    st.write(f"- {diet}")
            
            # Allergens
            if recipe.get('allergens') and recipe['allergens'] != ['None']:
                st.markdown("### Allergens")
                for allergen in recipe['allergens']:
                    st.write(f"- {allergen}")
            
            # Nutritional info if available
            if recipe.get('nutritional_info'):
                st.markdown("### Nutritional Information")
                st.write(recipe['nutritional_info'])
            
            # Tags
            if recipe.get('tags'):
                st.markdown("### Tags")
                tags_str = ", ".join(recipe['tags'])
                st.write(tags_str)
    
    # Show edit/delete buttons for owner
    if recipe['user_id'] == st.session_state.username:
        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Edit Recipe"):
                st.session_state.current_page = 'edit_recipe'
                st.experimental_rerun()
        with col2:
            if st.button("Delete Recipe"):
                st.session_state.recipe_to_delete = recipe_id
                st.session_state.current_page = 'confirm_delete'
                st.experimental_rerun()
    
    # Back button
    st.markdown("---")
    if st.button("Back to Browse"):
        st.session_state.current_page = 'browse'
        st.experimental_rerun()

def edit_recipe_page():
    """Edit an existing recipe"""
    # Get recipe ID from session state
    recipe_id = st.session_state.current_recipe_id
    
    if not recipe_id:
        st.error("Recipe not found")
        return
    
    # Get recipe data
    recipe = get_recipe_by_id(recipe_id)
    
    if not recipe:
        st.error("Recipe not found")
        return
    
    # Check if user owns this recipe
    if recipe['user_id'] != st.session_state.username:
        st.error("You don't have permission to edit this recipe")
        return
    
    st.title(f"Edit Recipe: {recipe['recipe_name']}")
    
    with st.form("edit_recipe_form"):
        recipe_name = st.text_input("Recipe Name", value=recipe['recipe_name'])
        description = st.text_area("Description", value=recipe.get('description', ''))
        ingredients = st.text_area("Ingredients (one per line)", value='\n'.join(recipe.get('ingredients', [])))
        instructions = st.text_area("Instructions (step by step)", value='\n'.join(recipe.get('instructions', [])))
        servings = st.number_input("Servings", min_value=1, value=recipe.get('servings', 4))
        cooking_time = st.number_input("Cooking Time (minutes)", min_value=1, value=recipe.get('cooking_time', 30))
        
        # Categories and cuisine as dropdowns
        category_options = ["Main Course", "Dessert", "Appetizer", "Breakfast", "Lunch", "Dinner", "Snack", "Beverage", "Other"]
        category = st.selectbox("Category", category_options, index=category_options.index(recipe['category']) if recipe.get('category') in category_options else 0)
        
        cuisine_options = ["Italian", "Chinese", "Mexican", "Indian", "American", "French", "Japanese", "Thai", "Mediterranean", "Other"]
        cuisine = st.selectbox("Cuisine", cuisine_options, index=cuisine_options.index(recipe['cuisine']) if recipe.get('cuisine') in cuisine_options else 0)
        
        difficulty_options = ["Easy", "Medium", "Hard"]
        difficulty = st.selectbox("Difficulty Level", difficulty_options, index=difficulty_options.index(recipe['difficulty_level']) if recipe.get('difficulty_level') in difficulty_options else 0)
        
        # Additional fields
        nutritional_info = st.text_area("Nutritional Information (optional)", value=recipe.get('nutritional_info', ''))
        
        allergen_options = ["Nuts", "Gluten", "Dairy", "Eggs", "Soy", "Shellfish", "Fish", "None"]
        allergens = st.multiselect("Allergens", allergen_options, default=recipe.get('allergens', []))
        
        dietary_options = ["Vegetarian", "Vegan", "Gluten-Free", "Dairy-Free", "Keto", "Low-Carb", "Paleo", "None"]
        dietary_restrictions = st.multiselect("Dietary Restrictions", dietary_options, default=recipe.get('dietary_restrictions', []))
        
        tags = st.text_input("Tags (comma separated)", value=', '.join(recipe.get('tags', [])))
        youtube_link = st.text_input("YouTube Link (optional)", value=recipe.get('youtube_link', ''))
        
        # Show current image if available
        if recipe.get('image_url'):
            st.write("Current Image:")
            try:
                image_url = check_and_fix_s3_urls(recipe['image_url'])
                st.image(image_url, width=300)
            except Exception as e:
                st.write(f"Image URL: [View Image]({recipe['image_url']})")
        
        # File uploads
        st.write("Upload a new image to replace the current one (optional):")
        image_file = st.file_uploader("Upload Recipe Image", type=["jpg", "jpeg", "png"])
        
        # Show current video if available
        if recipe.get('video_url'):
            st.write("Current Video:")
            try:
                video_url = check_and_fix_s3_urls(recipe['video_url'])
                st.video(video_url)
            except Exception as e:
                st.write(f"Video URL: [View Video]({recipe['video_url']})")
        
        st.write("Upload a new video to replace the current one (optional):")
        video_file = st.file_uploader("Upload Recipe Video", type=["mp4", "mov", "avi"])
        
        # Handle large videos
        if video_file is not None:
            file_size_mb = video_file.size / (1024 * 1024)
            if file_size_mb > 200:
                st.warning(f"""
                Your video is {file_size_mb:.1f} MB, which exceeds the recommended size (200 MB).
                For better performance, consider:
                1. Uploading to YouTube and providing the link
                2. Compressing your video before uploading
                """)
        
        # Privacy settings
        is_public = st.checkbox("Make this recipe public", value=recipe.get('is_public', True))
        
        submitted = st.form_submit_button("Update Recipe")

    if submitted:
        if not recipe_name:
            st.error("Recipe Name is required!")
        else:
            # Process image upload if provided
            image_url = recipe.get('image_url')
            if image_file:
                # Delete old image if exists
                if image_url and S3_BUCKET_NAME in image_url:
                    try:
                        image_key = image_url.split(f"{S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
                        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=image_key)
                    except Exception as e:
                        st.warning(f"Error deleting old image: {e}")
                
                # Upload new image
                image_extension = image_file.name.split('.')[-1]
                image_filename = f"images/{recipe_id}.{image_extension}"
                image_url = upload_file_to_s3(image_file, image_filename, f"image/{image_extension}")
            
            # Process video upload if provided
            video_url = recipe.get('video_url')
            if video_file:
                # Delete old video if exists
                if video_url and S3_BUCKET_NAME in video_url:
                    try:
                        video_key = video_url.split(f"{S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
                        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=video_key)
                    except Exception as e:
                        st.warning(f"Error deleting old video: {e}")
                
                # Upload new video
                video_url = process_video_upload(video_file, recipe_id)
            
            # Prepare updated recipe data
            updated_recipe = {
                "recipe_id": recipe_id,
                "user_id": st.session_state.username,
                "recipe_name": recipe_name,
                "description": description,
                "ingredients": ingredients.split('\n') if ingredients else [],
                "instructions": instructions.split('\n') if instructions else [],
                "servings": servings,
                "cooking_time": cooking_time,
                "category": category,
                "cuisine": cuisine,
                "difficulty_level": difficulty,
                "nutritional_info": nutritional_info if nutritional_info else None,
                "allergens": allergens if allergens else [],
                "dietary_restrictions": dietary_restrictions if dietary_restrictions else [],
                "tags": [tag.strip() for tag in tags.split(',')] if tags else [],
                "youtube_link": youtube_link if youtube_link else None,
                "image_url": image_url,
                "video_url": video_url,
                "is_public": is_public,
                "created_at": recipe.get('created_at'),  # Preserve original creation date
                "updated_at": datetime.datetime.now().isoformat()
            }
            
            # Update in DynamoDB
            success, message = update_recipe(updated_recipe)
            if success:
                st.success(f"Recipe '{recipe_name}' updated successfully!")
                # Go back to recipe detail page
                st.session_state.current_page = 'recipe_detail'
                st.experimental_rerun()
            else:
                st.error(f"Failed to update recipe: {message}")

def confirm_delete_page():
    """Confirm recipe deletion"""
    recipe_id = st.session_state.recipe_to_delete
    
    if not recipe_id:
        st.error("No recipe selected for deletion")
        return
    
    # Get recipe data
    recipe = get_recipe_by_id(recipe_id)
    
    if not recipe:
        st.error("Recipe not found")
        return
    
    # Check if user owns this recipe
    if recipe['user_id'] != st.session_state.username:
        st.error("You don't have permission to delete this recipe")
        return
    
    st.title("Confirm Delete")
    st.warning(f"Are you sure you want to delete the recipe '{recipe['recipe_name']}'?")
    st.write("This action cannot be undone.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Yes, Delete"):
            success, message = delete_recipe(recipe_id)
            if success:
                st.success(message)
                # Clear recipe ID and go back to my recipes
                st.session_state.recipe_to_delete = None
                st.session_state.current_recipe_id = None
                st.session_state.current_page = 'my_recipes'
                st.experimental_rerun()
            else:
                st.error(f"Failed to delete recipe: {message}")
    with col2:
        if st.button("Cancel"):
            st.session_state.recipe_to_delete = None
            # Go back to recipe detail page
            st.session_state.current_page = 'recipe_detail'
            st.experimental_rerun()

def user_profile_page():
    """Display and edit user profile"""
    st.title("My Profile")
    
    # Get user info
    user_info = get_user_info(st.session_state.username)
    
    if not user_info:
        st.error("Unable to retrieve user information")
        return
    
    # Display current information
    st.subheader("Account Information")
    st.write(f"**Username:** {user_info['username']}")
    st.write(f"**Email:** {user_info['email']}")
    st.write(f"**Account Created:** {user_info['created_at']}")
    
    # Display user stats
    st.subheader("Recipe Stats")
    try:
        # Count user's recipes
        response = recipe_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('user_id').eq(st.session_state.username)
        )
        recipes = response.get('Items', [])
        
        total_recipes = len(recipes)
        public_recipes = sum(1 for r in recipes if r.get('is_public', False))
        private_recipes = total_recipes - public_recipes
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Recipes", total_recipes)
        with col2:
            st.metric("Public Recipes", public_recipes)
        with col3:
            st.metric("Private Recipes", private_recipes)
    except Exception as e:
        st.error(f"Error retrieving recipe stats: {e}")
    
    # Update profile section
    st.subheader("Update Profile")
    
    with st.form("update_profile"):
        new_email = st.text_input("Email", value=user_info['email'])
        bio = st.text_area("Bio", value=user_info.get('bio', ''))
        profile_visible = st.checkbox("Make profile public", value=user_info.get('profile_visible', False))
        
        submitted = st.form_submit_button("Update Profile")
        
        if submitted:
            try:
                # Update user info in DynamoDB
                updated_info = {
                    "username": user_info['username'],
                    "email": new_email,
                    "bio": bio,
                    "profile_visible": profile_visible,
                    "created_at": user_info['created_at'],
                    "updated_at": datetime.datetime.now().isoformat(),
                    "user_id": user_info['user_id']
                }
                
                user_table.put_item(Item=updated_info)
                st.success("Profile updated successfully!")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Error updating profile: {e}")
    
    # Change password section
    with st.expander("Change Password"):
        st.write("Password changes must be done through AWS Cognito. Please contact support for assistance.")
    
    # Delete account section
    with st.expander("Delete Account"):
        st.warning("Deleting your account will permanently remove all your recipes and data!")
        st.write("Account deletion must be processed through support.")
        if st.button("Request Account Deletion"):
            st.info("Please contact support to process your account deletion request.")

# Main app logic
def main():
    # Show sidebar navigation
    sidebar_menu()
    
    # Display the appropriate page based on current_page
    if st.session_state.current_page == 'login':
        login_page()
    elif st.session_state.current_page == 'register':
        register_page()
    elif st.session_state.current_page == 'verify':
        verify_page()
    elif st.session_state.authenticated:
        # Authenticated pages
        if st.session_state.current_page == 'my_recipes':
            my_recipes_page()
        elif st.session_state.current_page == 'add_recipe':
            add_recipe_page()
        elif st.session_state.current_page == 'browse':
            browse_recipes_page()
        elif st.session_state.current_page == 'recipe_detail':
            recipe_detail_page()
        elif st.session_state.current_page == 'edit_recipe':
            edit_recipe_page()
        elif st.session_state.current_page == 'confirm_delete':
            confirm_delete_page()
        elif st.session_state.current_page == 'profile':
            user_profile_page()
        elif st.session_state.current_page == 'test_s3':
            test_s3_access()
        else:
            st.error("Unknown page. Redirecting to home.")
            st.session_state.current_page = 'my_recipes'
            st.experimental_rerun()
    else:
        # Redirect to login if trying to access authenticated pages
        st.warning("Please login to continue")
        login_page()

if __name__ == "__main__":
    main()