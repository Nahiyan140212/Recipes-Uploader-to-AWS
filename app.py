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
    if key in st.secrets:
        return st.secrets[key]
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
user_table = dynamodb.Table('recipe_app_users')

# --- Helper Functions for S3 and File Uploads ---

def check_and_fix_s3_urls(url):
    if not url:
        return url
    if url.startswith('http://'):
        url = url.replace('http://', 'https://')
    if not url.startswith('https://'):
        url = f"https://{url}"
    return url

def upload_file_to_s3(file, file_name, content_type):
    try:
        content_disposition = 'inline' if content_type.startswith('image/') else 'attachment'
        s3_client.upload_fileobj(
            file,
            S3_BUCKET_NAME,
            file_name,
            ExtraArgs={
                'ContentType': content_type,
                'ACL': 'public-read',
                'ContentDisposition': f'{content_disposition}; filename="{os.path.basename(file_name)}"'
            }
        )
        return f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{file_name}"
    except Exception as e:
        st.error(f"Error uploading file to S3: {e}")
        return None

def upload_large_file_to_s3(file, bucket, object_name):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        shutil.copyfileobj(file, tmp)
        tmp_filename = tmp.name
    
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )
    
    try:
        response = s3_client.create_multipart_upload(
            Bucket=bucket,
            Key=object_name,
            ContentType=file.type,
            ACL='public-read'
        )
        upload_id = response['UploadId']
        
        file_size = os.path.getsize(tmp_filename)
        chunk_size = 5 * 1024 * 1024
        num_parts = (file_size // chunk_size) + 1
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        parts = []
        
        def upload_part(part_number):
            start = (part_number - 1) * chunk_size
            end = min(start + chunk_size, file_size)
            with open(tmp_filename, 'rb') as f:
                f.seek(start)
                part_data = f.read(end - start)
            response = s3_client.upload_part(
                Body=part_data,
                Bucket=bucket,
                Key=object_name,
                PartNumber=part_number,
                UploadId=upload_id
            )
            progress = int((part_number / num_parts) * 100)
            progress_bar.progress(progress / 100)
            status_text.text(f"Uploading: {progress}% complete")
            return {
                'PartNumber': part_number,
                'ETag': response['ETag']
            }
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            parts = list(executor.map(upload_part, range(1, num_parts + 1)))
        
        s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=object_name,
            MultipartUpload={'Parts': parts},
            UploadId=upload_id
        )
        
        os.unlink(tmp_filename)
        progress_bar.progress(1.0)
        status_text.text("Upload complete!")
        return f"https://{bucket}.s3.amazonaws.com/{object_name}"
    
    except Exception as e:
        if 'upload_id' in locals():
            s3_client.abort_multipart_upload(
                Bucket=bucket,
                Key=object_name,
                UploadId=upload_id
            )
        if os.path.exists(tmp_filename):
            os.unlink(tmp_filename)
        st.error(f"Error uploading file: {e}")
        return None

def process_video_upload(video_file, recipe_id): 
    if video_file:
        video_extension = video_file.name.split('.')[-1]
        video_filename = f"videos/{recipe_id}.{video_extension}"
        file_size_mb = video_file.size / (1024 * 1024)
        if file_size_mb > 200:
            st.warning(f"""
            Your video is {file_size_mb:.1f} MB, which exceeds the recommended size (200 MB).
            For better performance, consider:
            1. Uploading to YouTube and providing the link
            2. Compressing your video before uploading
            """)
            video_url = upload_large_file_to_s3(
                video_file, 
                S3_BUCKET_NAME, 
                video_filename
            )
        else:
            video_url = upload_file_to_s3(
                video_file, 
                video_filename, 
                f"video/{video_extension}"
            )
        return video_url
    return None

def test_s3_access():
    st.subheader("S3 Bucket Access Test")
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, MaxKeys=5)
        if 'Contents' in response:
            st.success(f"Successfully connected to S3 bucket '{S3_BUCKET_NAME}'")
            st.write("Sample objects in bucket:")
            for item in response['Contents'][:5]:
                st.write(f"- {item['Key']}")
        else:
            st.warning(f"Connected to bucket '{S3_BUCKET_NAME}' but it appears to be empty")
            
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
        
        s3_client.delete_object(
            Bucket=S3_BUCKET_NAME,
            Key=test_object_key
        )
    except Exception as e:
        st.error(f"Error testing S3 access: {e}")
        st.write("Check your AWS credentials and bucket permissions")

# --- Authentication Functions ---

def get_cognito_secret_hash(username):
    message = username + COGNITO_APP_CLIENT_ID
    dig = hmac.new(
        str(COGNITO_APP_CLIENT_SECRET).encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def register_user(username, email, password):
    try:
        cognito_client = boto3.client(
            'cognito-idp',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
        secret_hash = get_cognito_secret_hash(username)
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
    try:
        cognito_client = boto3.client(
            'cognito-idp',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
        secret_hash = get_cognito_secret_hash(username)
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
    try:
        cognito_client = boto3.client(
            'cognito-idp',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )
        secret_hash = get_cognito_secret_hash(username)
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
    try:
        response = user_table.get_item(Key={'username': username})
        return response.get('Item', {})
    except Exception as e:
        st.error(f"Error retrieving user data: {e}")
        return {}

# --- Recipe functions ---

def generate_unique_id():
    return str(uuid.uuid4())

def save_recipe_to_dynamodb(recipe_data):
    try:
        recipe_table.put_item(Item=recipe_data)
        return True
    except Exception as e:
        st.error(f"Error saving to DynamoDB: {e}")
        return False

def get_recipe_by_id(recipe_id):
    try:
        response = recipe_table.get_item(Key={'recipe_id': recipe_id})
        return response.get('Item', {})
    except Exception as e:
        st.error(f"Error retrieving recipe: {e}")
        return {}

def delete_recipe_from_dynamodb(recipe_id):
    try:
        # Get recipe to delete associated S3 objects
        recipe = get_recipe_by_id(recipe_id)
        
        # Delete associated S3 objects
        if recipe.get('image_url'):
            image_key = recipe['image_url'].split('.com/')[-1]
            s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=image_key)
        
        if recipe.get('video_url'):
            video_key = recipe['video_url'].split('.com/')[-1]
            s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=video_key)
        
        # Delete from DynamoDB
        recipe_table.delete_item(Key={'recipe_id': recipe_id})
        return True
    except Exception as e:
        st.error(f"Error deleting recipe: {e}")
        return False

# --- Streamlit App ---
st.set_page_config(page_title="Recipe Manager", layout="wide")

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'access_token' not in st.session_state:
    st.session_state.access_token = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'login'

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
        category_options = ["Main Course", "Dessert", "Appetizer", "Breakfast", "Lunch", "Dinner", "Snack", "Beverage", "Other"]
        category = st.selectbox("Category", category_options)
        cuisine_options = ["Italian", "Chinese", "Mexican", "Indian", "American", "French", "Japanese", "Thai", "Mediterranean", "Other"]
        cuisine = st.selectbox("Cuisine", cuisine_options)
        difficulty_options = ["Easy", "Medium", "Hard"]
        difficulty = st.selectbox("Difficulty Level", difficulty_options)
        nutritional_info = st.text_area("Nutritional Information (optional)")
        allergen_options = ["Nuts", "Gluten", "Dairy", "Eggs", "Soy", "Shellfish", "Fish", "None"]
        allergens = st.multiselect("Allergens", allergen_options)
        dietary_options = ["Vegetarian", "Vegan", "Gluten-Free", "Dairy-Free", "Keto", "Low-Carb", "Paleo", "None"]
        dietary_restrictions = st.multiselect("Dietary Restrictions", dietary_options)
        tags = st.text_input("Tags (comma separated)")
        youtube_link = st.text_input("YouTube Link (optional)")
        image_file = st.file_uploader("Upload Recipe Image", type=["jpg", "jpeg", "png"])
        video_file = st.file_uploader("Upload Recipe Video (optional)", type=["mp4", "mov", "avi"])
        
        if video_file is not None:
            file_size_mb = video_file.size / (1024 * 1024)
            if file_size_mb > 200:
                st.warning(f"""
                Your video is {file_size_mb:.1f} MB, which exceeds the recommended size (200 MB).
                For better performance, consider:
                1. Uploading to YouTube and providing the link
                2. Compressing your video before uploading
                """)
        
        is_public = st.checkbox("Make this recipe public", value=True)
        submitted = st.form_submit_button("Save Recipe")

    if submitted:
        if not recipe_name:
            st.error("Recipe Name is required!")
        else:
            recipe_id = generate_unique_id()
            image_url = None
            if image_file:
                image_extension = image_file.name.split('.')[-1]
                image_filename = f"images/{recipe_id}.{image_extension}"
                image_url = upload_file_to_s3(image_file, image_filename, f"image/{image_extension}")
            
            video_url = None
            if video_file:
                video_url = process_video_upload(video_file, recipe_id)
            
            recipe_data = {
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
                "created_at": datetime.datetime.now().isoformat(),
                "updated_at": datetime.datetime.now().isoformat()
            }
            
            if save_recipe_to_dynamodb(recipe_data):
                st.success(f"Recipe '{recipe_name}' saved successfully!")
                st.write("Recipe ID: ", recipe_id)
            else:
                st.error("Failed to save recipe. Please try again.")

def my_recipes_page():
    st.title("My Recipes")
    try:
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
            col1, col2 = st.columns(2)
            for i, recipe in enumerate(recipes):
                with col1 if i % 2 == 0 else col2:
                    with st.container():
                        st.subheader(recipe['recipe_name'])
                        if recipe.get('image_url'):
                            try:
                                image_url = check_and_fix_s3_urls(recipe['image_url'])
                                st.image(image_url, use_column_width=True)
                            except Exception as e:
                                st.error(f"Error loading image: {e}")
                                st.write(f"Image URL: [View Image]({recipe['image_url']})")
                        
                        st.write(f"**Category:** {recipe['category']} | **Cuisine:** {recipe['cuisine']}")
                        st.write(f"**Difficulty:** {recipe['difficulty_level']} | **Time:** {recipe['cooking_time']} min")
                        
                        col_view, col_edit, col_delete = st.columns(3)
                        with col_view:
                            if st.button(f"View", key=f"view_{recipe['recipe_id']}"):
                                st.session_state.current_recipe_id = recipe['recipe_id']
                                st.session_state.current_page = 'recipe_detail'
                                st.experimental_rerun()
                        
                        with col_edit:
                            if st.button(f"Edit", key=f"edit_{recipe['recipe_id']}"):
                                st.session_state.current_recipe_id = recipe['recipe_id']
                                st.session_state.current_page = 'edit_recipe'
                                st.experimental_rerun()
                        
                        with col_delete:
                            if st.button(f"Delete", key=f"delete_{recipe['recipe_id']}"):
                                st.session_state.recipe_to_delete = recipe['recipe_id']
                                st.session_state.current_page = 'confirm_delete'
                                st.experimental_rerun()
                        
                        st.markdown("---")
    
    except Exception as e:
        st.error(f"Error retrieving recipes: {e}")

def browse_recipes_page():
    st.title("Browse Recipes")
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
        response = recipe_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('is_public').eq(True)
        )
        all_recipes = response.get('Items', [])
        
        filtered_recipes = all_recipes
        if search_term:
            filtered_recipes = [
                r for r in filtered_recipes if 
                search_term.lower() in r['recipe_name'].lower() or
                search_term.lower() in r.get('description', '').lower() or
                any(search_term.lower() in tag.lower() for tag in r.get('tags', []))
            ]
        
        if category_filter != "All Categories":
            filtered_recipes = [r for r in filtered_recipes if r['category'] == category_filter]
        
        if cuisine_filter != "All Cuisines":
            filtered_recipes = [r for r in filtered_recipes if r['cuisine'] == cuisine_filter]
        
        if difficulty_filter:
            filtered_recipes = [r for r in filtered_recipes if r['difficulty_level'] in difficulty_filter]
        
        if dietary_filter:
            filtered_recipes = [
                r for r in filtered_recipes if 
                any(restriction in r.get('dietary_restrictions', []) for restriction in dietary_filter)
            ]
        
        st.subheader(f"Found {len(filtered_recipes)} recipes")
        
        if not filtered_recipes:
            st.info("No recipes match your search criteria.")
        else:
            col1, col2, col3 = st.columns(3)
            for i, recipe in enumerate(filtered_recipes):
                with col1 if i % 3 == 0 else col2 if i % 3 == 1 else col3:
                    with st.container():
                        st.subheader(recipe['recipe_name'])
                        if recipe.get('image_url'):
                            try:
                                image_url = check_and_fix_s3_urls(recipe['image_url'])
                                st.image(image_url, use_column_width=True)
                            except Exception as e:
                                st.error(f"Error loading image: {e}")
                                st.write(f"Image URL: [View Image]({recipe['image_url']})")
                        
                        st.write(f"**Category:** {recipe['category']} | **Cuisine:** {recipe['cuisine']}")
                        st.write(f"**Difficulty:** {recipe['difficulty_level']} | **Time:** {recipe['cooking_time']} min")
                        st.write(f"**Created by:** {recipe['user_id']}")
                        
                        if st.button(f"View Details", key=f"browse_view_{recipe['recipe_id']}"):
                            st.session_state.current_recipe_id = recipe['recipe_id']
                            st.session_state.current_page = 'recipe_detail'
                            st.experimental_rerun()
                        
                        st.markdown("---")
    
    except Exception as e:
        st.error(f"Error retrieving recipes: {e}")

def recipe_detail_page():
    st.title("Recipe Details")
    recipe = get_recipe_by_id(st.session_state.current_recipe_id)
    
    if not recipe:
        st.error("Recipe not found!")
        return
    
    col1, col2 = st.columns([2, 1])
    with col1:
        st.header(recipe['recipe_name'])
        if recipe.get('image_url'):
            try:
                image_url = check_and_fix_s3_urls(recipe['image_url'])
                st.image(image_url, use_column_width=True)
            except Exception as e:
                st.error(f"Error loading image: {e}")
    
    with col2:
        st.write(f"**Created by:** {recipe['user_id']}")
        st.write(f"**Category:** {recipe['category']}")
        st.write(f"**Cuisine:** {recipe['cuisine']}")
        st.write(f"**Difficulty:** {recipe['difficulty_level']}")
        st.write(f"**Servings:** {recipe['servings']}")
        st.write(f"**Cooking Time:** {recipe['cooking_time']} minutes")
        st.write(f"**Created:** {recipe['created_at'].split('T')[0]}")
        
    st.markdown("---")
    st.subheader("Description")
    st.write(recipe['description'] if recipe['description'] else "No description provided.")
    
    st.subheader("Ingredients")
    for ingredient in recipe['ingredients']:
        st.write(f"- {ingredient}")
    
    st.subheader("Instructions")
    for i, instruction in enumerate(recipe['instructions'], 1):
        st.write(f"{i}. {instruction}")
    
    if recipe.get('nutritional_info'):
        st.subheader("Nutritional Information")
        st.write(recipe['nutritional_info'])
    
    if recipe.get('allergens'):
        st.subheader("Allergens")
        st.write(", ".join(recipe['allergens']))
    
    if recipe.get('dietary_restrictions'):
        st.subheader("Dietary Restrictions")
        st.write(", ".join(recipe['dietary_restrictions']))
    
    if recipe.get('tags'):
        st.subheader("Tags")
        st.write(", ".join(recipe['tags']))
    
    if recipe.get('youtube_link'):
        st.subheader("Video Tutorial")
        st.write(f"[Watch on YouTube]({recipe['youtube_link']})")
    
    if recipe.get('video_url'):
        st.subheader("Recipe Video")
        try:
            video_url = check_and_fix_s3_urls(recipe['video_url'])
            st.video(video_url)
        except Exception as e:
            st.error(f"Error loading video: {e}")
    
    st.markdown("---")
    if st.button("Back to Recipes"):
        st.session_state.current_page = 'my_recipes' if recipe['user_id'] == st.session_state.username else 'browse'
        st.experimental_rerun()

def edit_recipe_page():
    st.title("Edit Recipe")
    recipe = get_recipe_by_id(st.session_state.current_recipe_id)
    
    if not recipe:
        st.error("Recipe not found!")
        return
    
    if recipe['user_id'] != st.session_state.username:
        st.error("You don't have permission to edit this recipe!")
        return
    
    with st.form("edit_recipe_form"):
        recipe_name = st.text_input("Recipe Name", value=recipe['recipe_name'])
        description = st.text_area("Description", value=recipe['description'] or "")
        ingredients = st.text_area("Ingredients (one per line)", value="\n".join(recipe['ingredients']))
        instructions = st.text_area("Instructions (step by step)", value="\n".join(recipe['instructions']))
        servings = st.number_input("Servings", min_value=1, value=recipe['servings'])
        cooking_time = st.number_input("Cooking Time (minutes)", min_value=1, value=recipe['cooking_time'])
        
        category_options = ["Main Course", "Dessert", "Appetizer", "Breakfast", "Lunch", "Dinner", "Snack", "Beverage", "Other"]
        category = st.selectbox("Category", category_options, index=category_options.index(recipe['category']))
        
        cuisine_options = ["Bangladesh", "Italian", "Chinese", "Mexican", "Indian", "American", "French", "Japanese", "Thai", "Mediterranean", "Other"]
        cuisine = st.selectbox("Cuisine", cuisine_options, index=cuisine_options.index(recipe['cuisine']))
        
        difficulty_options = ["Easy", "Medium", "Hard"]
        difficulty = st.selectbox("Difficulty Level", difficulty_options, index=difficulty_options.index(recipe['difficulty_level']))
        
        nutritional_info = st.text_area("Nutritional Information (optional)", value=recipe['nutritional_info'] or "")
        
        allergen_options = ["Nuts", "Gluten", "Dairy", "Eggs", "Soy", "Shellfish", "Fish", "None"]
        allergens = st.multiselect("Allergens", allergen_options, default=recipe['allergens'])
        
        dietary_options = ["Vegetarian", "Vegan", "Gluten-Free", "Dairy-Free", "Keto", "Low-Carb", "Paleo", "None"]
        dietary_restrictions = st.multiselect("Dietary Restrictions", dietary_options, default=recipe['dietary_restrictions'])
        
        tags = st.text_input("Tags (comma separated)", value=", ".join(recipe['tags']))
        youtube_link = st.text_input("YouTube Link (optional)", value=recipe['youtube_link'] or "")
        
        image_file = st.file_uploader("Upload New Recipe Image", type=["jpg", "jpeg", "png"])
        if recipe.get('image_url'):
            st.image(check_and_fix_s3_urls(recipe['image_url']), caption="Current Image")
        
        video_file = st.file_uploader("Upload New Recipe Video (optional)", type=["mp4", "mov", "avi"])
        if recipe.get('video_url'):
            st.video(check_and_fix_s3_urls(recipe['video_url']), caption="Current Video")
        
        is_public = st.checkbox("Make this recipe public", value=recipe['is_public'])
        
        col1, col2 = st.columns(2)
        with col1:
            submitted = st.form_submit_button("Update Recipe")
        with col2:
            if st.form_submit_button("Cancel"):
                st.session_state.current_page = 'my_recipes'
                st.experimental_rerun()

    if submitted:
        if not recipe_name:
            st.error("Recipe Name is required!")
        else:
            # Process new uploads
            image_url = recipe.get('image_url')
            if image_file:
                # Delete old image if exists
                if image_url:
                    old_image_key = image_url.split('.com/')[-1]
                    s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=old_image_key)
                
                image_extension = image_file.name.split('.')[-1]
                image_filename = f"images/{recipe['recipe_id']}.{image_extension}"
                image_url = upload_file_to_s3(image_file, image_filename, f"image/{image_extension}")
            
            video_url = recipe.get('video_url')
            if video_file:
                # Delete old video if exists
                if video_url:
                    old_video_key = video_url.split('.com/')[-1]
                    s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=old_video_key)
                
                video_url = process_video_upload(video_file, recipe['recipe_id'])
            
            # Update recipe data
            updated_recipe = {
                "recipe_id": recipe['recipe_id'],
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
                "created_at": recipe['created_at'],
                "updated_at": datetime.datetime.now().isoformat()
            }
            
            if save_recipe_to_dynamodb(updated_recipe):
                st.success(f"Recipe '{recipe_name}' updated successfully!")
                st.session_state.current_page = 'recipe_detail'
                st.experimental_rerun()
            else:
                st.error("Failed to update recipe. Please try again.")

def confirm_delete_page():
    st.title("Confirm Delete")
    recipe = get_recipe_by_id(st.session_state.recipe_to_delete)
    
    if not recipe:
        st.error("Recipe not found!")
        return
    
    st.warning(f"Are you sure you want to delete '{recipe['recipe_name']}'?")
    st.write("This action cannot be undone.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Confirm Delete"):
            if delete_recipe_from_dynamodb(st.session_state.recipe_to_delete):
                st.success("Recipe deleted successfully!")
                st.session_state.recipe_to_delete = None
                st.session_state.current_page = 'my_recipes'
                st.experimental_rerun()
            else:
                st.error("Failed to delete recipe. Please try again.")
    
    with col2:
        if st.button("Cancel"):
            st.session_state.recipe_to_delete = None
            st.session_state.current_page = 'my_recipes'
            st.experimental_rerun()

def profile_page():
    st.title("My Profile")
    user_info = get_user_info(st.session_state.username)
    
    if not user_info:
        st.error("User information not found!")
        return
    
    st.subheader("User Information")
    st.write(f"**Username:** {user_info['username']}")
    st.write(f"**Email:** {user_info['email']}")
    st.write(f"**Joined:** {user_info['created_at'].split('T')[0]}")
    
    # Statistics
    st.subheader("My Statistics")
    try:
        response = recipe_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('user_id').eq(st.session_state.username)
        )
        recipes = response.get('Items', [])
        public_recipes = [r for r in recipes if r['is_public']]
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Recipes", len(recipes))
        with col2:
            st.metric("Public Recipes", len(public_recipes))
    
    except Exception as e:
        st.error(f"Error loading statistics: {e}")
    
    st.markdown("---")
    if st.button("Back to My Recipes"):
        st.session_state.current_page = 'my_recipes'
        st.experimental_rerun()

# Main app logic
def main():
    sidebar_menu()
    
    if st.session_state.current_page == 'login':
        login_page()
    elif st.session_state.current_page == 'register':
        register_page()
    elif st.session_state.current_page == 'verify':
        verify_page()
    elif st.session_state.current_page == 'add_recipe':
        add_recipe_page()
    elif st.session_state.current_page == 'my_recipes':
        my_recipes_page()
    elif st.session_state.current_page == 'browse':
        browse_recipes_page()
    elif st.session_state.current_page == 'recipe_detail':
        recipe_detail_page()
    elif st.session_state.current_page == 'edit_recipe':
        edit_recipe_page()
    elif st.session_state.current_page == 'confirm_delete':
        confirm_delete_page()
    elif st.session_state.current_page == 'profile':
        profile_page()
    elif st.session_state.current_page == 'test_s3':
        test_s3_access()

if __name__ == "__main__":
    main()