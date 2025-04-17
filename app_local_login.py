import streamlit as st
import boto3
import json
import os
import uuid
import datetime
from dotenv import load_dotenv
from PIL import Image
import io
import hmac
import hashlib
import base64

# Load environment variables
load_dotenv()

# AWS Credentials
AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
DYNAMODB_TABLE_NAME = os.getenv('DYNAMODB_TABLE_NAME')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

# Cognito Settings
COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_APP_CLIENT_ID = os.getenv('COGNITO_APP_CLIENT_ID')
COGNITO_APP_CLIENT_SECRET = os.getenv('COGNITO_APP_CLIENT_SECRET')

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

# --- Recipe functions (from previous code) ---

def generate_unique_id():
    """Generate a unique ID for the recipe"""
    return str(uuid.uuid4())

def upload_file_to_s3(file, file_name, content_type):
    """Upload a file to S3 bucket and return the URL"""
    try:
        s3_client.upload_fileobj(
            file,
            S3_BUCKET_NAME,
            file_name,
            ExtraArgs={
                'ContentType': content_type
            }
        )
        return f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{file_name}"
    except Exception as e:
        st.error(f"Error uploading file to S3: {e}")
        return None

def save_recipe_to_dynamodb(recipe_data):
    """Save recipe data to DynamoDB"""
    try:
        recipe_table.put_item(Item=recipe_data)
        return True
    except Exception as e:
        st.error(f"Error saving to DynamoDB: {e}")
        return False

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
        
        cuisine_options = ["Italian", "Chinese", "Mexican", "Indian", "American", "French", "Japanese", "Thai", "Mediterranean", "Other"]
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
                video_extension = video_file.name.split('.')[-1]
                video_filename = f"videos/{recipe_id}.{video_extension}"
                video_url = upload_file_to_s3(video_file, video_filename, f"video/{video_extension}")
            
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
                            st.image(recipe['image_url'], use_column_width=True)
                        
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
                            st.image(recipe['image_url'], use_column_width=True)
                        
                        st.write(f"**Category:** {recipe['category']} | **Cuisine:** {recipe['cuisine']}")
                        st.write(f"**Difficulty:** {recipe['difficulty_level']} | **Time:** {recipe['cooking_time']} min")
                        st.write(f"By: {recipe['user_id']}")
                        
                        # Add view button
                        if st.button(f"View Recipe", key=f"view_{recipe['recipe_id']}"):
                            # Set recipe ID in session state and navigate to detail page
                            st.session_state.current_recipe_id = recipe['recipe_id']
                            st.session_state.current_page = 'recipe_detail'
                            st.experimental_rerun()
                        
                        st.markdown("---")
    
    except Exception as e:
        st.error(f"Error retrieving recipes: {e}")

def recipe_detail_page():
    # Get recipe ID from session state
    recipe_id = st.session_state.get('current_recipe_id')
    
    if not recipe_id:
        st.error("Recipe not found")
        return
    
    try:
        # Query DynamoDB for the recipe
        response = recipe_table.get_item(Key={'recipe_id': recipe_id})
        recipe = response.get('Item')
        
        if not recipe:
            st.error("Recipe not found")
            return
        
        # Display recipe details
        st.title(recipe['recipe_name'])
        
        # Display image if available
        if recipe.get('image_url'):
            st.image(recipe['image_url'], use_column_width=True)
        
        # Recipe metadata
        col1, col2, col3 = st.columns(3)
        with col1:
            st.write(f"**Category:** {recipe['category']}")
            st.write(f"**Cuisine:** {recipe['cuisine']}")
        with col2:
            st.write(f"**Difficulty:** {recipe['difficulty_level']}")
            st.write(f"**Cooking Time:** {recipe['cooking_time']} minutes")
        with col3:
            st.write(f"**Servings:** {recipe['servings']}")
            st.write(f"**By:** {recipe['user_id']}")
        
        # Description
        st.subheader("Description")
        st.write(recipe['description'])
        
        # Create two columns for ingredients and instructions
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Ingredients
            st.subheader("Ingredients")
            for ingredient in recipe['ingredients']:
                st.write(f"• {ingredient}")
            
            # Nutritional info if available
            if recipe.get('nutritional_info'):
                st.subheader("Nutritional Information")
                st.write(recipe['nutritional_info'])
            
            # Allergens if available
            if recipe.get('allergens') and recipe['allergens'] != ['None']:
                st.subheader("Allergens")
                st.write(", ".join(recipe['allergens']))
            
            # Dietary restrictions if available
            if recipe.get('dietary_restrictions') and recipe['dietary_restrictions'] != ['None']:
                st.subheader("Dietary Information")
                st.write(", ".join(recipe['dietary_restrictions']))
        
        with col2:
            # Instructions
            st.subheader("Instructions")
            for i, instruction in enumerate(recipe['instructions'], 1):
                st.write(f"{i}. {instruction}")
        
        # Video if available
        if recipe.get('video_url'):
            st.subheader("Video")
            st.video(recipe['video_url'])
        
        # YouTube link if available
        if recipe.get('youtube_link'):
            st.subheader("YouTube Video")
            st.markdown(f"[Watch on YouTube]({recipe['youtube_link']})")
        
        # Tags if available
        if recipe.get('tags'):
            st.subheader("Tags")
            st.write(", ".join(recipe['tags']))
        
        # Back button
        if st.button("Back to Recipes"):
            st.session_state.current_page = 'my_recipes' if recipe['user_id'] == st.session_state.username else 'browse'
            st.experimental_rerun()
    
    except Exception as e:
        st.error(f"Error retrieving recipe: {e}")

def profile_page():
    st.title("My Profile")
    
    # Get user info
    user_info = get_user_info(st.session_state.username)
    
    # Display user info
    col1, col2 = st.columns([1, 2])
    
    with col1:
        # Display avatar (placeholder)
        st.image("https://via.placeholder.com/150", width=150)
        
    with col2:
        st.subheader(st.session_state.username)
        st.write(f"Email: {user_info.get('email', 'Not available')}")
        st.write(f"Member since: {user_info.get('created_at', 'Not available').split('T')[0]}")
    
    # User statistics
    st.subheader("Your Recipe Statistics")
    
    try:
        # Query DynamoDB for user's recipes
        response = recipe_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('user_id').eq(st.session_state.username)
        )
        recipes = response.get('Items', [])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Recipes", len(recipes))
        with col2:
            public_recipes = sum(1 for r in recipes if r.get('is_public', False))
            st.metric("Public Recipes", public_recipes)
        with col3:
            private_recipes = len(recipes) - public_recipes
            st.metric("Private Recipes", private_recipes)
        
        # Recipe categories breakdown
        if recipes:
            st.subheader("Your Recipe Categories")
            categories = {}
            for recipe in recipes:
                category = recipe.get('category', 'Other')
                categories[category] = categories.get(category, 0) + 1
            
            # Display as a horizontal bar chart
            category_names = list(categories.keys())
            category_counts = list(categories.values())
            
            # Create a simple bar chart using markdown
            for i, (cat, count) in enumerate(zip(category_names, category_counts)):
                percentage = int((count / len(recipes)) * 100)
                st.write(f"**{cat}**: {count} recipes ({percentage}%)")
                st.progress(percentage / 100)
    
    except Exception as e:
        st.error(f"Error retrieving user statistics: {e}")
    
    # Account settings
    with st.expander("Account Settings"):
        st.subheader("Change Password")
        
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            submitted = st.form_submit_button("Change Password")
            
            if submitted:
                st.info("Password change functionality would be implemented here")
        
        st.subheader("Notification Preferences")
        email_notifications = st.checkbox("Receive email notifications", value=True)
        if email_notifications:
            st.checkbox("New comments on your recipes", value=True)
            st.checkbox("New likes on your recipes", value=True)
            st.checkbox("Recipe of the week", value=True)

# Routing for different pages
def main():
    sidebar_menu()
    
    # Route to appropriate page based on session state
    if not st.session_state.authenticated:
        if st.session_state.current_page == 'login':
            login_page()
        elif st.session_state.current_page == 'register':
            register_page()
        elif st.session_state.current_page == 'verify':
            verify_page()
        else:
            login_page()
    else:
        if st.session_state.current_page == 'add_recipe':
            add_recipe_page()
        elif st.session_state.current_page == 'my_recipes':
            my_recipes_page()
        elif st.session_state.current_page == 'browse':
            browse_recipes_page()
        elif st.session_state.current_page == 'recipe_detail':
            recipe_detail_page()
        elif st.session_state.current_page == 'profile':
            profile_page()
        else:
            my_recipes_page()

if __name__ == "__main__":
    main()