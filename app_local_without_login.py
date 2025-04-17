import streamlit as st
import boto3
import json
import os
import uuid
import datetime
from dotenv import load_dotenv
from PIL import Image
import io

# Load environment variables
load_dotenv()

# AWS Credentials
AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
DYNAMODB_TABLE_NAME = os.getenv('DYNAMODB_TABLE_NAME')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

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

# Set up Streamlit app
st.title("Recipe Management App")
st.write("Enter details of your recipe below")

# Form for recipe information
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
    
    submitted = st.form_submit_button("Save Recipe")

if submitted:
    if not recipe_name:
        st.error("Recipe Name is required!")
    else:
        # Generate unique ID for the recipe
        id = generate_unique_id()
        
        # Process image upload if provided
        image_url = None
        if image_file:
            image_extension = image_file.name.split('.')[-1]
            image_filename = f"images/{id}.{image_extension}"
            image_url = upload_file_to_s3(image_file, image_filename, f"image/{image_extension}")
        
        # Process video upload if provided
        video_url = None
        if video_file:
            video_extension = video_file.name.split('.')[-1]
            video_filename = f"videos/{id}.{video_extension}"
            video_url = upload_file_to_s3(video_file, video_filename, f"video/{video_extension}")
        
        # Prepare recipe data
        recipe_data = {
            "id": id,
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
            "created_at": datetime.datetime.now().isoformat(),
            "updated_at": datetime.datetime.now().isoformat()
        }
        
        # Save to DynamoDB
        if save_recipe_to_dynamodb(recipe_data):
            st.success(f"Recipe '{recipe_name}' saved successfully!")
            st.write("Recipe ID: ", id)
        else:
            st.error("Failed to save recipe. Please try again.")

# View recipes section
st.header("View Recipes")
if st.button("Show All Recipes"):
    try:
        # Scan DynamoDB table to get all recipes
        response = recipe_table.scan()
        recipes = response.get('Items', [])
        
        if not recipes:
            st.info("No recipes found.")
        else:
            # Display each recipe
            for recipe in recipes:
                st.subheader(recipe['recipe_name'])
                st.write(f"**Category:** {recipe['category']} | **Cuisine:** {recipe['cuisine']} | **Difficulty:** {recipe['difficulty_level']}")
                
                # Display image if available
                if recipe.get('image_url'):
                    st.image(recipe['image_url'], caption=recipe['recipe_name'])
                
                st.write(f"**Description:** {recipe['description']}")
                
                # Display more details in an expander
                with st.expander("View Recipe Details"):
                    st.write("### Ingredients")
                    for ingredient in recipe['ingredients']:
                        st.write(f"- {ingredient}")
                    
                    st.write("### Instructions")
                    for i, instruction in enumerate(recipe['instructions'], 1):
                        st.write(f"{i}. {instruction}")
                    
                    if recipe.get('video_url'):
                        st.video(recipe['video_url'])
                    
                    if recipe.get('youtube_link'):
                        st.write(f"[Watch on YouTube]({recipe['youtube_link']})")
                
                st.divider()
                
    except Exception as e:
        st.error(f"Error retrieving recipes: {e}")

        