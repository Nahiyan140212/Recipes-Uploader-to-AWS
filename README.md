# Recipe Manager App

A Streamlit-based web application that allows users to create, store, and share recipes. The app includes image and video uploads, comprehensive recipe metadata, and user authentication.

## Features

- User registration and authentication via AWS Cognito
- Upload and store recipe images and videos in Amazon S3
- Save recipe details in Amazon DynamoDB
- Browse public recipes from other users
- Search and filter recipes by various criteria
- User profiles with recipe statistics

## Demo

Check out the live demo on Hugging Face Spaces: [Recipe Manager App](https://sharedskillet.streamlit.app/)

## Local Development

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your AWS credentials and other environment variables
4. Run the Streamlit app:
   ```bash
   streamlit run app.py
   ```

## AWS Setup Requirements

- Amazon S3 bucket for media storage
- DynamoDB tables for recipe and user data
- AWS Cognito User Pool for authentication
- IAM user with appropriate permissions
