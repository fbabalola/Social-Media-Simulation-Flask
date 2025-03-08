# Author: Firebami Babalola
# app.py
# This is a simple Flask app for the Handshake project.
# It simulates user roles and posts using in-memory data structures.
# For a real production environment, I'd use a proper database and more secure authentication (e.g., JWT, OAuth).


from flask import Flask, request, jsonify
from functools import wraps
import os
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape  # To sanitize user inputs and prevent XSS attacks

app = Flask("Handshake App")

# A secret key for session management. In production, this should be a long, random string stored securely.
app.secret_key = os.urandom(24)

# In-memory "databases" to simulate users and posts.
# In a real app, we'd use a database like PostgreSQL or MongoDB.

# Users DB: Each user has an ID, name, role, and hashed password.
# Assumption: Authentication is required for most actions.
legendary_users = {
    '1': {'id': '1', 'name': 'Firebami', 'role': 'student', 'password': generate_password_hash('studentpass')},
    '2': {'id': '2', 'name': 'Captain', 'role': 'edu_admin', 'password': generate_password_hash('adminpass')},
    '3': {'id': '3', 'name': 'Alex', 'role': 'employer', 'password': generate_password_hash('employerpass')},
    '4': {'id': '4', 'name': 'Kanye', 'role': 'employer_admin', 'password': generate_password_hash('empadminpass')},
}

# Posts DB: Each post includes its content, the owner’s ID, and the owner type.
stellar_posts = {
    '101': {'id': '101', 'content': 'Welcome to Handshake!', 'owner_id': '1', 'owner_type': 'student'}
}

# Helper Functions & Decorators

def get_current_legend():
    """
    Retrieves the current logged-in user using HTTP  Auth.
    In production, we'd use something more robust like JWT or OAuth.
    But for now, this gets the job done!
    """
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return None  # No auth provided? No user for you!

    # Find the user by matching the username (name in our DB).
    user = next((u for u in legendary_users.values() if u['name'] == auth.username), None)
    if user and check_password_hash(user['password'], auth.password):
        return user  #  authenticated user!
    return None  # Invalid credentials? Denied!

def must_be_legendary(f):
    """
    Decorator to ensure the user is authenticated.
    If not, return a 401 error. Because no hacks allowed!
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_legend()
        if not user:
            return jsonify({'error': 'Authentication required. Please log in!'}), 401
        return f(*args, **kwargs)
    return wrapper

def owner_or_captain_required(f):
    """
     to ensure only the owner of the post or an authorized admin can modify it.
    This will be our gatekeeper against Broken Access Control risks.
    """
    @wraps(f)
    def wrapper(post_id, *args, **kwargs):
        user = get_current_legend()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401

        post = stellar_posts.get(post_id)
        if not post:
            return jsonify({'error': 'Post not found!'}), 404

        # allow if the user is the post owner.
        if post['owner_id'] == user['id']:
            return f(post_id, *args, **kwargs)

        # Check admin roles based on the post .
        # EDU admins can modify posts from students or EDU staff.
        if post['owner_type'] in ['student', 'edu_staff'] and user['role'] == 'edu_admin':
            return f(post_id, *args, **kwargs)
        # Employer admins can modify posts from employers.
        if post['owner_type'] == 'employer' and user['role'] == 'employer_admin':
            return f(post_id, *args, **kwargs)

        #  none of the above, deny access. No trespassing!
        return jsonify({'error': 'Access denied: You are neither the owner nor an authorized admin.'}), 403
    return wrapper


# API Endpoints

@app.route('/post/<post_id>', methods=['GET'])
def show_stellar_post(post_id):
    """
    Public endpoint: Anyone can view a post.
    No authentication needed here. 
    """
    post = stellar_posts.get(post_id)
    if not post:
        return jsonify({'error': 'Post not found!'}), 404
    return jsonify(post)

@app.route('/post/<post_id>/like', methods=['POST'])
@must_be_legendary
def like_stellar_post(post_id):
    """
     to like a post.
    Must be authenticated to like a post. No anonymous likes allowed!
    """
    post = stellar_posts.get(post_id)
    if not post:
        return jsonify({'error': 'Post not found!'}), 404
    # In a full implementation, we'd update a like counter here.
    return jsonify({'message': 'Post liked!'}), 200

@app.route('/post/<post_id>/comment', methods=['POST'])
@must_be_legendary
def comment_on_stellar_post(post_id):
    """
     to comment on a post.
    Users must be logged in to comment. so no trolling is allowed!
    """
    post = stellar_posts.get(post_id)
    if not post:
        return jsonify({'error': 'Post not found!'}), 404
    comment = request.json.get('comment')
    if not comment:
        return jsonify({'error': 'Please provide a comment.'}), 400
    # Sanitize the comment to prevent XSS attacks. Safety first!
    sanitized_comment = escape(comment)
    return jsonify({'message': 'Comment added!', 'comment': sanitized_comment}), 200

@app.route('/post/<post_id>/update', methods=['PUT'])
@owner_or_captain_required
def update_stellar_post(post_id):
    """
    this rndpoint to update a post.
     the post owner or an authorized admin can update a post.
     protects against unauthorized modifications.
    """
    post = stellar_posts.get(post_id)
    new_content = request.json.get('content')
    if not new_content:
        return jsonify({'error': 'Provide new content for the post.'}), 400
    # Sanitize the new content to keep things clean and safe.
    post['content'] = escape(new_content)
    return jsonify({'message': 'Post updated successfully!', 'post': post}), 200

@app.route('/post/<post_id>/delete', methods=['DELETE'])
@owner_or_captain_required
def delete_stellar_post(post_id):
    """
    this endpoint is to delete a post.
     only the post owner or an authorized admin can delete a post.
    This ensures no one can delete posts they shouldn't.
    """
    if post_id in stellar_posts:
        del stellar_posts[post_id]
        return jsonify({'message': 'Post deleted.'}), 200
    return jsonify({'error': 'Post not found!'}), 404

# Running the Application
if __name__ == '__main__':
    # Run in debug mode for development only.
    # In production, we'd turn this off and use a proper server like Gunicorn.
    app.run(debug=True)