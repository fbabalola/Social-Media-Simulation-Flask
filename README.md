# Flask Project

A Flask app simulating user roles and posts, similar to a basic social media platform like LinkedIn or X. This project was created as part of an intern assignment, showcasing my ability to implement role-based access control, authentication, and security features.

---

## Features

- **User Roles**: Students, EDU Admins, Employers, Employer Admins.
- **Post Actions**: View, like, comment, update, and delete posts with proper authorization.
- **Security**: HTTP Basic Authentication, role-based access control, input sanitization, and password hashing.

---

## How It Works

### Users DB
- Stores user data in an in-memory dictionary.
- Each user has an ID, name, role, and hashed password.

### Posts DB
- Stores posts in an in-memory dictionary.
- Each post has an ID, content, owner ID, and owner type.

---

## API Endpoints

- **View a Post**: `GET /post/<post_id>`
- **Like a Post**: `POST /post/<post_id>/like` (authenticated users only)
- **Comment on a Post**: `POST /post/<post_id>/comment` (authenticated users only)
- **Update a Post**: `PUT /post/<post_id>/update` (owner or admin only)
- **Delete a Post**: `DELETE /post/<post_id>/delete` (owner or admin only)

---

