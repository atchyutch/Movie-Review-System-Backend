# 🎬 Movie Review System - Backend (Monolithic with Docker)

This project is a **monolithic backend application** for a **Movie Review System**, containerized with **Docker** for easy deployment.  
It provides RESTful APIs to manage users, movies, and reviews in one unified service.

---

## 🚀 Features
- User management (signup, login, profile)
- Add, update, delete movies
- Post and manage reviews for movies
- Authentication and authorization
- Containerized with Docker for consistent builds
- Single service monolithic architecture

---

## 🛠 Tech Stack
- **Backend:** Python (Flask) / Node.js / Java (depending on your implementation)
- **Database:** SQLite / MySQL (check your codebase)
- **Containerization:** Docker
- **Architecture:** Monolithic

---

## 📂 Project Structure



### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Movie-Review-Backend.git
cd Movie-Review-Backend

## Build Docker image
docker build -t movie-review-backend

## Run the container
docker run -p 5000:5000 movie-review-backend
