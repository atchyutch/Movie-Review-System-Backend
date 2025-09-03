DROP TABLE IF EXISTS user_details;

CREATE TABLE user_details (
    first_name TEXT,
    last_name TEXT,
    username TEXT NOT NULL UNIQUE,
    email_address TEXT NOT NULL UNIQUE,
    password TEXT,
    salt TEXT,
    moderator TEXT,
    critic TEXT,
    PRIMARY KEY (username, email_address)
);

DROP TABLE IF EXISTS user_passwords;
CREATE TABLE user_passwords (
    username TEXT,
    previous_password TEXT, 
    FOREIGN KEY(username) REFERENCES user_details(username) ON DELETE CASCADE
);


DROP TABLE IF EXISTS movie_details;
CREATE TABLE movie_details(
    title TEXT,
    synopsis TEXT,
    movie_id INTEGER PRIMARY KEY,
    created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);


DROP TABLE IF EXISTS movie_genres;
CREATE TABLE movie_genres(
    movie_id INTEGER,
    genre TEXT,
    FOREIGN KEY(movie_id) REFERENCES movie_details(movie_id)
);

DROP TABLE IF EXISTS movie_reviews;
CREATE TABLE movie_reviews(
    username TEXT,
    rating INTEGER,
    text TEXT,
    movie_id INTEGER,
    review_id INTEGER PRIMARY KEY,
    FOREIGN KEY(movie_id) REFERENCES movie_details(movie_id)
);