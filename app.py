import sqlite3
import os
import json
from flask import Flask, request
import hashlib
import base64
import hmac

app = Flask(__name__)
db_name = "project2.db"
sql_file = "project2.sql"
db_flag = False

def create_db():
	conn = sqlite3.connect(db_name)
	with open(sql_file, 'r') as sql_startup:
		init_db = sql_startup.read()
	cursor = conn.cursor()
	cursor.executescript(init_db)
	conn.commit()
	conn.close()
	global db_flag
	db_flag = True
	return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	return conn

@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM movie_details;")
	# result = cursor.fetchall()
	# conn.close()

	# return result
	result = cursor.fetchall()
	conn.close()
	return json.dumps(result)

@app.route('/test_get/<post_id>', methods=(['GET']))
def test_get(post_id):
	result = {}
	result['numbers'] = request.args.get('numbers')
	result['post_id'] = post_id
	result['jwt'] = request.headers['Authorization']

	return json.dumps(result)


@app.route('/test_post', methods=(['POST']))
def test_post():
	result = request.form
	return result

@app.route('/clear', methods=(['GET']))
def clear():
	if os.path.exists(db_name):
		os.remove(db_name)
	else:
		None
	create_db()
	return "Database Cleared"

@app.route('/create_user', methods=(['POST']))
def create_user():
	conn = get_db()
	cursor = conn.cursor()
	try:
		firstname = request.form.get('first_name')
		lastname = request.form.get('last_name')
		username = request.form.get('username')
		email_address = request.form.get('email_address')
		password = request.form.get('password')
		salt = request.form.get('salt')
		moderator = request.form.get('moderator')
		critic = request.form.get('critic')

		if verify_password(password,firstname,username,lastname,salt) == True:
			password_stored = hash_password(salt, password)
		else:
			return json.dumps({"status": 4, "pass_hash": "NULL"})
		
		cursor.execute("INSERT INTO user_details(first_name, last_name, username, email_address, password, salt, moderator, critic) VALUES(?,?,?,?,?,?,?,?);",
					(firstname, lastname, username, email_address, password_stored,salt, moderator, critic))
		cursor.execute("INSERT INTO user_passwords(username, previous_password) VALUES(?,?);",
					(username, password_stored))
		conn.commit()
		return json.dumps({"status": 1, "pass_hash": password_stored})

	except sqlite3.IntegrityError as e:
		if ("UNIQUE constraint failed: user_details.username" in str(e)):
			return json.dumps({"status": 2, "pass_hash": "NULL"})
		elif ("UNIQUE constraint failed: user_details.email_address" in str(e)):
			return json.dumps({"status": 3, "pass_hash": "NULL"})
	finally:
		conn.close()


def verify_password(password,firstname,username,lastname,salt):
	if (firstname in password) or (username in password) or (lastname in password):
		return False
	if len(password) < 8:
		return False
	has_upper = False
	has_lower = False
	has_digit = False
	if any(c.isupper() for c in password):
		has_upper = True
	if any(c.islower() for c in password):
		has_lower = True
	if any(c.isdigit() for c in password):
		has_digit = True
	if user_previous_passwords(username, password, salt) == False:
		return False
	if has_upper and has_lower and has_digit:
		return True
	else:
		return False


def hash_password(salt, password): 
	password_salt = (password + salt).encode()
	hashed_password = hashlib.sha256(password_salt).hexdigest()
	return hashed_password


def user_previous_passwords(username, password, salt):
	conn = get_db()
	cursor = conn.cursor()
	password = hash_password(salt, password)
	cursor.execute("SELECT previous_password FROM user_passwords WHERE username = ?;", (username,))
	result2 = cursor.fetchall() 
	for hash in result2:
		if password == hash[0]:
			return False
	conn.commit()
	conn.close()
	return True


@app.route('/login', methods=(['POST']))
def login_user():
	username = request.form.get('username')
	password = request.form.get('password')

	conn = get_db()
	cursor = conn.cursor()

	cursor.execute("SELECT password FROM user_details WHERE username = ?;",(username,))
	retrieved_password = cursor.fetchone()
	cursor.execute("SELECT salt FROM user_details WHERE username = ?;",(username,))
	retrieved_salt = cursor.fetchone() 
	
	password_calculated = hash_password(retrieved_salt[0], password)

	if password_calculated == retrieved_password[0]:  
		header = {"alg": "HS256" , "typ": "JWT"}
		cursor.execute("SELECT moderator FROM user_details WHERE username = ?;",(username,))
		retrieved_moderator_tuple = cursor.fetchone()
		retrieved_moderator = retrieved_moderator_tuple[0]
		if retrieved_moderator == "True":
			payload = {"username": username, "moderator": "True"}
		else:
			payload = {"username": username}

		header_json = json.dumps(header)
		payload_json = json.dumps(payload, sort_keys = False)
		
		encoded_header = base64.urlsafe_b64encode(header_json.encode('utf-8')).decode('utf-8')
		encoded_payload = base64.urlsafe_b64encode(payload_json.encode('utf-8')).decode('utf-8')

		return json.dumps({"status": 1, "jwt": create_jwt(encoded_header,encoded_payload)})
		
	elif password_calculated != retrieved_password[0]:
		return json.dumps({"status": 2, "jwt": "NULL"})
	conn.commit()
	conn.close()


def create_jwt(encoded_header,encoded_payload): 
	with open('key.txt' , 'r') as key:
		key = key.read().strip()
	join_header_payload = f"{encoded_header}.{encoded_payload}"
	signature = hmac.new(key.encode('utf-8'), join_header_payload.encode('utf-8'), hashlib.sha256).hexdigest()
	jwt_token = f"{join_header_payload}.{signature}"
	return jwt_token

def decode_jwt(jwt_token):
	with open('key.txt', 'r') as key:
		key = key.read().strip()
	jwt_list = jwt_token.split('.')

	header_jwt = jwt_list[0]
	payload_jwt = jwt_list[1]
	signature_jwt = jwt_list[2]

	header_bytes = (base64.urlsafe_b64decode((header_jwt).encode('utf-8')))
	payload_bytes = (base64.urlsafe_b64decode((payload_jwt).encode('utf-8')))
	
	decoded_header = (header_bytes).decode('utf-8')
	decoded_payload = (payload_bytes).decode('utf-8')
	
	header_data = json.loads(decoded_header)
	payload_data = json.loads(decoded_payload) 

	header_data = json.dumps(header_data) #this is converting the dictionary to a json string
	payload_data = json.dumps(payload_data, sort_keys = False)

	join_header_payload = f"{header_jwt}.{payload_jwt}"
	newly_created_signature = hmac.new(key.encode('utf-8'), join_header_payload.encode('utf-8'), hashlib.sha256).hexdigest()
	if newly_created_signature == signature_jwt:
		return True, json.loads(payload_data)
	else:
		return False, payload_data


@app.route('/create_movie',methods=(['POST']))
def create_movie():
	conn = get_db()
	cursor = conn.cursor()
	try:
		title = request.form.get('title')
		synopsis = request.form.get('synopsis')
		movie_id = request.form.get('movie_id')
		genre = request.form.get('genre') 

		authorisation = request.headers['Authorization']
		payload_boolean ,payload_data_retrieved = decode_jwt(authorisation)

		if payload_boolean == False:
			return json.dumps({"status": 2})
		elif payload_boolean == True:
			if "moderator" in payload_data_retrieved:
				if genre is not None: 
					genre_object = json.loads(genre)
					for key in genre_object:
						genre_name = genre_object[key]
						cursor.execute("INSERT INTO movie_genres(movie_id, genre) VALUES(?,?);", (movie_id, genre_name))
				cursor.execute("INSERT INTO movie_details(title, synopsis, movie_id) VALUES(?,?,?);", (title, synopsis, movie_id))
		conn.commit()
		return json.dumps({"status": 1})
	except sqlite3.IntegrityError as e:
		if ("UNIQUE constraint failed: movie_details.movie_id" in str(e)):
			return json.dumps({"status": 2}) 
	finally:
		conn.close()


@app.route('/review',methods = (['POST']))
def review_movie():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("PRAGMA foreign_keys = ON;")
	try:
		movie_id = request.form.get("movie_id")
		review_id = request.form.get("review_id")
		rating = request.form.get("rating")
		text = request.form.get("text")
		if int(rating) < 0 or int(rating) > 5:
			return json.dumps({"status": 2})
		authorisation = request.headers['Authorization']
		payload_boolean ,payload_data_retrieved = decode_jwt(authorisation)
		user_name = payload_data_retrieved["username"]

		if payload_boolean == False:
			return json.dumps({"status": 2})
		elif payload_boolean == True:
			tuple_movie_ids = cursor.execute("SELECT movie_id FROM movie_details;") 
			tuple_movie_ids = tuple_movie_ids.fetchall()
			count = 0
			for id in tuple_movie_ids:
				if int(movie_id) == id[0]:
					count = 1
			if count == 0:
				return json.dumps({"status": 2})
			else:
				cursor.execute("INSERT INTO movie_reviews(username, rating, text, movie_id, review_id) VALUES(?,?,?,?,?);", (user_name, rating, text, movie_id, review_id))
		conn.commit()
		return json.dumps({"status": 1})
	except sqlite3.IntegrityError as e:
		if ("FOREIGN KEY constraint failed" in str(e)):
			return json.dumps({"status": 2})
		return json.dumps({"status": 2})
	finally:
		conn.close()

@app.route("/view_movie/<int:id>",methods = (['GET']))
def view_movie(id):
	conn = get_db()
	cursor = conn.cursor()
	recieved_auth  = request.headers["Authorization"]
	boolean, payload_data = decode_jwt(recieved_auth)
	if boolean == False:
		return json.dumps({"status": 2, "data": "NULL"})
	title_boolean = request.args.get('title')
	synopsis_boolean = request.args.get('synopsis')
	genre_boolean = request.args.get('genre')
	critic_boolean = request.args.get('critic')
	audience_boolean = request.args.get('audience')
	reviews_boolean = request.args.get('reviews')
	data_returned = {}

	cursor.execute("SELECT title FROM movie_details WHERE movie_id = ?;",(id,))
	title = cursor.fetchone() 
	
	cursor.execute("SELECT synopsis FROM movie_details WHERE movie_id = ?;",(id,))
	synopsis = cursor.fetchone()

	cursor.execute("SELECT genre FROM movie_genres WHERE movie_id = ?;",(id,))
	genre = cursor.fetchall()
	genre_list = []
	for each_genre in genre:
		genre_list.append(each_genre[0]) 

	critic_score, audience_score = get_critic_details(id)
	cursor.execute("SELECT username, rating, text FROM movie_reviews WHERE movie_id = ?;",(id,))
	review_details_retrieved = cursor.fetchall() 
	reviews_array = []
	for each in review_details_retrieved:
		user_collected = each[0]
		rating_collected = each[1]
		text_collected = each[2]
		review_dict = {"user": user_collected, "rating": str(rating_collected), "text": text_collected}
		reviews_array.append(review_dict)

	if title_boolean == "True":
		data_returned["title"] = title[0]
	if synopsis_boolean == "True":
		data_returned["synopsis"] = synopsis[0]
	if genre_boolean == "True":
		data_returned["genre"] = genre_list
	if critic_boolean == "True":
		data_returned["critic"] = critic_score
	if audience_boolean == "True":
		data_returned["audience"] = audience_score
	if reviews_boolean == "True":
		data_returned["reviews"] = reviews_array

	conn.commit()
	conn.close()
	return json.dumps({"status": 1, "data": data_returned})

def get_critic_details(id):
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT username, review_id FROM movie_reviews WHERE movie_id = ?;",(id,))
	username_review_id = cursor.fetchall() 
	boolean_dictionery = {}
	for each_review in username_review_id:
		userid = each_review[0]
		reviewid = each_review[1]
		cursor.execute("SELECT critic FROM user_details WHERE username = ?;",(userid,))
		critic_status = cursor.fetchone()
		critic_status = critic_status[0]
		boolean_dictionery[reviewid] = critic_status
	current_critic_rating = 0
	critic_count = 0
	current_audience_rating = 0
	audience_count = 0
	for item in boolean_dictionery.keys():
		if boolean_dictionery[item] == "True":
			cursor.execute("SELECT rating FROM movie_reviews WHERE review_id = ?;",(item,))
			critic_rating = cursor.fetchone()
			critic_rating = critic_rating[0]
			current_critic_rating += critic_rating
			critic_count += 1
		elif boolean_dictionery[item] == "False":
			cursor.execute("SELECT rating FROM movie_reviews WHERE review_id = ?;",(item,))
			audience_rating = cursor.fetchone()
			audience_rating = audience_rating[0]
			current_audience_rating += audience_rating
			audience_count += 1
	if critic_count != 0:
		critic_score = f"{(current_critic_rating / critic_count):.2f}"
	elif critic_count == 0:
		critic_score = "0.00"

	if audience_count != 0:
		audience_score = f"{(current_audience_rating / audience_count):.2f}"
	elif audience_count == 0:
		audience_score = "0.00"
	return critic_score, audience_score

@app.route("/search", methods=["GET"])
def search():
	conn = get_db()
	cursor = conn.cursor()

	genre = request.args.get('genre')
	feed = request.args.get('feed')
	authorisation = request.headers['Authorization']
	payload_boolean ,payload_data_retrieved = decode_jwt(authorisation)
	if payload_boolean == False:
		return json.dumps({"status":2})
	elif payload_boolean == True:
			return_dict = {}
			if genre :
				cursor.execute("SELECT movie_id FROM movie_genres WHERE genre = ?;",(genre,))
				movie_ids = cursor.fetchall()
			if feed:
				cursor.execute("SELECT movie_id,created_at FROM movie_details ORDER BY created_at DESC LIMIT 5;")
				movie_ids = cursor.fetchall()
			for id in movie_ids:
				current_id = id[0]
				cursor.execute("SELECT title, synopsis FROM movie_details WHERE movie_id = ?;",(current_id,))
				details = cursor.fetchone()	
				title = details[0]
				synopsis = details[1]
				cursor.execute("SELECT username, rating, text FROM movie_reviews WHERE movie_id = ?;",(current_id,))
				review_details_retrieved = cursor.fetchall() 
				reviews_array = []
				for each in review_details_retrieved:
					user_collected = each[0]
					rating_collected = each[1]
					text_collected = each[2]
					review_dict = {"user": user_collected, "rating": str(rating_collected), "text": text_collected}
					reviews_array.append(review_dict)
			
				critic_score, audience_score = get_critic_details(current_id)

				cursor.execute("SELECT genre FROM movie_genres WHERE movie_id = ?;",(current_id,))
				genre = cursor.fetchall()
				genre_list = []
				for each_genre in genre:
					genre_list.append(each_genre[0])

				return_dict[current_id] = {"title": title, "synopsis": synopsis, "genre": genre_list, "critic": critic_score, "audience": audience_score, "reviews": reviews_array}
			conn.commit()
			conn.close()
			return json.dumps({"status": 1, "data": return_dict})


@app.route("/delete", methods=["POST"])
def delete():
	conn = get_db()
	cursor = conn.cursor()
	authorisation = request.headers['Authorization']
	payload_boolean ,payload_data_retrieved = decode_jwt(authorisation)
	if payload_boolean == False:
		return json.dumps({"status":2})
	elif payload_boolean == True:
		username_to_delete = request.form.get("username")
		review_id = request.form.get("review_id")
		get_user_name = payload_data_retrieved["username"]
		get_moderator_boolean = payload_data_retrieved.get("moderator")

		if username_to_delete:
			if get_user_name != username_to_delete:
				return json.dumps({"status": 2})
			cursor.execute("DELETE FROM user_details WHERE username = ?;",(username_to_delete,))
			cursor.execute("DELETE FROM user_passwords WHERE username = ?;",(username_to_delete,))
			cursor.execute("DELETE FROM movie_reviews WHERE username = ?;",(username_to_delete,))
		if review_id:
			cursor.execute("SELECT username FROM movie_reviews WHERE review_id = ?;",(review_id,))
			username_review = cursor.fetchone()
			if username_review[0] != get_user_name and get_moderator_boolean != "True":
				return json.dumps({"status": 2})
			elif username_review[0] == get_user_name or get_moderator_boolean == "True":
				cursor.execute("DELETE FROM movie_reviews WHERE review_id = ?;",(review_id,))
		conn.commit()
		conn.close()
		return json.dumps({"status": 1})