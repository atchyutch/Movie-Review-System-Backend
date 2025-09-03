import requests
import json


try:
	URLclear = "http://127.0.0.1:5000/clear"
	r_clear = requests.get(url = URLclear)
	 
	#create and login jmariani
	URL = "http://127.0.0.1:5000/create_user"
	PARAMS = {'first_name': 'James', 'last_name': 'Mariani', 'username': 'jmariani', 'email_address': 'james@mariani.com', 'password': 'Examplepassword1', 'moderator': True, 'critic': True, 'salt': 'FE8x1gO+7z0B'}

	r = requests.post(url = URL, data = PARAMS)

	URLLogin = "http://127.0.0.1:5000/login"
	LOGINPARAMS = {'username': 'jmariani', 'password': 'Examplepassword1'}
	r_login = requests.post(url = URLLogin, data = LOGINPARAMS)

	#create and login pgriffin
	PARAMS = {'first_name': 'Peter', 'last_name': 'Griffin', 'username': 'pgriffin', 'email_address': 'peter@griffin.com', 'password': 'Igapfakbsm2', 'moderator': True, 'critic': True, 'salt': 'K8ENdhu#nxe3'}
	r = requests.post(url = URL, data = PARAMS)

	LOGINPARAMS = {'username': 'pgriffin', 'password': 'Igapfakbsm2'}
	r_login = requests.post(url = URLLogin, data = LOGINPARAMS)

	#create movie
	URLCreateMovie = "http://127.0.0.1:5000/create_movie"
	MOVIEPARAMS = {'title': 'The Godfather', 'synopsis': 'The aging patriarch of an organized crime dynasty transfers control of his clandestine empire to his reluctant son', 'movie_id': 524, 'genre': json.dumps({'genre1': 'Mafia'})}
	r_create_movie = requests.post(url = URLCreateMovie, data = MOVIEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dd221'})

	#review movie by pgriffin
	URLReviewMovie = "http://127.0.0.1:5000/review"
	REVEIWPARAMS = {'movie_id': 524, 'review_id': 41, 'rating': 0, 'text': "It insists upon itself"}
	r_review_movie = requests.post(url = URLReviewMovie, data = REVEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJwZ3JpZmZpbiIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.ce2d1ac59971017829258582b60e9b605bb30e74546341d611f32a2bdb5cf01c'})
	review_movie_data = r_review_movie.json()

	if review_movie_data['status'] != 1:
		print('Test Failed')
		quit()
		
	print('Test Passed')
except:
	print('Test Failed')
