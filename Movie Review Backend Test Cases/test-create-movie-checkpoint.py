import requests
import json


try:
	URLclear = "http://127.0.0.1:5000/clear"
	r_clear = requests.get(url = URLclear)
	 
	URL = "http://127.0.0.1:5000/create_user"
	PARAMS = {'first_name': 'James', 'last_name': 'Mariani', 'username': 'jmariani', 'email_address': 'james@mariani.com', 'password': 'Examplepassword1', 'moderator': True, 'critic': True, 'salt': 'FE8x1gO+7z0B'}

	r = requests.post(url = URL, data = PARAMS)
	data = r.json()

	solution = {"status": 1, "pass_hash": "9060e88fe7f9a95839a19926d517a442da58f47c48edc2f37e1c3aea5f8956fc"}

	for key in solution:
		if solution[key] != data[key]:
			print('Test Failed 1')
			quit()

	URLLogin = "http://127.0.0.1:5000/login"
	LOGINPARAMS = {'username': 'jmariani', 'password': 'Examplepassword1'}

	r_login = requests.post(url = URLLogin, data = LOGINPARAMS)
	login_data = r_login.json()

	URLCreateMovie = "http://127.0.0.1:5000/create_movie"
	MOVIEPARAMS = {'title': 'The Godfather', 'synopsis': 'The aging patriarch of an organized crime dynasty transfers control of his clandestine empire to his reluctant son', 'movie_id': 524, 'genre': json.dumps({'genre1': 'Mafia'})}
	r_create_movie = requests.post(url = URLCreateMovie, data = MOVIEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dD221'})
	create_movie_data = r_create_movie.json()

	#bad jwt, should be rejected
	if create_movie_data['status'] != 2:
		print('Test Failed 2')
		quit()
	
	#correct jwt, should be accepted
	r_create_movie = requests.post(url = URLCreateMovie, data = MOVIEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dd221'})
	create_movie_data = r_create_movie.json()
	if create_movie_data['status'] != 1:
		print('Test Failed 3')
		quit()

	print('Test Passed')
except:
	print('Test Failed')
