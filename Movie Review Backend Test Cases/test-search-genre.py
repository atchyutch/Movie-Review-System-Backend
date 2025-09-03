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

	#create and login karen
	PARAMS = {'first_name': 'Karen', 'last_name': 'Smith', 'username': 'karen', 'email_address': 'karen@smith.com', 'password': 'Cygwtpi4', 'moderator': False, 'critic': False, 'salt': 'xaxkRSzNPnP4'}
	r = requests.post(url = URL, data = PARAMS)

	LOGINPARAMS = {'username': 'karen', 'password': 'Cygwtpi4'}
	r_login = requests.post(url = URLLogin, data = LOGINPARAMS)

	#create movie
	URLCreateMovie = "http://127.0.0.1:5000/create_movie"
	MOVIEPARAMS = {'title': 'The Conjuring', 'synopsis': 'Paranormal investigators Ed and Lorraine Warren work to help a family terrorized by a dark presence in their farmhouse', 'movie_id': 102, 'genre': json.dumps({'genre1': 'Childrens'})}
	r_create_movie = requests.post(url = URLCreateMovie, data = MOVIEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dd221'})

	#create second movie
	MOVIEPARAMS = {'title': 'The Godfather', 'synopsis': 'The aging patriarch of an organized crime dynasty transfers control of his clandestine empire to his reluctant son', 'movie_id': 52, 'genre': json.dumps({'genre1': 'Mafia'})}
	r_create_movie = requests.post(url = URLCreateMovie, data = MOVIEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dd221'})

	#review movie by karen
	URLReviewMovie = "http://127.0.0.1:5000/review"
	REVEIWPARAMS = {'movie_id': 102, 'review_id': 96, 'rating': 1, 'text': "Who said this was a kids movie?? My little darling is traumatized!!"}
	r_review_movie = requests.post(url = URLReviewMovie, data = REVEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})

	#review second movie by karen
	REVEIWPARAMS = {'movie_id': 52, 'review_id': 41, 'rating': 0, 'text': "It insists upon itself"}
	r_review_movie = requests.post(url = URLReviewMovie, data = REVEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})

	#search by feed by jmariani
	URLSearchGenre = "http://127.0.0.1:5000/search"
	SEARCHPARAMS = {'genre': 'Childrens'}
	r_search = requests.get(url = URLSearchGenre, params = SEARCHPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dd221'})
	search_data = r_search.json()

	solution = json.dumps({'status': 1, 'data': {102: {'title': 'The Conjuring', 'synopsis': 'Paranormal investigators Ed and Lorraine Warren work to help a family terrorized by a dark presence in their farmhouse', 'genre': ['Childrens'], 'critic': '0.00', 'audience': '1.00', 'reviews': [{'user': 'karen', 'rating': '1','text': 'Who said this was a kids movie?? My little darling is traumatized!!'}]}}})
	solution_dict = json.loads(solution)

	if len(search_data['data']) != len(solution_dict['data']):
		quit()

	for movie in solution_dict['data']:
		for x in solution_dict['data'][movie]:
			if x == 'genre':
				if len(solution_dict['data'][movie][x]) != len(search_data['data'][movie][x]):
					quit()
				else:
					for genre in search_data['data'][movie][x]:
						if genre not in solution_dict['data'][movie][x]:
							quit()
			elif x == 'reviews':
				if len(solution_dict['data'][movie][x]) != len(search_data['data'][movie][x]):
					quit()
				else:
					for review in search_data['data'][movie][x]:
						match = False
						for sol_review in solution_dict['data'][movie][x]:
							if (review['user'] != sol_review['user']) or (review['rating'] != sol_review['rating']) or (review['text'] != sol_review['text']):
								continue
							else:
								match = True
								break
						if not match:
							print('Test Failed')
							quit()
								
			elif solution_dict['data'][movie][x] != search_data['data'][movie][x]:
				quit()

	print('Test Passed')
except:
	print('Test Failed')
