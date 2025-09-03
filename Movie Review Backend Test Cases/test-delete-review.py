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
	MOVIEPARAMS = {'title': 'The Conjuring', 'synopsis': 'Paranormal investigators Ed and Lorraine Warren work to help a family terrorized by a dark presence in their farmhouse', 'movie_id': 102, 'genre': json.dumps({'genre1': 'Childrens', 'genre2': 'Horror'})}
	r_create_movie = requests.post(url = URLCreateMovie, data = MOVIEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqbWFyaWFuaSIsICJtb2RlcmF0b3IiOiAiVHJ1ZSJ9.d3a20e5290f8f85adf96eb4aecf52bee4c11ae2e8f8f67a2ed872920767dd221'})

	#review movie by karen
	URLReviewMovie = "http://127.0.0.1:5000/review"
	REVEIWPARAMS = {'movie_id': 102, 'review_id': 96, 'rating': 1, 'text': "Who said this was a kids movie?? My little darling is traumatized!!"}
	r_review_movie = requests.post(url = URLReviewMovie, data = REVEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})

	#review movie again by karen
	REVEIWPARAMS = {'movie_id': 102, 'review_id': 106, 'rating': 5, 'text': "Me and the Hubby enjoyed it though!"}
	r_review_movie = requests.post(url = URLReviewMovie, data = REVEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})

	#view movie by karen
	URLViewMovie = "http://127.0.0.1:5000/view_movie/102"
	VEIWPARAMS = {'audience': 'True'}
	r_view_movie = requests.get(url = URLViewMovie, params = VEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})
	view_data = r_view_movie.json()

	solution = json.dumps({'status': 1, 'data': {'audience': '3.00'}})
	solution_dict = json.loads(solution)

	if len(view_data['data']) != len(solution_dict['data']) or solution_dict['data']['audience'] != view_data['data']['audience']:
		quit()


	#delete review by karen
	URLDeleteReview = "http://127.0.0.1:5000/delete"
	DELETEPARAMS = {'review_id': 106}
	r_delete_movie = requests.post(url = URLDeleteReview, data = DELETEPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})

	VEIWPARAMS = {'audience': 'True'}
	r_view_movie = requests.get(url = URLViewMovie, params = VEIWPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJrYXJlbiJ9.3344eacf514c7ddb72498bf553cf8e0288de7b91a3ee938e56800b65caa8e5d2'})
	view_data = r_view_movie.json()

	solution = json.dumps({'status': 1, 'data': {'audience': '1.00'}})
	solution_dict = json.loads(solution)

	if len(view_data['data']) != len(solution_dict['data']) or solution_dict['data']['audience'] != view_data['data']['audience']:
		quit()

	print('Test Passed')
except:
	print('Test Failed')
