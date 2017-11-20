## Introduction

This application provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

This is a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication (google).

- User can login with google account or can sign up a user account wiht email address
- After login, user can create new Category
- After login, user can create new items, and user can edit/delete their own items, but not items created by other users 

Below JSON endpoints are also implemented:
- /json/catalog
- /json/<category_name>
- /json/<category_name>/<item_name> 

To access the API endpoint to get the data back in JSON format, user can do either one of below:
- access `/token` providing email and password to get a valid token from the server, then client can access the JSON endpoints listed above by passing along the token
- access `/oauth/google` providing the one time authorization code from google to get a valid token from the server, then client can access the JSON endpoints listed above by passing along the token

	 either provide email and password get data from `/catalog.json`, client need to provide valid email and password, or client can access `/token` first with valid email and password to get a valid token from the server, then client can access `/catalog.json` with the token 

## Python version 2.7

## Contents:
- models.py
- security.py
- views.py
- requirements.txt
- static
	* styles.css
- templates
	* index.html
	* publicindex.html
	* itemlist.html
	* login.html
	* newcategory.html
	* item.html
	* publicitem.html
	* signup.html
	* newitem.html
	* deleteitem.html
	* edititem.html
	* latestitemlist.html
	* main.html
	* header.html
	

## Prequisition
To run this application successfully, you should install below packages:

`pip install Flask`
`pip install SQLAlchemy`
`pip install passlib`
`pip install flask_httpauth`
`pip install httplib2`
`pip install --upgrade oauth2client`
`pip install requests`

To enable google sign in, you should place a file named `google.json` in the same folder where views.py resides.
In `google.json`, google client id and password should be included


## Start the Application
`python views.py`

The default port numer is: 5000
And after the application run, the database will be created automtically
