## Introduction

This application provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

This is a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication.

- User can login with google account or can sign up a user account wiht email address
- After login, user can create new Category
- After login, user can create new items, and user can edit/delete their own items, but not items created by other users 
- To get data from `/catalog.json`, client need to provide valid email and password, or client can access `/token` first with valid email and password to get a valid token from the server, then client can access `/catalog.json` with the token 

## Python version 2.7

## Contents:
- models.py
- security.py
- views.py
- static
	-- styles.css
- templates
	-- index.html
	-- publicindex.html
	-- itemlist.html
	-- login.html
	-- newcategory.html
	-- item.html
	-- publicitem.html
	-- signup.html
	-- newitem.html
	-- deleteitem.html
	-- edititem.html
	-- latestitemlist.html
	-- main.html
	-- header.html
	

## Prequisition
To run this application successfully, you should install below packages:
`pip install Flask`

To enable google sign in, you should place a file named `client_secret_google.json` in the same folder where views.py resides
In `client_secret_google.json`, google client id and password should be included



## Start the Application
`python views.py`

The default port numer is: 5000


