from models import Base, User, Category, Item
from flask import Flask, flash, make_response, render_template, redirect
from flask import request, jsonify, url_for, g, abort
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask_httpauth import HTTPBasicAuth
from flask import session as login_session
import random
import string
import httplib2
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import json
import re
import requests
auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
app.secret_key = "testing"

CLIENT_ID = json.loads(open('google.json', 'r').read())['web']['client_id']


@app.route('/login', methods=['GET', 'POST'])
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('pwd')
        if(userLogin(email, password)):
            return redirect(url_for('catalogHandler'))
        else:
            return redirect(url_for('login'))
    else:
        return render_template('login.html', STATE=state)


@auth.verify_password
def verify_password(email_or_token, password):
    # try to see if it is a token first
    user_id = User.verify_auth_token(email_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(email=email_or_token).first()
        if not user or not user.verify_password(password):
            return False

    g.user = user
    return True


@app.route('/oauth/<provider>', methods=['POST'])
def oauth_login(provider):

    # STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')

    # print "Step1 - Complete, received auth code %s" %auth_code
    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('google.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade auth code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])

        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            return response
        # print "Step 2 Complete! Access Token : %s " % credentials.access_token

        # STEP 3 - Find User or make a new one
            # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/plus/v1/people/me"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()

        name = data['displayName']
        email = data['emails'][0]['value']

        # see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if user is None:
            user = User(username=name, email=email)
            session.add(user)
            session.commit()

        # STEP 4 - Make token
        token = user.generate_auth_token(600)

        # STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})

    else:
        return 'Unrecoginized Provider'


def userLogin(email, password):
    if email is None or email == "" or password is None or password == "":
        flash("Email or Password is empty")
        return False
    user = session.query(User).filter_by(email=email).first()
    print "password herer: "
    print password
    if not user or not user.verify_password(password):
        flash("Sorry, we weren't able to find the email address and \
        password combination you entered")
        return False
    login_session['user_id'] = user.id
    login_session['email'] = email
    login_session['username'] = user.username
    login_session['picture'] = user.picture
    return True


def verify_password_format(password):
    if(len(password) < 8 or len(password) > 20):
        return False
    if re.match('^[A-Za-z0-9]{8,20}', password):
        return True
    return False


def verify_email_format(email):
    match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
    if match:
        return True
    return False


@app.route('/fbconnect', methods=['GET', 'POST'])
def fbconnect():
    # validate state token
    if request.args.get('state') != login_session['state']:
                response = make_response(json.dumps('Invalid token'), 401)
                response.headers['Content-Type'] = 'application/json'
                return response

    access_token = request.data
    # exchange a long live token
    app_id = json.loads(open('fb_client_secret.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secret.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    userinfor_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(":")[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % (token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']
    login_session['provider'] = 'facebook'
    login_session['access_token'] = token
    login_session['firstname'] = data['name']
    login_session['lastname'] = data['name']

    # get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    # check if user exist
    uid = getUserID(login_session['email'])
    if not uid:
        uid = createUserFromOauth(login_session)
    login_session['user_id'] = uid

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/gconnect', methods=['GET', 'POST'])
def gconnect():
    # validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state token'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # obtain one time authorization code
    code = request.data

    try:
        # upgrade the authorization code into a credential object
        oauth_flow = flow_from_clientsecrets('google.json', scope='profile', redirect_uri='postmessage')
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(json.dumps('Failed to ugrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    # check tha access token is valid to avoid confused deputy problem vulnerability
    url = ('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s' % (access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if there was an error in the access token
    if(result.get('error') is not None):
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['sub'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # verify the access token is valid for this app
    if result['aud'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # store the accress token in the session for later use
    login_session['access_token'] = credentials.access_token
    # get user info
    userinfo_url = "https://www.googleapis.com/plus/v1/people/me"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get('https://www.googleapis.com/plus/v1/people/me', params=params)
    data = answer.json()

    login_session['username'] = data['displayName']
    login_session['picture'] = data['image']['url']
    login_session['email'] = data['emails'][0]['value']
    login_session['provider'] = 'google'
    login_session['google_id'] = data['id']
    login_session['firstname'] = data['name'].get('givenName')
    login_session['lastname'] = data['name'].get('familyName')
    # see if user exist in the database, if not, then make a new one
    uid = getUserID(login_session['email'])
    if uid is None:
        uid = createUserFromOauth(login_session)

    login_session['user_id'] = uid

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # the access token must be included to successfull log out
    access_token = login_session['access_token']
    url = "https://graph.facebook.com/%s/permissions?access_token=%s" % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    msg = result.split(":")
    tag = result[2:9]
    flag = result[11:15]
    if tag == "success" and flag == "true":
        del login_session['access_token']
        del login_session['facebook_id']
        del login_session['firstname']
        del login_session['lastname']
        del login_session['username']
        del login_session['picture']
        del login_session['email']
        return True
    else:
        return False


@app.route('/gdiconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('current user not logged int yet'))
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % (access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['google_id']
        del login_session['firstname']
        del login_session['lastname']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash("Log out successfully")
        return True
    else:
        flash("problem while logout")
        return False


@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            if (gdisconnect()):
                del login_session['provider']
                del login_session['user_id']
                flash("You have successfuly logged out")
                redirect('/catalog')
            else:
                flash("Something got wrong, not logged out yet!")
            return redirect('/catalog')

        if login_session['provider'] == 'facebook':
            if (fbdisconnect()):
                del login_session['provider']
                del login_session['user_id']
                flash("You have successfully logged out")
                return redirect('/catalog')
            else:
                flash("Some thing got wrong, not logged out yet")
                return redirect('/catalog')

    elif 'username' in login_session:
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have successfully logged out")
        return redirect('/catalog')

    else:
        print "error here, try again"
        flash("Something got worng not logged out yet")
        return redirect('/catalog')


@app.route('/')
@app.route('/catalog')
def catalogHandler():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(Item.id.desc()).limit(10).all()
    allitems = []
    for item in items:
        cat = session.query(Category).filter_by(id=item.category_id).first()
        allitems.append({'category': cat.name, 'item': item.name})

    if 'username' not in login_session:
        return render_template('publicindex.html', categories=categories, items=allitems)
    else:
        return render_template('index.html', categories=categories, items=allitems)


@app.route('/category', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == "GET":
        return render_template("newcategory.html")
    else:
        name = request.form.get("name")
        desc = request.form.get("desc")
        find_name = session.query(Category).filter_by(name=name).first()
        if find_name:
            flash("Operation failed: category with name %s exist already!" % (name))
            render_template("newcategory.html")
        category = Category(name=name, description=desc)
        session.add(category)
        session.commit()
        flash("Category created successfully")
        return render_template("newcategory.html")


@app.route('/item', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
                return redirect('/login')
    categories = session.query(Category).all()
    if request.method == "GET":
            return render_template("newitem.html", categories=categories)
    else:
        name = request.form.get("name")
        desc = request.form.get("desc")
        cat = request.form.get("select")
        if cat is None:
            return "Operation failed, no category selected!, please select one!"

        cat_name = session.query(Category).filter_by(id=cat).first().name
        find_item = session.query(Item).filter_by(name=name).first()
        if find_item:
            find_cat = session.query(Category).filter_by(id=find_item.category_id).first()
            if int(find_cat.id) == int(cat):
                flash("Operation failed: item under category %s with the name %s exist already!" % (cat_name, name))
                return render_template("newitem.html", categories=categories)
        item = Item(name=name, description=desc, category_id=cat, user_id=login_session['user_id'])
        session.add(item)
        session.commit()
        flash("Item %s created successfully!" % (name))
        return render_template("newitem.html", categories=categories)


@app.route('/catalog/<string:category_name>/items')
def showItemList(category_name):
    categories = session.query(Category).all()
    category_obj = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category_id=category_obj.id).all()
    return render_template('itemlist.html', categories=categories, category=category_name, items=items, count=len(items))


@app.route('/catalog/<string:category_name>/<string:item_name>')
def showItem(category_name, item_name):
    # if user login in show edit and delete button url_for('publicitem.html')
    # otherwies, show the public version url_for('item.html')
    category = session.query(Category).filter_by(name=category_name).first()
    if not category:
        return "Operation failed: No this category %s" % (category_name)
    item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
    if not item:
        return "Operation failed: No this item: %s under category: %s" % (item_name, category_name)
    if 'username' not in login_session or item.user_id != login_session['user_id']:
        return render_template("publicitem.html", item=item, category=category)
    else:
        return render_template("item.html", item=item, category=category)


@app.route('/catalog/<string:category_name>/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')

    editItem = session.query(Item).filter_by(name=item_name).first()
    if editItem.user_id != login_session['user_id']:
        return "<script> function myFunction() {alert('You are not authorized to edit this item');}</script><body onload='myFunction()''>"

    if request.method == 'GET':
        category = session.query(Category).filter_by(name=category_name).first()
        if not category:
            return "Operation failed: No this category %s" % (category_name)
        item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
        if not item:
            return "Operation failed: No this item: %s under category: %s" % (item_name, category_name)

        categories = session.query(Category).all()
        return render_template('edititem.html', categories=categories, category=category, item=item)
    else:
        category = session.query(Category).filter_by(name=category_name).first()
        item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
        name = request.form.get('name')
        desc = request.form.get('desc')
        cate = request.form.get('select')
        if(name):
            item.name = name
        if(desc):
            item.description = desc
        if(cate):
            item.category_id = cate

        session.commit()

        return redirect(url_for('catalogHandler'))


@app.route('/catalog/<string:category_name>/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')

    deleteItem = session.query(Item).filter_by(name=item_name).first()
    if deleteItem.user_id != login_session['user_id']:
        return "<script> function myFunction() {alert('You are not autorized to delete this item');}</script><body onload='myFunction()'>"

    category = session.query(Category).filter_by(name=category_name).first()
    if not category:
        return "Operation failed: No this category %s" % (category_name)
    item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
    if not item:
        return "Operation failed: No this item: %s under category: %s" % (item_name, category_name)

    if request.method == 'GET':
        return render_template('deleteitem.html', category=category, item=item)
    else:
        session.delete(item)
        session.commit()
        flash("Item %s deleted from the database" % (item_name))
        return redirect(url_for('catalogHandler'))


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/json/catalog')
@auth.login_required
def showAllItmesJSON():
    categories = session.query(Category).all()
    results = []

    for category in categories:
        items = session.query(Item).filter_by(category_id=category.id).all()
        results.append({"id": category.id, "name": category.name, "description": category.description, "items": [item.serialize for item in items]})

    return jsonify(catogories=[result for result in results])


@app.route('/json/<string:category_name>')
@auth.login_required
def showItemsInACategoryJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    if category is None:
        response = make_response(json.dumps('Invalid uri, category not found'), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(items=[item.serialize for item in items])


@app.route('/json/<string:category_name>/<string:item_name>')
@auth.login_required
def showItemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).first()
    if category is None:
        response = make_response(json.dumps('Invalid uri, category not found'), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    item = session.query(Item).filter_by(name=item_name).first()
    if item is None:
        response = make_response(json.dumps('Invalid uri, item not found'), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    return jsonify(item=item.serialize)


# user helper function
def createUserFromOauth(login_session):
    new_user = User(first_name=login_session['firstname'], last_name=login_session['lastname'], username=login_session['username'], email=login_session['email'].decode('utf-8'))
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).frist()
    return user


def getUserID(mail):
    try:
        user = session.query(User).filter_by(email=mail).first()
        user = session.query(User).filter_by(email=mail.decode('utf-8')).first()
        return user.id
    except:
        return None


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        email = request.form.get('email')
        username = request.form.get('username')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        password = request.form.get('pwd')
        password_confirm = request.form.get('pwd_confirm')

        if email is None or email == "" or password is None or password == "" or username is None or username == "":
            return "Missing argument, Email, Username and Password field could not be empty"

        if (not verify_email_format(email)):
            return "Email format is not correct, please enter valid email address"

        if (not verify_password_format(password)):
            return "Password must contains 8-20 alphanumeric characters, \
                no special characters are allowed!"
        if password != password_confirm:
            return "Password not match"

        # check if user profile with the same email address exist or not in the database
        user = session.query(User).filter_by(email=email).first()
        if user is not None:
            flash("Operation failed: email address %s already exist in the database" % (email))
            return redirect('signup')

        new_user = User(first_name=firstname, last_name=lastname, username=username, email=email)
        new_user.hash_password(password)
        session.add(new_user)
        session.commit()
        user = session.query(User).filter_by(email=email).first()

        flash("User %s created successfully! You can login in now by clicking the Login \
            link on the upper right corner!" % (email))
        return redirect('signup')


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

