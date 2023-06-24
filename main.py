from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, jsonify, _request_ctx_stack, abort
from google.cloud import datastore
import requests
from functools import wraps
import json
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
from werkzeug.exceptions import HTTPException
from six.moves.urllib.parse import urlencode


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

client = datastore.Client()

BOATS = "boats"
LOADS = "loads"
USERS = "users"

CLIENT_ID = env.get("AUTH0_CLIENT_ID")
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
DOMAIN = env.get("AUTH0_DOMAIN")

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.errorhandler(403)
def forbidden_403(e):
    return jsonify(Error=str(e.description)), 403

@app.errorhandler(405)
def method_not_allowed_405(e):
    return jsonify(Error="You are not supporting edit/delete of the entire list of boats/loads"), 405

@app.errorhandler(406)
def not_acceptable_406(e):
    return jsonify(Error="You are sending a request with Accept header set to a MIME type that is NOT supported"), 406


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload  

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    session["jwt"] = session["user"]["id_token"]
    return redirect("/userInfo")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/userInfo")
def userInfo():
    users_query = client.query(kind=USERS)
    list_all_users = list(users_query.fetch())
    user_id_exist = False
    for user in list_all_users:
        if user["user_id"] == session["user"]["userinfo"]["sub"]:
            user_id_exist = True
    if user_id_exist == False:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({"user_id": session["user"]["userinfo"]["sub"]})
        client.put(new_user)
    return render_template("userInfo.html", session=session.get('user'), pretty=session.get('jwt'))

@app.route("/users", methods=["GET"])
def users_get():
    if request.method == "GET":
        # List all the users currently registered in application,
        # even if they don't currently have any relationship with a non-user entity.
        users_query = client.query(kind=USERS)
        list_all_users = list(users_query.fetch())
        for user in list_all_users:
            user["id"] = user.key.id
        return jsonify(list_all_users), 200
    else:
        return jsonify(error="Method not recognized")
    

@app.route("/boats", methods=["POST", "GET", "DELETE", "PUT"])
def boats_post_get():
    if request.method == "POST":
        # for final

        # Create a new boat with a valid JWT.
        # If JWT is missing or invalid, returns 401 status code.
        
        # 406 status code - Request with Accept header set to unsupported MIME type.
        if not 'application/json' in request.accept_mimetypes:
            abort(406)
            return
        
        payload = verify_jwt(request)
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(BOATS))
        owner_id = payload["sub"]
        new_boat.update({"name": content["name"], "type": content["type"], 
                         "length": content["length"],
                         "ownerID": owner_id, "loads": []})
        client.put(new_boat)
        new_boat["self"] = str(request.base_url) + "/" + str(new_boat.key.id)
        new_boat["id"] = str(new_boat.key.id)
        return jsonify(new_boat), 201

    elif request.method == "GET":
        # for final

        # If an entity is related to a user, then this must
        # show only those entities in the collection which are
        # related to the user corresponding to the valid JWT provided
        # in the request.
        #
        # For an entity that is NOT related to users, this should
        # show all the entities in the collection
        #
        # - pagination: should return 5 boats per page / next link (except last page)
        # - a property that how many total items are in the collection
        # - self links
        boats_query = client.query(kind=BOATS)
        all_boats_query = client.query(kind=BOATS)
        
        try:
            payload = verify_jwt(request)
            sub_jwt_val = payload["sub"]
            boats_query.add_filter("ownerID", "=", sub_jwt_val)
            list_boats_query = list(boats_query.fetch())
            total_items_num = len(list_boats_query)
            
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = boats_query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            for e in results:
                e["total_items"] = total_items_num
                e["id"] = e.key.id
                e["self"] = str(request.base_url) + "/" + str(e.key.id)
                if len(e["loads"]) != 0:
                    for l in e["loads"]:
                        l["self"] = str(request.url_root) + "loads/" + str(l["id"])
            output = {"boats": results}

            if next_url:
                output["next"] = next_url

            return json.dumps(output), 200
        except:
            list_boats_query = list(all_boats_query.fetch())
            total_items_num = len(list_boats_query)            

            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = all_boats_query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            
            for e in results:
                e["total_items"] = total_items_num
                e["id"] = e.key.id
                e["self"] = str(request.base_url) + "/" + str(e.key.id)
                if len(e["loads"]) != 0:
                    for l in e["loads"]:
                        l["self"] = str(request.url_root) + "loads/" + str(l["id"])
            output = {"boats": results}

            if next_url:
                output["next"] = next_url

            return json.dumps(output), 200
    elif request.method == "DELETE":
        # for final

        # 405 status code - DELETE request on root boat URL is not allowed.
        # Because you are not supporting deleting of the entire list of boats.
        abort(405)
        return
    elif request.method == "PUT":
        # for final

        # 405 status code - PUT request on root boat URL is not allowed.
        # Because you are not supporting editing of the entier list of boats.
        abort(405)
        return
    else:
        return jsonify(error="Method not recognized")
    

@app.route("/boats/<boat_id>", methods=["GET", "DELETE", "PATCH", "PUT"])
def get_delete_edit_boat(boat_id):
    if request.method == "GET":
        # for final

        # Get an existing boat with a valid JWT
        payload = verify_jwt(request)

        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        sub_jwt_val = payload["sub"]

        if str(boat["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return

        if len(boat["loads"]) != 0:
            for b in boat["loads"]:
                b["self"] = str(request.url_root) + "loads/" + str(b["id"])
        boat["id"] = boat_id
        boat["self"] = request.base_url
        return json.dumps(boat), 200
    elif request.method == "DELETE":
        # for final

        # Only the owner of a boat with a valid JWT
        # should be able to delete the boat
        payload = verify_jwt(request)

        boat_key = client.key(BOATS, int(boat_id))
        boat_to_delete = client.get(key=boat_key)

        sub_jwt_val = payload["sub"]
        if str(boat_to_delete["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return
        
        if len(boat_to_delete["loads"]) != 0:
            for load in boat_to_delete["loads"]:
                load_key = client.key(LOADS, int(load["id"]))
                load_to_update = client.get(key=load_key)
                load_to_update["carrier"] = None
                client.put(load_to_update)
        
        client.delete(boat_to_delete)
        return '', 204
    elif request.method == "PATCH":
        # for final

        # Update any sbsets of attributes of a boat while
        # the other attributes remain unchanged. With a valid JWT
        
        # 406 status code - Request with Accept header set to unsupported MIME type.
        if not 'application/json' in request.accept_mimetypes:
            abort(406)
            return

        payload = verify_jwt(request)
        sub_jwt_val = payload["sub"]
        content = request.get_json()

        with client.transaction():
            boat_key = client.key(BOATS, int(boat_id))
            boat_to_edit = client.get(key=boat_key)
            if str(boat_to_edit["ownerID"]) != str(sub_jwt_val):
                # 403 - JWT is valid but boat_id is owned by someone else.
                abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
                return
            
            if "name" in content.keys():
                boat_to_edit["name"] = content["name"]
            if "type" in content.keys():
                boat_to_edit["type"] = content["type"]
            if "length" in content.keys():
                boat_to_edit["length"] = content["length"]
            client.put(boat_to_edit)

        if len(boat_to_edit["loads"]) != 0:
            for b in boat_to_edit["loads"]:
                b["self"] = str(request.url_root) + "loads/" + str(b["id"])
        boat_to_edit["id"] = boat_id
        boat_to_edit["self"] = request.base_url
        return jsonify(boat_to_edit), 200
    elif request.method == "PUT":
        # for final

        # Update all attributes, except ID. With a valid JWT
        
        # 406 status code - Request with Accept header set to unsupported MIME type.
        if not 'application/json' in request.accept_mimetypes:
            abort(406)
            return
        
        payload = verify_jwt(request)
        content = request.get_json()
        with client.transaction():
            boat_key = client.key(BOATS, int(boat_id))
            boat_to_edit = client.get(key=boat_key)
            sub_jwt_val = payload["sub"]
            if str(boat_to_edit["ownerID"]) != str(sub_jwt_val):
                # 403 - JWT is valid but boat_id is owned by someone else.
                abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
                return
            boat_to_edit["name"] = content["name"]
            boat_to_edit["type"] = content["type"]
            boat_to_edit["length"] = content["length"]
            client.put(boat_to_edit)

        if len(boat_to_edit["loads"]) != 0:
            for b in boat_to_edit["loads"]:
                b["self"] = str(request.url_root) + "loads/" + str(b["id"])
        boat_to_edit["id"] = boat_id
        boat_to_edit["self"] = request.base_url
        return jsonify(boat_to_edit), 200
    else:
        return jsonify(error="Method not recognized")


@app.route("/loads", methods=["POST", "GET", "DELETE", "PUT"])
def loads_post_get():
    if request.method == "POST":
        # for final

        # Create a new load with a valid JWT.
        # If JWT is missing or invalid, returns 401 status code.
        
        # 406 status code - Request with Accept header set to unsupported MIME type.
        if not 'application/json' in request.accept_mimetypes:
            abort(406)
            return
        
        payload = verify_jwt(request)
        content = request.get_json()
        new_load = datastore.entity.Entity(key=client.key(LOADS))
        owner_id = payload["sub"]
        new_load.update({"volume": content["volume"], "item": content["item"], 
                         "creation_date": content["creation_date"],
                         "ownerID": owner_id, "carrier": None})
        client.put(new_load)
        new_load["self"] = str(request.base_url) + "/" + str(new_load.key.id)
        new_load["id"] = str(new_load.key.id)
        return jsonify(new_load), 201

    elif request.method == "GET":
        # for final

        # If an entity is related to a user, then this must
        # show only those entities in the collection which are
        # related to the user corresponding to the valid JWT provided
        # in the request.
        #
        # For an entity that is NOT related to users, this should
        # show all the entities in the collection
        #
        # - pagination: should return 5 loads per page / next link (except last page)
        # - a property that how many total items are in the collection
        # - self links
        loads_query = client.query(kind=LOADS)
        all_loads_query = client.query(kind=LOADS)
        
        try:
            payload = verify_jwt(request)
            sub_jwt_val = payload["sub"]
            loads_query.add_filter("ownerID", "=", sub_jwt_val)
            list_loads_query = list(loads_query.fetch())
            total_items_num = len(list_loads_query)
            
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = loads_query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            for e in results:
                e["total_items"] = total_items_num
                e["id"] = e.key.id
                e["self"] = str(request.base_url) + "/" + str(e.key.id)
                if e["carrier"]:
                    e["carrier"]["self"] = str(request.url_root) + "boats/" + str(e["carrier"]["id"])
            
            output = {"loads": results}

            if next_url:
                output["next"] = next_url
            return json.dumps(output), 200
        except:
            list_all_loads_query = list(all_loads_query.fetch())
            total_items_num = len(list_all_loads_query)
            
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = all_loads_query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            
            for e in results:
                e["total_items"] = total_items_num
                e["id"] = e.key.id
                e["self"] = str(request.base_url) + "/" + str(e.key.id)
                if e["carrier"]:
                    e["carrier"]["self"] = str(request.url_root) + "boats/" + str(e["carrier"]["id"])
            
            output = {"loads": results}

            if next_url:
                output["next"] = next_url

            return json.dumps(output), 200
    elif request.method == "DELETE":
        # for final

        # 405 status code - DELETE request on root boat URL is not allowed.
        # Because you are not supporting deleting of the entire list of boats.
        abort(405)
        return
    elif request.method == "PUT":
        # for final

        # 405 status code - PUT request on root boat URL is not allowed.
        # Because you are not supporting editing of the entier list of boats.
        abort(405)
        return
    else:
        return jsonify(error="Method not recognized")
    

@app.route("/loads/<load_id>", methods=["GET", "DELETE", "PATCH", "PUT"])
def get_delete_edit_load(load_id):
    if request.method == "GET":
        # for final

        # Get an existing load with a valid JWT
        payload = verify_jwt(request)

        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)
        sub_jwt_val = payload["sub"]

        if str(load["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but load_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return

        if load["carrier"]:
            load["carrier"]["self"] = str(request.url_root) + "boats/" + str(load["carrier"]["id"])
        load["id"] = load_id
        load["self"] = request.base_url
        return json.dumps(load), 200
    elif request.method == "DELETE":
        # for final

        # Only the owner of a load with a valid JWT
        # should be able to delete the load.
        payload = verify_jwt(request)

        load_key = client.key(LOADS, int(load_id))
        load_to_delete = client.get(key=load_key)

        sub_jwt_val = payload["sub"]
        if str(load_to_delete["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return
        
        # Remove the load from the carrier(boat)'s "loads".
        if load_to_delete["carrier"]:
            boat_id_to_update = load_to_delete["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id_to_update))
            boat_to_update = client.get(key=boat_key)
            idx_to_remove = None
            for i in range(len(boat_to_update["loads"])):
                if str(boat_to_update["loads"][i]["id"]) == str(load_id):
                    idx_to_remove = i
            boat_to_update["loads"].pop(idx_to_remove)
            client.put(boat_to_update)
        
        client.delete(load_to_delete)
        return '', 204
    elif request.method == "PATCH":
        # for final

        # Update any subsets of attributes of a load while
        # the other attributes remain unchanged. With a valid JWT.
        
        # 406 status code - Request with Accept header set to unsupported MIME type.
        if not 'application/json' in request.accept_mimetypes:
            abort(406)
            return

        payload = verify_jwt(request)
        content = request.get_json()
        with client.transaction():
            load_key = client.key(LOADS, int(load_id))
            load_to_edit = client.get(key=load_key)

            sub_jwt_val = payload["sub"]
            if str(load_to_edit["ownerID"]) != str(sub_jwt_val):
                # 403 - JWT is valid but boat_id is owned by someone else.
                abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
                return
            
            if "volume" in content.keys():
                load_to_edit["volume"] = content["volume"]
            if "item" in content.keys():
                load_to_edit["item"] = content["item"]
            if "creation_date" in content.keys():
                load_to_edit["creation_date"] = content["creation_date"]
            client.put(load_to_edit)

        load_to_edit["id"] = load_id
        load_to_edit["self"] = request.base_url
        if load_to_edit["carrier"]:
            load_to_edit["carrier"]["self"] = str(request.url_root) + "boats/" + str(load_to_edit["carrier"]["id"])    
        return jsonify(load_to_edit), 200
    elif request.method == "PUT":
        # for final

        # Update all attributes, except ID. With a valid JWT
        
        # 406 status code - Request with Accept header set to unsupported MIME type.
        if not 'application/json' in request.accept_mimetypes:
            abort(406)
            return
        
        payload = verify_jwt(request)
        content = request.get_json()
        with client.transaction():
            load_key = client.key(LOADS, int(load_id))
            load_to_edit = client.get(key=load_key)
            sub_jwt_val = payload["sub"]
            if str(load_to_edit["ownerID"]) != str(sub_jwt_val):
                # 403 - JWT is valid but boat_id is owned by someone else.
                abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
                return
            load_to_edit["volume"] = content["volume"]
            load_to_edit["item"] = content["item"]
            load_to_edit["creation_date"] = content["creation_date"]
            client.put(load_to_edit)

        load_to_edit["id"] = load_id
        load_to_edit["self"] = request.base_url
        if load_to_edit["carrier"]:
            load_to_edit["carrier"]["self"] = str(request.url_root) + "boats/" + str(load_to_edit["carrier"]["id"])
        return jsonify(load_to_edit), 200
    else:
        return jsonify(error="Method not recognized")

@app.route("/boats/<boat_id>/loads/<load_id>", methods=["PUT", "DELETE"])
def managing_loads(boat_id, load_id):
    if request.method == "PUT":
        # for final

        # Assign a load to a boat with a valid JWT.
        payload = verify_jwt(request)
        sub_jwt_val = payload["sub"]

        boat_key = client.key(BOATS, int(boat_id))
        load_key = client.key(LOADS, int(load_id))
        boat = client.get(key=boat_key)
        load = client.get(key=load_key)

        if str(boat["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return

        if str(load["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return
        
        if load["carrier"] is None:
            boat["loads"].append({"id": str(load_id)})
            load["carrier"] = {"id": str(boat_id), "name": boat["name"]}
            client.put(boat)
            client.put(load)
            return '', 204
        else:
            abort(403, description="The load is already loaded on another boat")
            return
    elif request.method == "DELETE":
        # for final

        # Remove a load from a boat with a valid JWT
        payload = verify_jwt(request)
        sub_jwt_val = payload["sub"]

        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)

        if str(load["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return

        load["carrier"] = None
        client.put(load)

        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)

        if str(boat["ownerID"]) != str(sub_jwt_val):
            # 403 - JWT is valid but boat_id is owned by someone else.
            abort(403, description="JWT is valid but boat_id/load_id is owned by someone else")
            return

        remove_idx = None
        if 'loads' in boat.keys():
            for i in range(len(boat["loads"])):
                if boat["loads"][i]["id"] == load_id:
                    remove_idx = i

        boat["loads"].pop(remove_idx)
        client.put(boat)
        return '', 204
    else:
        return jsonify(error="Method not recognized")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))