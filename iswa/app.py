from flask import Flask, abort, jsonify, make_response, request, render_template
from utils import get_connection
import hashlib
import hmac
import base64

app = Flask(__name__)

def getMD5(string_input):
    str_bytes = string_input.encode('utf-8')
    hasher = hashlib.md5()
    hasher.update(str_bytes)
    return hasher.hexdigest()

def HMACSHA256Encode(input, key):
    key_bytes = key.encode('utf-8')
    input_bytes = input.encode('utf-8')
    signature = hmac.new(
        key=key_bytes,
        msg=input_bytes,
        digestmod=hashlib.sha256
    )
    return signature.hexdigest()

def generateToken(userid):
    token = userid + ':' + HMACSHA256Encode(userid, "t0k3n_s3cr3t")
    token_bytes = token.encode('utf-8')
    token_b64_bytes = base64.b64encode(token_bytes)
    return token_b64_bytes.decode('utf-8')

def getLoggedInUser(request):
    memberID = ""
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
        if token != "":
            token_bytes = token.encode('utf-8')
            token_bytes_pt = base64.b64decode(token_bytes)
            token_str = token_bytes_pt.decode('utf-8')
            memberID = token_str.split(':')[0]

    return memberID
            
@app.errorhandler(400)
def invalid_request(error):
    return make_response(jsonify({'error': 'Bad Request'}), 400)

@app.route("/", methods=['GET'])
def index():
    return render_template('app.html')

@app.route("/login", methods=['POST'])
def login():
    result = ""
    if (request.form and 
        'user' in request.form and
        'password' in request.form
    ):
        username = request.form['user']
        password = getMD5(request.form['password'])
        
        connection = get_connection()
        cursor = connection.cursor()
        sql = 'SELECT userid FROM users WHERE ' + \
                'userid = %s AND ' + \
                'password = %s'
        cursor.execute(sql, (username,password,))
        userid = cursor.fetchone()
        connection.close()
        if userid:
            token = generateToken(userid["userid"])
            response_string = '"{}"'.format(token)
            return make_response(response_string, 200)

@app.route("/home", methods=['GET'])
def home():
    loggedInUser = getLoggedInUser(request)
    if loggedInUser == "":
        return make_response(jsonify({}, 401))
        
    sql = "SELECT * FROM messages WHERE userid = %s " + \
            "ORDER BY sent DESC"

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(sql, (loggedInUser,))
    messages = cursor.fetchall()
    connection.close()
    return make_response(jsonify(messages), 200)

@app.route("/search", methods=['GET'])
def search():
    loggedInUser = getLoggedInUser(request)
    if loggedInUser == "":
        return make_response(jsonify({}, 401))
    
    keyword = ""
    if 'keyword' in request.args:
        keyword = request.args['keyword']
    
    sql = "SELECT * FROM messages WHERE userid = %s AND " + \
            "content LIKE '%%" + keyword + "%%' " \
            "ORDER BY sent DESC"

    print(sql)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(sql, (loggedInUser,))
    messages = cursor.fetchall()
    connection.close()
    return make_response(jsonify(messages), 200)

@app.route("/details", methods=['GET'])
def details():
    loggedInUser = getLoggedInUser(request)
    if loggedInUser == "":
        return make_response(jsonify({}, 401))

    messageid = ""
    if 'messageid' in request.args:
        messageid = request.args['messageid']

    sql = "SELECT * FROM messages WHERE messageid = %s"

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(sql, (messageid,))
    message = cursor.fetchone()
    connection.close()
    return make_response(jsonify(message), 200)

@app.route("/profile", methods=['GET'])
def profile():
    loggedInUser = getLoggedInUser(request)
    if loggedInUser == "":
        return make_response(jsonify({}, 401))

    sql = "SELECT * FROM users WHERE userid = %s"

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(sql, (loggedInUser,))
    user = cursor.fetchone()
    connection.close()
    return make_response(jsonify(user), 200)
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)