import pymysql.cursors  

def get_connection():
    # You can change the connection arguments.
    connection = pymysql.connect(
        host='mysql',
        user='root',
        password='rootpassword',                             
        db='iswa',
        cursorclass=pymysql.cursors.DictCursor
    )

    return connection
