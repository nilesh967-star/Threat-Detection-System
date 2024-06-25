import mysql.connector
from flask import Flask, render_template, jsonify

app = Flask(__name__)


def retrieve_logs_from_database():
    try:
        connection = mysql.connector.connect(
            host="192.168.1.36",
            user="windows",
            password="windows",
            database="TDS_database"
        )
        cursor = connection.cursor()

        cursor.execute("SELECT ip_address, user_agent, attack_type, location, time_stamp FROM user_logs ORDER BY visitor_id DESC")

        logs = cursor.fetchall()

        return logs

    except mysql.connector.Error as error:
        print("Error: {}".format(error))
        return []

    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.route('/get_data')
def get_data():
    logs = retrieve_logs_from_database()
    data = []

    for log in logs:
        ip_address = log[0]
        user_agent = log[1]
        attack_type = log[2]
        location = log[3]
        time_stamp = log[4]

        new_attack = {
            'ip_address': ip_address,
            'location': location,
            'attack_type': attack_type,
            'timestamp': time_stamp,
            'user_agent': user_agent
        }
        data.append(new_attack)

    return jsonify(data)


@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/httpTrafic')
def HTTP():
    return render_template('httpTrafic.html')

@app.route('/map')
def Map():
    return render_template('map.html')

@app.route('/profile')
def Profile():
    return render_template('profile.html')

# login signup

@app.route('/login')
def Login():
    return render_template('signin.html')

@app.route('/register')
def Register():
    return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True,port=5000)
