import re
import asyncio
from aiohttp import ClientSession, ClientError, web
import ipinfo
import time
import urllib.parse
import mysql.connector
from datetime import datetime

# Define rate limiting 
MAX_REQUESTS = 100
REQUESTS_WINDOW = 60  #60 second = 1 minutes
BLOCK_DURATION = 60  #60 second = 1 minutes

# Track requests per IP address and their timestamps
request_counts = {}
request_timestamps = {}
blocked_users = {}

# Define patterns for SQL Injection detection
SQL_INJECTION_PATTERNS = [
  r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|GRANT)\b',  # Detect common SQL keywords
    r'\b(?:OR|AND)\b.+\b(?:=|>|<)\b',           # Detect OR/AND based injections
    r'\bUNION\b.+\b(?:SELECT)\b',               # Detect UNION-based injections
    r'\b(?:DECLARE\s+@|DECLARE\s+%)\b',         # Detect DECLARE statements
    r'\b(?:CAST|CONVERT)\b',                   # Detect data type conversion
    r'\b(?:xp_cmdshell|sp_executesql)\b',      # Detect potentially harmful stored procedures
    r'\b(?:WAITFOR\s+DELAY)\b',                # Detect potential time-based attacks
    r'\b(?:BULK\s+INSERT)\b',                  # Detect bulk insert operations
    r'\b(?:OPENROWSET|OPENDATASOURCE)\b',      # Detect data access operations
    r'\b(?:SET\s+|EXEC\s+\()',                 # Detect SET and EXEC statements
    r'\b(?:--|#|\/\*)\s*[\w\s]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',  # Detect comment-based injections
    r'\b(?:INSERT\s+INTO|VALUES)\b',           # Detect INSERT INTO and VALUES keywords
    r'\b(?:UPDATE\s+\w+\s+SET)\b',             # Detect UPDATE SET statements
    r'\b(?:DELETE\s+FROM)\b',                 # Detect DELETE FROM statements
    r'\b(?:FROM\s+\w+\s+WHERE)\b',            # Detect FROM and WHERE clauses
    r'\b(?:ALTER\s+TABLE|ADD\s+CONSTRAINT)\b',# Detect ALTER TABLE and ADD CONSTRAINT statements
    r'\b(?:CASE\s+WHEN)\b',                   # Detect CASE WHEN statements
    r'\b(?:LEFT\s+JOIN|RIGHT\s+JOIN)\b',      # Detect LEFT JOIN and RIGHT JOIN
    r'\b(?:OUTER\s+APPLY|CROSS\s+APPLY)\b'    # Detect OUTER APPLY and CROSS APPLY

]

#  Patterns Remote-Code Execution detection

REMOTE_CODE_EXECUTION_PATTERNS = [
    # PHP reverse shell patterns
    r'fsockopen\s*\(\s*["\']\d+\.\d+\.\d+\.\d+["\']\s*,\s*\d+\s*\)',  # Detect fsockopen function call with IP and port
    r'shell_exec\s*\(\s*["\']sh\s+<&3\s+>&3\s+2>&3["\']\s*\)',  # Detect shell_exec with specific shell command
    r'exec\s*\(\s*["\']nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+-e\s+/bin/sh["\']\s*\)',  # Detect exec with netcat reverse shell command
    r'passthru\s*\(\s*["\']nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+-e\s+/bin/sh["\']\s*\)',  # Detect passthru with netcat reverse shell command
    r'system\s*\(\s*["\']nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+-e\s+/bin/sh["\']\s*\)',  # Detect system with netcat reverse shell command

    # Python reverse shell patterns
    r'import\s+socket\s*\n\s*sock\s*=\s*socket\.socket\(socket\.AF_INET,\s*socket\.SOCK_STREAM\)\n\s*sock\.connect\(["\']\d+\.\d+\.\d+\.\d+["\']\s*,\s*\d+\)',  # Detect Python socket connection
    r'os\.system\(["\']nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+-e\s+/bin/sh["\']\)',  # Detect os.system with netcat reverse shell command
    r'subprocess\.Popen\(\["\']nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+-e\s+/bin/sh["\']\)',  # Detect subprocess.Popen with netcat reverse shell command

    # JavaScript reverse shell patterns
    r'new\s+WebSocket\s*\(\s*["\']ws://\d+\.\d+\.\d+\.\d+:\d+["\']\s*\)',  # Detect WebSocket connection to IP and port

    # Shell command execution patterns in HTTP requests
    r'curl\s+\S+\s+\|\s+sh',  # Detect curl command with piping to shell
    r'wget\s+\S+\s+-O\s+-\s+\|\s+sh',  # Detect wget command with piping to shell
    r'fetch\s+\S+\s+\|\s+sh',  # Detect fetch command with piping to shell

    # Additional patterns for reverse shell detection
    r'import\s+pickle\s*\n\s*pickle\.loads\(',  # Detect pickle deserialization for reverse shell
    r'subprocess\s*\.\s*run\s*\(\s*\[.*?\bnc\b.*?\]',  # Detect subprocess run with netcat command
    r'socket\s*\.\s*connect\s*\(\s*\(',  # Detect socket connection attempt

    # Common reverse shell one-liners
    r'\bnc\s+\S+\s+\d+\s*>\s*/dev/tcp/\S+\s+\d+',  # Detect netcat reverse shell one-liner
    r'\bpython\s+-c\s+[\'"]import\s+socket,\s+subprocess;\s+s=socket.socket(socket.AF_INET,\s+socket.SOCK_STREAM);\s+s.connect\([\'"].+?\bnc\b.+?\)[\'"];\s+subprocess.call\([\'"](.*?)\.recv\(1024\)[\'"],\s+shell=True\)',  # Detect Python reverse shell one-liner
    r'\bperl\s+-MIO::Socket::INET\b',  # Detect Perl reverse shell imports
    r'\bruby\s+-rsocket\b',  # Detect Ruby reverse shell imports
    r'\b(?:telnet|ssh|nc|netcat)\s+[^&|;]*?\b(?:-e|--e|-c|--c|--command|-O|--option)\b',  # Detect potentially malicious command execution using netcat, telnet, or SSH
    r'\b(?:telnet|ssh|nc|netcat)\s+[^&|;]*?(?:\|&|\|>|;)',  # Detect potentially malicious piping or redirection with netcat, telnet, or SSH
    r'\b(?:telnet|ssh|nc|netcat)\s+[^&|;]*?\b(?:<|>|>>)\s+',  # Detect potentially malicious file I/O redirection with netcat, telnet, or SSH
    r'\b(?:telnet|ssh|nc|netcat)\s+[^&|;]*?\b(?:\.\.|\/|\.\.|\.\/)[^&|;]*',  # Detect potentially malicious directory traversal with netcat, telnet, or SSH
]

# Define patterns for File Inclusion detection
FILE_INCLUSION_PATTERNS = [
    r'include\s*\(\s*[\'"](?:\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/var\/www\/config\.php)[\'"]\s*\)',  # Detect inclusion of sensitive files
    r'require\s*\(\s*[\'"](?:\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/var\/www\/config\.php)[\'"]\s*\)',  # Detect requirement of sensitive files
    r'include_once\s*\(\s*[\'"](?:\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/var\/www\/config\.php)[\'"]\s*\)',  # Detect inclusion of sensitive files only once
    r'require_once\s*\(\s*[\'"](?:\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/var\/www\/config\.php)[\'"]\s*\)'  # Detect requirement of sensitive files only once
]

XSS_PATTERNS = [
    r'<\s*script\s*[^>]*>(.*?)<\s*/\s*script\s*>',                # Detect <script> tags
    r'<\s*img\s*src\s*=\s*["\'][^"\']*["\'][^>]*>',               # Detect <img> tags with src attribute
    r'<\s*a\s*href\s*=\s*["\'][^"\']*["\'][^>]*>',                # Detect <a> tags with href attribute
    r'<\s*iframe\s*src\s*=\s*["\'][^"\']*["\'][^>]*>',             # Detect <iframe> tags with src attribute
    r'<\s*svg\s*onload\s*=\s*["\'][^"\']*["\'][^>]*>',             # Detect <svg> tags with onload attribute
    r'<\s*body\s*onload\s*=\s*["\'][^"\']*["\'][^>]*>',            # Detect <body> tags with onload attribute
    r'<\s*input\s*type\s*=\s*["\']hidden["\']\s*value\s*=\s*["\'][^"\']*["\'][^>]*>',  # Detect <input> tags with type=hidden and value attributes
    r'<\s*marquee\s*>.*?<\s*/\s*marquee\s*>',                      # Detect <marquee> tags
    r'<\s*input\s*type\s*=\s*["\']text["\']\s*on[^>]*>',           # Detect <input> tags with type=text and on* attributes
    r'<\s*form\s*[^>]*onsubmit\s*=\s*["\'][^"\']*["\'][^>]*>',    # Detect <form> tags with onsubmit attribute
    r'<\s*div\s*[^>]*onmouseover\s*=\s*["\'][^"\']*["\'][^>]*>',  # Detect <div> tags with onmouseover attribute
    r'<\s*audio\s*[^>]*onplay\s*=\s*["\'][^"\']*["\'][^>]*>',     # Detect <audio> tags with onplay attribute
    r'<\s*video\s*[^>]*onplay\s*=\s*["\'][^"\']*["\'][^>]*>',     # Detect <video> tags with onplay attribute
    r'<\s*input\s*[^>]*onclick\s*=\s*["\'][^"\']*["\'][^>]*>',    # Detect <input> tags with onclick attribute
    r'<\s*body\s*[^>]*onmouseover\s*=\s*["\'][^"\']*["\'][^>]*>', # Detect <body> tags with onmouseover attribute
    r'<\s*button\s*[^>]*onclick\s*=\s*["\'][^"\']*["\'][^>]*>',   # Detect <button> tags with onclick attribute
    r'<\s*img\s*[^>]*onload\s*=\s*["\'][^"\']*["\'][^>]*>',       # Detect <img> tags with onload attribute
    r'<\s*object\s*[^>]*onload\s*=\s*["\'][^"\']*["\'][^>]*>',    # Detect <object> tags with onload attribute
    r'<\s*div\s*[^>]*onmouseover\s*=\s*["\'][^"\']*["\'][^>]*>',  # Detect <div> tags with onmouseover attribute
    r'<\s*td\s*[^>]*onmouseover\s*=\s*["\'][^"\']*["\'][^>]*>',   # Detect <td> tags with onmouseover attribute
    r'<\s*th\s*[^>]*onmouseover\s*=\s*["\'][^"\']*["\'][^>]*>',   # Detect <th> tags with onmouseover attribute
    r'<script.*?>.*?</script>'   
]


async def dos_protection(request):
    global request_counts
    global request_timestamps
    global blocked_users

    client_ip = request.remote

    # Check if the IP address is blocked
    if client_ip in blocked_users:
        # Check if the blocking duration has expired
        if time.time() - blocked_users[client_ip] >= BLOCK_DURATION:
            # Unblock the user
            del blocked_users[client_ip]
            print(f"Unblocked user {client_ip}")
        else:
            print(f"Blocked user {client_ip}")
            return True  # User is still blocked

    # Check if the IP address is tracked
    if client_ip not in request_counts:
        request_counts[client_ip] = 0
        request_timestamps[client_ip] = time.time()

    # Check if the time window has elapsed since the last request
    if time.time() - request_timestamps[client_ip] > REQUESTS_WINDOW:
        # Reset the request count and update the timestamp
        request_counts[client_ip] = 0
        request_timestamps[client_ip] = time.time()

    # Increment the request count
    request_counts[client_ip] += 1

    # Check if the request count exceeds the limit
    if request_counts[client_ip] > MAX_REQUESTS:
        print("Too many requests from", client_ip)
        client_ip = request.headers.get('X-Forwarded-For') or request.remote
        print("Request received from:", client_ip)
        print("performing SQL injection :- ")
        if client_ip == '127.0.0.1':
            pass
        else:
            geolocation = await get_geolocation(client_ip)

    
            IP_ADDRESS = geolocation['ip']
            CITY = geolocation['city']
            REGION = geolocation['region']
            COUNTRY = geolocation['country']  
            LATITUDE = geolocation['latitude']
            LONGITUDE = geolocation['longitude']
        
            print(f"IP_ADDRESS: {IP_ADDRESS}, CITY: {CITY}, REGION: {REGION}, COUNTRY: {COUNTRY}, LATITUDE: {LATITUDE}, LONGITUDE: {LONGITUDE}")
            location = CITY + COUNTRY
            user_agent = request.headers.get('User-Agent')
            
            if user_agent:
                print("User-Agent:", user_agent)
            else:
                print("User-Agent not found")
            
            time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            insert_logs_in_database(client_ip,user_agent,'DOS-Attack',location,time_stamp)
    
        # Block the user and record the time
        blocked_users[client_ip] = time.time()
        return True  # Too many requests, block the user
    else:
        return False  # Request allowed


async def get_geolocation(ip_address):
    access_token = '286ec0ac599b49'  # Replace 'YOUR_ACCESS_TOKEN' with your actual access token
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip_address)
    return details.all

def insert_logs_in_database(ip_address, user_agent, attack_type, location, time_stamp):
    try:       
        connection = mysql.connector.connect(
            host="192.168.1.36",
            user="windows",
            password="windows",
            database="TDS_database"
            )
        cursor = connection.cursor()
    
        sql_query= "INSERT INTO user_logs(ip_address,user_agent, attack_type, location, time_stamp) VALUES (%s,%s,%s,%s,%s)"
    
        cursor.execute(sql_query, (ip_address, user_agent, attack_type, location, time_stamp))
    
    
        # Commit the transaction
        connection.commit()
        print("Entry has been added  into database")
    except mysql.connector.Error as error:
        print("Error: {}".format(error))
    
    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
    
async def handle_request(request):
    target_url = 'http://127.0.0.1/dvwa'
    
    # Extract request data

    # request_data = request.rel_url.raw_path_qs
    request_data = urllib.parse.unquote(request.rel_url.raw_path_qs)
    if request.method == "POST":
        post_data = await request.read()
        request_data += post_data.decode('utf-8')

    # dos_protection    
    is_blocked = await dos_protection(request)
    if is_blocked:
        return web.Response(status=429, text='Too Many Requests')

    # Perform unblocking for previously blocked IPs if needed
    for ip in blocked_users.copy():
        if time.time() - blocked_users[ip] >= BLOCK_DURATION:
            del blocked_users[ip]
            print(f"Unblocked user {ip}")
            
    # Check for SQL Injection
    if any(re.search(pattern, request_data, re.IGNORECASE) for pattern in SQL_INJECTION_PATTERNS):
        client_ip = request.headers.get('X-Forwarded-For') or request.remote
        print("Request received from:", client_ip)
        print("performing SQL injection :- ")
        if client_ip == '127.0.0.1':
            pass
        else:
            geolocation = await get_geolocation(client_ip)

    
            IP_ADDRESS = geolocation['ip']
            CITY = geolocation['city']
            REGION = geolocation['region']
            COUNTRY = geolocation['country']
            LATITUDE = geolocation['latitude']
            LONGITUDE = geolocation['longitude']
        
            print(f"IP_ADDRESS: {IP_ADDRESS}, CITY: {CITY}, REGION: {REGION}, COUNTRY: {COUNTRY}, LATITUDE: {LATITUDE}, LONGITUDE: {LONGITUDE}")
            location = CITY + COUNTRY
            user_agent = request.headers.get('User-Agent')
            
            if user_agent:
                print("User-Agent:", user_agent)
            else:
                print("User-Agent not found")
            
            time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            insert_logs_in_database(client_ip,user_agent,'SQL-Injection',location,time_stamp)
        return web.Response(status=403, text='Potential SQL Injection detected')
    
    # Check for Cross-Site Scripting (XSS)
    if any(re.search(pattern, request_data, re.IGNORECASE) for pattern in XSS_PATTERNS):
        client_ip = request.headers.get('X-Forwarded-For') or request.remote
        print("Request received from:", client_ip)
        print("performing Cross-Site Scripting (XSS) :- ")
        if client_ip == '127.0.0.1':
            pass
        else:
            geolocation = await get_geolocation(client_ip)

    
            IP_ADDRESS = geolocation['ip']
            CITY = geolocation['city']
            REGION = geolocation['region']
            COUNTRY = geolocation['country']
            LATITUDE = geolocation['latitude']
            LONGITUDE = geolocation['longitude']
        
            print(f"IP_ADDRESS: {IP_ADDRESS}, CITY: {CITY}, REGION: {REGION}, COUNTRY: {COUNTRY}, LATITUDE: {LATITUDE}, LONGITUDE: {LONGITUDE}")
            location = CITY + COUNTRY
            user_agent = request.headers.get('User-Agent')
            
            if user_agent:
                print("User-Agent:", user_agent)
            else:
                print("User-Agent not found")
            
            time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            insert_logs_in_database(client_ip,user_agent,'Cross-Site Scripting (XSS)',location,time_stamp)
        return web.Response(status=403, text='Potential XSS Attack detected')


    # Check for Remote-Code Execution 
    if any(re.search(pattern, request_data, re.IGNORECASE) for pattern in REMOTE_CODE_EXECUTION_PATTERNS):
        client_ip = request.headers.get('X-Forwarded-For') or request.remote
        print("Request received from:", client_ip)
        print("performing Remote-Code Execution ")
        if client_ip == '127.0.0.1':
            pass
        else:
            geolocation = await get_geolocation(client_ip)

    
            IP_ADDRESS = geolocation['ip']
            CITY = geolocation['city']
            REGION = geolocation['region']
            COUNTRY = geolocation['country']
            LATITUDE = geolocation['latitude']
            LONGITUDE = geolocation['longitude']
        
            print(f"IP_ADDRESS: {IP_ADDRESS}, CITY: {CITY}, REGION: {REGION}, COUNTRY: {COUNTRY}, LATITUDE: {LATITUDE}, LONGITUDE: {LONGITUDE}")
            location = CITY + COUNTRY
            user_agent = request.headers.get('User-Agent')
            
            if user_agent:
                print("User-Agent:", user_agent)
            else:
                print("User-Agent not found")
            
            time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            insert_logs_in_database(client_ip,user_agent,'Remote-Code Execution (RCE)',location,time_stamp)
        return web.Response(status=403, text='Remote-Code Execution (RCE) detected')
        

    # Check for File Inclusion
    if any(re.search(pattern, request_data, re.IGNORECASE) for pattern in FILE_INCLUSION_PATTERNS):
        
        client_ip = request.headers.get('X-Forwarded-For') or request.remote
        print("Request received from:", client_ip)
        print("Malicious File Uploaded :-")
        if client_ip == '127.0.0.1':
            pass
        else:
            geolocation = await get_geolocation(client_ip)

    
            IP_ADDRESS = geolocation['ip']
            CITY = geolocation['city']
            REGION = geolocation['region']
            COUNTRY = geolocation['country']
            LATITUDE = geolocation['latitude']
            LONGITUDE = geolocation['longitude']
        
            print(f"IP_ADDRESS: {IP_ADDRESS}, CITY: {CITY}, REGION: {REGION}, COUNTRY: {COUNTRY}, LATITUDE: {LATITUDE}, LONGITUDE: {LONGITUDE}")
            location = CITY + COUNTRY
            user_agent = request.headers.get('User-Agent')
            
            if user_agent:
                print("User-Agent:", user_agent)
            else:
                print("User-Agent not found")
            
            time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            insert_logs_in_database(client_ip,user_agent,'File inclusion detected',location,time_stamp)
        return web.Response(status=403, text='Malicious File detected')                    

    # Forward request if no-malicious patterns found! on website 
    async with ClientSession() as session:
        try:
            async with session.request(request.method, f'{target_url}{request.rel_url}', headers=request.headers, data=await request.read()) as response:
                body = await response.read()
                return web.Response(status=response.status, body=body, headers=response.headers)
        except ClientError as e:
            return web.Response(status=500, text=f'Error: {e}')

if __name__ == '__main__':
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handle_request)
    web.run_app(app, port=8000)
