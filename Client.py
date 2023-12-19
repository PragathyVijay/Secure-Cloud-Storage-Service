def get_server_url():
    host = 'your ip address' 
    port = '5000'  

    server_url = f'http://{host}:{port}/'
    return server_url

if __name__ == '__main__':
    server_url = get_server_url()
    print(f"Access the server at: {server_url}")
