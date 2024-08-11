from waitress import serve
import api

if __name__ == '__main__':
    serve(api.app, host='0.0.0.0', port=3200)
