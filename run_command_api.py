import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/run/<command>', methods=['GET'])
def run_command(command):
    try:
        # For security, only allow specific commands or sanitize input in production
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return '''
            <script>
                window.close();
            </script>
        '''

        # return jsonify({
        #     'command': command,
        #     'stdout': result.stdout,
        #     'stderr': result.stderr,
        #     'returncode': result.returncode
        # })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(port=5000, debug=True)
